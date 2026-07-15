from __future__ import annotations

import json
import sqlite3
import threading
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from guardd.models.decisions import Decision
from guardd.models.events import GuardEvent, ToolResultEvent
from guardd.security import digest_payload, sanitize, summarize_mapping, summarize_value


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, event_type TEXT NOT NULL,
  gateway_id TEXT, agent_id TEXT NOT NULL, session_key TEXT NOT NULL, run_id TEXT,
  tool_call_id TEXT, tool_name TEXT, sanitized_json TEXT NOT NULL, event_hash TEXT NOT NULL,
  previous_hash TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_key, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_routing ON events(agent_id, tool_name, occurred_at);
CREATE TABLE IF NOT EXISTS decisions (
  decision_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, decision TEXT NOT NULL,
  would_decide TEXT, risk TEXT NOT NULL, reason TEXT NOT NULL, parameter_digest TEXT NOT NULL,
  mode TEXT NOT NULL, policy_digest TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_event ON decisions(event_id);
CREATE TABLE IF NOT EXISTS rule_matches (
  decision_id TEXT NOT NULL, rule_id TEXT NOT NULL, PRIMARY KEY(decision_id, rule_id)
);
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, event_id TEXT NOT NULL,
  agent_id TEXT NOT NULL, session_key TEXT NOT NULL, sender_id TEXT,
  parameter_digest TEXT NOT NULL, status TEXT NOT NULL, expires_at TEXT NOT NULL,
  resolved_at TEXT, operator TEXT, resolution_ms REAL, display_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, expires_at);
CREATE TABLE IF NOT EXISTS tool_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL, tool_call_id TEXT,
  success INTEGER NOT NULL, exit_code INTEGER, duration_ms REAL,
  sanitized_output TEXT, error TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  session_key TEXT PRIMARY KEY, agent_id TEXT NOT NULL, status TEXT NOT NULL,
  started_at TEXT NOT NULL, ended_at TEXT, metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
  digest TEXT PRIMARY KEY, version TEXT NOT NULL, source TEXT NOT NULL,
  operator TEXT NOT NULL, document_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT NOT NULL, category TEXT NOT NULL,
  message TEXT NOT NULL, detail_json TEXT, created_at TEXT NOT NULL
);
"""


class AuditStore:
    def __init__(self, path: Path, emergency_path: Path, secret_patterns: list[tuple[str, re.Pattern[str]]] | None = None):
        self.path = path
        self.emergency_path = emergency_path
        self.secret_patterns = secret_patterns or []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, timeout=5, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def record_policy(self, digest: str, version: Any, source: str, document: dict[str, Any], operator: str = "startup") -> None:
        clean, _ = sanitize(document, extra_patterns=self.secret_patterns)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO policy_versions VALUES (?, ?, ?, ?, ?, ?)",
                (digest, str(version), source, operator, json.dumps(clean, ensure_ascii=False), self._now()),
            )

    def record_event(self, event: GuardEvent) -> None:
        clean, _ = sanitize(event.model_dump(mode="json"), extra_patterns=self.secret_patterns)
        clean["params"] = summarize_mapping(event.params)
        for command in clean.get("derived", {}).get("commands", []):
            if not isinstance(command, dict):
                continue
            if command.get("dynamic_eval") and isinstance(command.get("raw"), str):
                command["raw"] = {"redacted_dynamic_command": summarize_value(command["raw"])}
                command["argv"] = [item if isinstance(item, str) and item.startswith("-") and len(item) <= 32 else summarize_value(item) for item in command.get("argv", [])]
            elif isinstance(command.get("raw"), str) and len(command["raw"]) > 2048:
                command["raw"] = command["raw"][:2048] + "<truncated>"
        payload = json.dumps(clean, sort_keys=True, ensure_ascii=False)
        try:
            with self._lock, self._connection:
                row = self._connection.execute("SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1").fetchone()
                previous = row[0] if row else None
                event_hash = digest_payload({"previous": previous, "event": clean})
                self._connection.execute(
                    "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(event.event_id), event.occurred_at.isoformat(), event.event_type, event.gateway_id,
                     event.agent_id, event.session_key, event.run_id, event.tool_call_id,
                     event.tool.name if event.tool else None, payload, event_hash, previous, self._now()),
                )
        except sqlite3.Error as exc:
            self.emergency("critical", "audit_write", str(exc), {"event_id": str(event.event_id), "event": clean})
            raise

    def record_decision(self, decision: Decision, policy_digest: str) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT OR REPLACE INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(decision.decision_id), str(decision.event_id), decision.decision.value,
                     decision.would_decide.value if decision.would_decide else None, decision.risk,
                     decision.reason, decision.parameter_digest, decision.effective_mode, policy_digest, self._now()),
                )
                self._connection.executemany(
                    "INSERT OR IGNORE INTO rule_matches VALUES (?, ?)",
                    [(str(decision.decision_id), rule_id) for rule_id in decision.rule_ids],
                )
        except sqlite3.Error as exc:
            if decision.risk == "critical" or decision.decision.value == "DENY":
                self.emergency("critical", "decision_audit_write", str(exc), decision.model_dump(mode="json"))
            raise

    def record_tool_result(self, result: ToolResultEvent) -> None:
        clean, _ = sanitize(result.output, extra_patterns=self.secret_patterns)
        output_summary = summarize_value(clean)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO tool_results(event_id, tool_call_id, success, exit_code, duration_ms, sanitized_output, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (str(result.event_id), result.tool_call_id, int(result.success), result.exit_code,
                 result.duration_ms, json.dumps(output_summary, ensure_ascii=False, default=str), result.error, self._now()),
            )

    def list_events(self, session: str | None = None, risk: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT e.*, d.decision, d.risk, d.reason FROM events e LEFT JOIN decisions d ON d.event_id=e.event_id WHERE 1=1"
        args: list[Any] = []
        if session:
            sql += " AND e.session_key=?"
            args.append(session)
        if risk:
            sql += " AND d.risk=?"
            args.append(risk)
        sql += " ORDER BY e.occurred_at DESC LIMIT ?"
        args.append(min(max(limit, 1), 1000))
        with self._lock:
            return [dict(row) for row in self._connection.execute(sql, args).fetchall()]

    def replay_events(self, session: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute("SELECT sanitized_json FROM events WHERE session_key=? ORDER BY occurred_at", (session,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def status_counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "events": self._connection.execute("SELECT count(*) FROM events").fetchone()[0],
                "decisions": self._connection.execute("SELECT count(*) FROM decisions").fetchone()[0],
                "pending_approvals": self._connection.execute("SELECT count(*) FROM approvals WHERE status='pending'").fetchone()[0],
                "incidents": self._connection.execute("SELECT count(*) FROM service_incidents").fetchone()[0],
            }

    def integrity_check(self) -> str:
        with self._lock:
            return str(self._connection.execute("PRAGMA integrity_check").fetchone()[0])

    def incident(self, severity: str, category: str, message: str, detail: Any = None) -> None:
        clean, _ = sanitize(detail, extra_patterns=self.secret_patterns)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO service_incidents(severity, category, message, detail_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (severity, category, message, json.dumps(clean, ensure_ascii=False, default=str), self._now()),
            )

    def emergency(self, severity: str, category: str, message: str, detail: Any) -> None:
        clean, _ = sanitize(detail, extra_patterns=self.secret_patterns)
        entry = json.dumps({"at": self._now(), "severity": severity, "category": category, "message": message, "detail": clean}, ensure_ascii=False, default=str)
        self.emergency_path.parent.mkdir(parents=True, exist_ok=True)
        with self.emergency_path.open("a", encoding="utf-8") as handle:
            handle.write(entry + "\n")
        try:
            self.emergency_path.chmod(0o600)
        except OSError:
            pass
