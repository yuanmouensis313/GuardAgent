from __future__ import annotations

import json
import sqlite3
import threading
import re
import base64
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
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
  mode TEXT NOT NULL, policy_digest TEXT NOT NULL, created_at TEXT NOT NULL,
  task_policy_digest TEXT, task_policy_revision INTEGER, task_policy_verdict TEXT,
  content_verdict_digest TEXT, transformation_digest TEXT
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
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_revisions (
  revision_id TEXT PRIMARY KEY, digest TEXT NOT NULL, source_digest TEXT,
  mode TEXT NOT NULL, operator TEXT NOT NULL, comment TEXT NOT NULL,
  raw_text TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_revisions_created ON policy_revisions(created_at DESC);
CREATE TABLE IF NOT EXISTS operator_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, operator TEXT NOT NULL,
  target_type TEXT NOT NULL, target_id TEXT, detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operator_actions_created ON operator_actions(created_at DESC);
CREATE TABLE IF NOT EXISTS diagnostic_runs (
  job_id TEXT PRIMARY KEY, operator TEXT NOT NULL, status TEXT NOT NULL,
  result_json TEXT, started_at TEXT NOT NULL, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS task_policies (
  task_policy_id TEXT PRIMARY KEY, session_key TEXT NOT NULL, agent_id TEXT NOT NULL,
  revision INTEGER NOT NULL, status TEXT NOT NULL, source_digest TEXT NOT NULL,
  policy_digest TEXT NOT NULL, base_policy_digest TEXT NOT NULL,
  objective_json TEXT NOT NULL, policy_json TEXT NOT NULL, generator_json TEXT NOT NULL,
  created_at TEXT NOT NULL, activated_at TEXT, expires_at TEXT NOT NULL, closed_at TEXT,
  UNIQUE(session_key, revision)
);
CREATE INDEX IF NOT EXISTS idx_task_policies_session_status ON task_policies(session_key, status, revision DESC);
CREATE TABLE IF NOT EXISTS task_policy_confirmations (
  confirmation_id INTEGER PRIMARY KEY AUTOINCREMENT, task_policy_id TEXT NOT NULL,
  operator TEXT NOT NULL, decision TEXT NOT NULL, candidate_digest TEXT NOT NULL,
  previous_digest TEXT, diff_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_confirmations_policy ON task_policy_confirmations(task_policy_id, created_at DESC);
CREATE TABLE IF NOT EXISTS sanitization_events (
  sanitizer_event_id TEXT PRIMARY KEY, direction TEXT NOT NULL, session_key TEXT NOT NULL,
  tool_name TEXT NOT NULL, tool_call_id TEXT, classifications_json TEXT NOT NULL,
  transformations_json TEXT NOT NULL, original_size INTEGER NOT NULL, result_size INTEGER NOT NULL,
  truncated INTEGER NOT NULL, blocked INTEGER NOT NULL, pattern_digest TEXT, content_digest TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sanitization_session_created ON sanitization_events(session_key, created_at DESC);
CREATE TABLE IF NOT EXISTS content_artifacts (
  artifact_id TEXT PRIMARY KEY, kind TEXT NOT NULL, canonical_name TEXT NOT NULL,
  source_identity TEXT NOT NULL, content_digest TEXT NOT NULL, manifest_json TEXT NOT NULL,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  UNIQUE(kind, source_identity, content_digest)
);
CREATE INDEX IF NOT EXISTS idx_content_artifacts_digest ON content_artifacts(content_digest, last_seen_at DESC);
CREATE TABLE IF NOT EXISTS inspection_verdicts (
  verdict_id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, status TEXT NOT NULL,
  decision TEXT NOT NULL, risk TEXT NOT NULL, scanner_version TEXT NOT NULL,
  inspection_policy_digest TEXT NOT NULL, llm_reviewer_json TEXT,
  findings_json TEXT NOT NULL, capability_manifest_json TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_inspection_artifact_created ON inspection_verdicts(artifact_id, created_at DESC);
CREATE TABLE IF NOT EXISTS content_confirmations (
  confirmation_id TEXT PRIMARY KEY, verdict_id TEXT NOT NULL, operator TEXT NOT NULL,
  decision TEXT NOT NULL, scope TEXT NOT NULL, session_key TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_content_confirmations_verdict ON content_confirmations(verdict_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_occurred_event ON events(occurred_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_risk_created ON decisions(risk, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_kind_created ON decisions(decision, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rule_matches_rule ON rule_matches(rule_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON service_incidents(created_at DESC);
"""


class AuditStore:
    def __init__(self, path: Path, emergency_path: Path, secret_patterns: list[tuple[str, re.Pattern[str]]] | None = None):
        self.path = path
        self.emergency_path = emergency_path
        self.secret_patterns = secret_patterns or []
        self._event_sink: Callable[[str, dict[str, Any]], None] | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._backup_before_ui_migration()
        self._backup_before_schema_migration()
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, timeout=5, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        try:
            self._connection.executescript(SCHEMA)
            self._ensure_column("decisions", "task_policy_digest", "TEXT")
            self._ensure_column("decisions", "task_policy_revision", "INTEGER")
            self._ensure_column("decisions", "task_policy_verdict", "TEXT")
            self._ensure_column("decisions", "content_verdict_digest", "TEXT")
            self._ensure_column("decisions", "transformation_digest", "TEXT")
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, ?)",
                (self._now(),),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (2, ?)",
                (self._now(),),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (3, ?)",
                (self._now(),),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (4, ?)",
                (self._now(),),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (5, ?)",
                (self._now(),),
            )
            self._connection.commit()
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        except sqlite3.Error:
            self._connection.close()
            backup = self.path.with_name(f"{self.path.name}.pre-schema-v5.bak")
            if not backup.is_file():
                backup = self.path.with_name(f"{self.path.name}.pre-ui-v1.bak")
            if backup.is_file():
                shutil.copy2(backup, self.path)
            raise

    def _backup_before_ui_migration(self) -> None:
        if not self.path.is_file():
            return
        backup = self.path.with_name(f"{self.path.name}.pre-ui-v1.bak")
        if backup.exists():
            return
        shutil.copy2(self.path, backup)
        for suffix in ("-wal", "-shm"):
            companion = Path(f"{self.path}{suffix}")
            if companion.is_file():
                shutil.copy2(companion, Path(f"{backup}{suffix}"))
        try:
            backup.chmod(0o600)
        except OSError:
            pass

    def _backup_before_schema_migration(self) -> None:
        if not self.path.is_file():
            return
        backup = self.path.with_name(f"{self.path.name}.pre-schema-v5.bak")
        if backup.exists():
            return
        shutil.copy2(self.path, backup)
        for suffix in ("-wal", "-shm"):
            companion = Path(f"{self.path}{suffix}")
            if companion.is_file():
                shutil.copy2(companion, Path(f"{backup}{suffix}"))
        try:
            backup.chmod(0o600)
        except OSError:
            pass

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {row[1] for row in self._connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            self._connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def set_event_sink(self, sink: Callable[[str, dict[str, Any]], None] | None) -> None:
        self._event_sink = sink

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
        clean["params"] = summarize_mapping(clean.get("params", {}))
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
                    "INSERT OR REPLACE INTO decisions("
                    "decision_id, event_id, decision, would_decide, risk, reason, parameter_digest, mode, policy_digest, created_at, "
                    "task_policy_digest, task_policy_revision, task_policy_verdict, content_verdict_digest, transformation_digest"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(decision.decision_id), str(decision.event_id), decision.decision.value,
                     decision.would_decide.value if decision.would_decide else None, decision.risk,
                     decision.reason, decision.parameter_digest, decision.effective_mode, policy_digest, self._now(),
                     decision.task_policy_digest, decision.task_policy_revision, decision.task_policy_verdict,
                     decision.content_verdict_digest, decision.transformation_digest),
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

    def record_sanitization_event(self, event: Any) -> None:
        document = event.model_dump(mode="json")
        clean, _ = sanitize(document, extra_patterns=self.secret_patterns)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO sanitization_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.sanitizer_event_id, event.direction, event.session_key, event.tool_name,
                    event.tool_call_id, json.dumps(clean["classifications"], ensure_ascii=False),
                    json.dumps(clean["transformations"], ensure_ascii=False), event.original_size,
                    event.result_size, int(event.truncated), int(event.blocked), event.pattern_digest,
                    event.content_digest, self._now(),
                ),
            )

    def list_sanitization_events(self, session_key: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM sanitization_events"
        args: list[Any] = []
        if session_key:
            sql += " WHERE session_key=?"
            args.append(session_key)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(min(max(limit, 1), 500))
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(sql, args).fetchall()]
        for row in rows:
            row["classifications"] = self._json(row.pop("classifications_json"), [])
            row["transformations"] = self._json(row.pop("transformations_json"), [])
            row["truncated"] = bool(row["truncated"])
            row["blocked"] = bool(row["blocked"])
        return rows

    def sanitization_metrics(self) -> dict[str, int]:
        with self._lock:
            row = self._connection.execute(
                "SELECT count(*) AS total, sum(blocked) AS blocked, sum(truncated) AS truncated, "
                "sum(original_size) AS original_size, sum(result_size) AS result_size FROM sanitization_events",
            ).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def record_content_inspection(self, artifact: Any, verdict: Any) -> tuple[str, str]:
        artifact_document, _ = sanitize(artifact.model_dump(mode="json"), extra_patterns=self.secret_patterns)
        verdict_document, _ = sanitize(verdict.model_dump(mode="json"), extra_patterns=self.secret_patterns)
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT artifact_id, first_seen_at FROM content_artifacts WHERE kind=? AND source_identity=? AND content_digest=?",
                (artifact.kind, artifact_document["source_identity"], artifact.content_digest),
            ).fetchone()
            artifact_id = existing["artifact_id"] if existing else str(artifact.artifact_id)
            if existing:
                self._connection.execute(
                    "UPDATE content_artifacts SET canonical_name=?, manifest_json=?, last_seen_at=? WHERE artifact_id=?",
                    (
                        artifact_document["canonical_name"],
                        json.dumps(artifact_document["manifest"], ensure_ascii=False),
                        artifact.last_seen_at.isoformat(), artifact_id,
                    ),
                )
            else:
                self._connection.execute(
                    "INSERT INTO content_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        artifact_id, artifact.kind, artifact_document["canonical_name"], artifact_document["source_identity"],
                        artifact.content_digest, json.dumps(artifact_document["manifest"], ensure_ascii=False),
                        artifact.first_seen_at.isoformat(), artifact.last_seen_at.isoformat(),
                    ),
                )
            verdict_id = str(verdict.verdict_id)
            self._connection.execute(
                "INSERT INTO inspection_verdicts VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                (
                    verdict_id, artifact_id, verdict.status, verdict.decision.value, verdict.risk,
                    verdict.scanner_version, verdict.inspection_policy_digest,
                    json.dumps(verdict_document["findings"], ensure_ascii=False),
                    json.dumps(verdict_document["capability_manifest"], ensure_ascii=False),
                    verdict.created_at.isoformat(), verdict.expires_at.isoformat() if verdict.expires_at else None,
                ),
            )
        return artifact_id, verdict_id

    def get_cached_inspection(
        self, kind: str, source_identity: str, content_digest: str,
        scanner_version: str, inspection_policy_digest: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT v.* FROM inspection_verdicts v JOIN content_artifacts a ON a.artifact_id=v.artifact_id "
                "WHERE a.kind=? AND a.source_identity=? AND a.content_digest=? AND v.scanner_version=? "
                "AND v.inspection_policy_digest=? AND v.status='valid' ORDER BY v.created_at DESC LIMIT 1",
                (kind, source_identity, content_digest, scanner_version, inspection_policy_digest),
            ).fetchone()
        return self._inspection_verdict_row(row) if row else None

    def _inspection_verdict_row(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["findings"] = self._json(item.pop("findings_json"), [])
        item["capability_manifest"] = self._json(item.pop("capability_manifest_json"), {})
        item["llm_reviewer"] = self._json(item.pop("llm_reviewer_json"), None)
        return item

    def get_inspection(self, content_digest: str) -> dict[str, Any] | None:
        with self._lock:
            artifact = self._connection.execute(
                "SELECT * FROM content_artifacts WHERE content_digest=? ORDER BY last_seen_at DESC LIMIT 1",
                (content_digest,),
            ).fetchone()
            if artifact is None:
                return None
            verdict = self._connection.execute(
                "SELECT * FROM inspection_verdicts WHERE artifact_id=? ORDER BY created_at DESC LIMIT 1",
                (artifact["artifact_id"],),
            ).fetchone()
            confirmations = [dict(row) for row in self._connection.execute(
                "SELECT c.* FROM content_confirmations c JOIN inspection_verdicts v ON v.verdict_id=c.verdict_id "
                "WHERE v.artifact_id=? ORDER BY c.created_at DESC",
                (artifact["artifact_id"],),
            ).fetchall()]
        item = dict(artifact)
        item["manifest"] = self._json(item.pop("manifest_json"), {})
        item["verdict"] = self._inspection_verdict_row(verdict)
        item["confirmations"] = confirmations
        return item

    def list_inspections(self, kind: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = (
            "SELECT a.*, v.verdict_id, v.status AS verdict_status, v.decision, v.risk, v.scanner_version, "
            "v.inspection_policy_digest, v.created_at AS inspected_at, v.expires_at "
            "FROM content_artifacts a LEFT JOIN inspection_verdicts v ON v.verdict_id=("
            "SELECT verdict_id FROM inspection_verdicts WHERE artifact_id=a.artifact_id ORDER BY created_at DESC LIMIT 1)"
        )
        args: list[Any] = []
        if kind:
            sql += " WHERE a.kind=?"
            args.append(kind)
        sql += " ORDER BY a.last_seen_at DESC LIMIT ?"
        args.append(min(max(limit, 1), 500))
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(sql, args).fetchall()]
        for row in rows:
            row["manifest"] = self._json(row.pop("manifest_json"), {})
        return rows

    def record_content_confirmation(
        self, confirmation_id: str, verdict_id: str, operator: str,
        decision: str, scope: str, session_key: str | None,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO content_confirmations VALUES (?, ?, ?, ?, ?, ?, ?)",
                (confirmation_id, verdict_id, operator, decision, scope, session_key, self._now()),
            )

    def invalidate_inspection(self, content_digest: str) -> int:
        with self._lock, self._connection:
            return self._connection.execute(
                "UPDATE inspection_verdicts SET status='stale', decision='STALE' WHERE artifact_id IN "
                "(SELECT artifact_id FROM content_artifacts WHERE content_digest=?) AND status='valid'",
                (content_digest,),
            ).rowcount

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
            rows = self._connection.execute(
                "SELECT e.sanitized_json FROM events e "
                "WHERE e.session_key=? AND EXISTS (SELECT 1 FROM decisions d WHERE d.event_id=e.event_id) "
                "ORDER BY e.occurred_at",
                (session,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def status_counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "events": self._connection.execute("SELECT count(*) FROM events").fetchone()[0],
                "decisions": self._connection.execute("SELECT count(*) FROM decisions").fetchone()[0],
                "pending_approvals": self._connection.execute("SELECT count(*) FROM approvals WHERE status='pending'").fetchone()[0],
                "incidents": self._connection.execute("SELECT count(*) FROM service_incidents").fetchone()[0],
                "active_task_policies": self._connection.execute("SELECT count(*) FROM task_policies WHERE status='active'").fetchone()[0],
                "pending_task_policies": self._connection.execute("SELECT count(*) FROM task_policies WHERE status IN ('candidate', 'revision_candidate')").fetchone()[0],
            }

    @staticmethod
    def _task_policy_from_row(row: sqlite3.Row | None) -> Any:
        if row is None:
            return None
        from guardd.task_policy.models import TaskPolicy

        payload = json.loads(row["policy_json"])
        payload.update({
            "status": row["status"],
            "activated_at": row["activated_at"],
            "closed_at": row["closed_at"],
        })
        return TaskPolicy.model_validate(payload)

    def record_task_policy(self, policy: Any) -> None:
        document = policy.model_dump(mode="json")
        clean, _ = sanitize(document, extra_patterns=self.secret_patterns)
        # These are already one-way structural identifiers. Generic secret
        # detection must not rewrite them or the persisted policy can no longer
        # pass its schema/digest checks on reload.
        for field in ("task_policy_id", "session_key", "agent_id", "policy_digest", "base_policy_digest"):
            clean[field] = document[field]
        clean["objective"]["source_digest"] = document["objective"]["source_digest"]
        clean["provenance"]["prompt_digest"] = document["provenance"]["prompt_digest"]
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO task_policies(task_policy_id, session_key, agent_id, revision, status, source_digest, "
                "policy_digest, base_policy_digest, objective_json, policy_json, generator_json, created_at, activated_at, expires_at, closed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(policy.task_policy_id), policy.session_key, policy.agent_id, policy.revision,
                    policy.status.value, policy.objective.source_digest, policy.policy_digest,
                    policy.base_policy_digest, json.dumps(clean["objective"], ensure_ascii=False),
                    json.dumps(clean, ensure_ascii=False), json.dumps(clean["provenance"], ensure_ascii=False),
                    policy.created_at.isoformat(), None, policy.limits.expires_at.isoformat(), None,
                ),
            )

    def latest_task_policy_revision(self, session_key: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT max(revision) FROM task_policies WHERE session_key=?", (session_key,),
            ).fetchone()
        return int(row[0] or 0)

    def get_task_policy(self, session_key: str, status: str | None = None) -> Any:
        sql = "SELECT * FROM task_policies WHERE session_key=?"
        args: list[Any] = [session_key]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY revision DESC LIMIT 1"
        with self._lock:
            row = self._connection.execute(sql, args).fetchone()
        return self._task_policy_from_row(row)

    def get_pending_task_policy(self, session_key: str) -> Any:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM task_policies WHERE session_key=? AND status IN ('candidate', 'revision_candidate') "
                "ORDER BY revision DESC LIMIT 1",
                (session_key,),
            ).fetchone()
        return self._task_policy_from_row(row)

    def supersede_pending_task_policies(self, session_key: str) -> int:
        with self._lock, self._connection:
            return self._connection.execute(
                "UPDATE task_policies SET status='superseded', closed_at=? "
                "WHERE session_key=? AND status IN ('candidate', 'revision_candidate')",
                (self._now(), session_key),
            ).rowcount

    def list_task_policies(self, session_key: str, limit: int = 100) -> list[Any]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM task_policies WHERE session_key=? ORDER BY revision DESC LIMIT ?",
                (session_key, min(max(limit, 1), 500)),
            ).fetchall()
        return [self._task_policy_from_row(row) for row in rows]

    def list_task_policy_confirmations(self, session_key: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT c.confirmation_id, c.task_policy_id, c.operator, c.decision, c.candidate_digest, "
                "c.previous_digest, c.diff_json, c.created_at FROM task_policy_confirmations c "
                "JOIN task_policies p ON p.task_policy_id=c.task_policy_id "
                "WHERE p.session_key=? ORDER BY c.confirmation_id DESC LIMIT ?",
                (session_key, min(max(limit, 1), 500)),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["diff"] = self._json(item.pop("diff_json"), {})
            result.append(item)
        return result

    def task_policy_usage(self, session_key: str, activated_at: datetime) -> dict[str, Any]:
        """Count calls that reached execution after the selected policy revision became active."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT e.sanitized_json, d.decision, tr.event_id AS has_result "
                "FROM events e JOIN decisions d ON d.event_id=e.event_id "
                "LEFT JOIN tool_results tr ON tr.event_id=e.event_id "
                "WHERE e.session_key=? AND e.event_type='tool.before' AND e.occurred_at>=? "
                "ORDER BY e.occurred_at",
                (session_key, activated_at.isoformat()),
            ).fetchall()
        tool_calls = 0
        external_writes = 0
        files_changed: set[str] = set()
        for row in rows:
            if row["decision"] != "ALLOW" and row["has_result"] is None:
                continue
            event = self._json(row["sanitized_json"], {})
            tool_calls += 1
            derived = event.get("derived", {})
            if any(item.get("direction") == "outbound_write" for item in derived.get("network_targets", [])):
                external_writes += 1
            for item in derived.get("paths", []):
                if item.get("access") == "write" and item.get("resolved"):
                    files_changed.add(str(item["resolved"]))
        return {
            "tool_calls": tool_calls,
            "external_writes": external_writes,
            "files_changed": sorted(files_changed),
        }

    def activate_task_policy(
        self, *, session_key: str, candidate_digest: str,
        expected_active_revision: int | None, operator: str,
        base_policy_digest: str,
    ) -> Any:
        now = self._now()
        with self._lock, self._connection:
            candidate = self._connection.execute(
                "SELECT * FROM task_policies WHERE session_key=? AND status IN ('candidate', 'revision_candidate') AND policy_digest=? ORDER BY revision DESC LIMIT 1",
                (session_key, candidate_digest),
            ).fetchone()
            if candidate is None or candidate["base_policy_digest"] != base_policy_digest:
                return None
            active = self._connection.execute(
                "SELECT * FROM task_policies WHERE session_key=? AND status='active' ORDER BY revision DESC LIMIT 1",
                (session_key,),
            ).fetchone()
            active_revision = int(active["revision"]) if active else None
            if active_revision != expected_active_revision:
                return None
            previous_digest = active["policy_digest"] if active else None
            if active:
                self._connection.execute(
                    "UPDATE task_policies SET status='superseded', closed_at=? WHERE task_policy_id=?",
                    (now, active["task_policy_id"]),
                )
            self._connection.execute(
                "UPDATE task_policies SET status='active', activated_at=? WHERE task_policy_id=? AND status IN ('candidate', 'revision_candidate')",
                (now, candidate["task_policy_id"]),
            )
            self._connection.execute(
                "INSERT INTO task_policy_confirmations(task_policy_id, operator, decision, candidate_digest, previous_digest, diff_json, created_at) "
                "VALUES (?, ?, 'activate', ?, ?, ?, ?)",
                (candidate["task_policy_id"], operator, candidate_digest, previous_digest,
                 json.dumps({"from_revision": active_revision, "to_revision": candidate["revision"]}), now),
            )
            row = self._connection.execute(
                "SELECT * FROM task_policies WHERE task_policy_id=?", (candidate["task_policy_id"],),
            ).fetchone()
        return self._task_policy_from_row(row)

    def reject_task_policy(self, session_key: str, candidate_digest: str, operator: str) -> Any:
        now = self._now()
        with self._lock, self._connection:
            candidate = self._connection.execute(
                "SELECT * FROM task_policies WHERE session_key=? AND status IN ('candidate', 'revision_candidate') AND policy_digest=? ORDER BY revision DESC LIMIT 1",
                (session_key, candidate_digest),
            ).fetchone()
            if candidate is None:
                return None
            self._connection.execute(
                "UPDATE task_policies SET status='rejected', closed_at=? WHERE task_policy_id=?",
                (now, candidate["task_policy_id"]),
            )
            self._connection.execute(
                "INSERT INTO task_policy_confirmations(task_policy_id, operator, decision, candidate_digest, previous_digest, diff_json, created_at) "
                "VALUES (?, ?, 'reject', ?, NULL, '{}', ?)",
                (candidate["task_policy_id"], operator, candidate_digest, now),
            )
            row = self._connection.execute(
                "SELECT * FROM task_policies WHERE task_policy_id=?", (candidate["task_policy_id"],),
            ).fetchone()
        return self._task_policy_from_row(row)

    def close_task_policies(self, session_key: str, operator: str) -> int:
        now = self._now()
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT task_policy_id, policy_digest FROM task_policies WHERE session_key=? AND status IN ('candidate', 'revision_candidate', 'active')",
                (session_key,),
            ).fetchall()
            if not rows:
                return 0
            self._connection.execute(
                "UPDATE task_policies SET status='closed', closed_at=? WHERE session_key=? AND status IN ('candidate', 'revision_candidate', 'active')",
                (now, session_key),
            )
            self._connection.executemany(
                "INSERT INTO task_policy_confirmations(task_policy_id, operator, decision, candidate_digest, previous_digest, diff_json, created_at) "
                "VALUES (?, ?, 'close', ?, NULL, '{}', ?)",
                [(row["task_policy_id"], operator, row["policy_digest"], now) for row in rows],
            )
            return len(rows)

    def close_child_task_policies(self, parent_session_key: str, operator: str) -> int:
        now = self._now()
        with self._lock, self._connection:
            candidates = self._connection.execute(
                "SELECT task_policy_id, policy_digest, policy_json FROM task_policies "
                "WHERE status IN ('candidate', 'revision_candidate', 'active')",
            ).fetchall()
            rows = [
                row for row in candidates
                if self._json(row["policy_json"], {}).get("parent_session_key") == parent_session_key
            ]
            if not rows:
                return 0
            self._connection.executemany(
                "UPDATE task_policies SET status='closed', closed_at=? WHERE task_policy_id=?",
                [(now, row["task_policy_id"]) for row in rows],
            )
            self._connection.executemany(
                "INSERT INTO task_policy_confirmations(task_policy_id, operator, decision, candidate_digest, previous_digest, diff_json, created_at) "
                "VALUES (?, ?, 'parent_close', ?, NULL, '{}', ?)",
                [(row["task_policy_id"], operator, row["policy_digest"], now) for row in rows],
            )
            return len(rows)

    def expire_task_policy(self, task_policy_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE task_policies SET status='expired', closed_at=? WHERE task_policy_id=? AND status='active'",
                (self._now(), task_policy_id),
            )

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
        if self._event_sink:
            try:
                self._event_sink("incident.created", {"severity": severity, "category": category})
            except Exception:
                # Audit persistence must not fail because a best-effort UI notification failed.
                pass

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

    @staticmethod
    def _encode_cursor(values: dict[str, str]) -> str:
        payload = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(cursor: str) -> dict[str, str]:
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
                raise ValueError("invalid cursor")
            return value
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid cursor") from exc

    @staticmethod
    def _json(value: Any, default: Any = None) -> Any:
        if value is None:
            return default
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return default

    def list_events_page(
        self,
        filters: dict[str, Any] | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        filters = filters or {}
        page_size = min(max(int(limit), 1), 200)
        sql = (
            "SELECT e.*, d.decision_id, d.decision, d.would_decide, d.risk, d.reason, "
            "d.mode, d.policy_digest, "
            "(SELECT group_concat(rule_id, ',') FROM rule_matches rm WHERE rm.decision_id=d.decision_id) AS rule_ids, "
            "(SELECT success FROM tool_results tr WHERE tr.event_id=e.event_id ORDER BY tr.id DESC LIMIT 1) AS tool_success, "
            "EXISTS(SELECT 1 FROM approvals a WHERE a.event_id=e.event_id) AS has_approval "
            "FROM events e LEFT JOIN decisions d ON d.event_id=e.event_id WHERE 1=1"
        )
        args: list[Any] = []
        simple = {
            "session": "e.session_key=?", "risk": "d.risk=?", "decision": "d.decision=?",
            "would_decide": "d.would_decide=?", "agent": "e.agent_id=?", "tool": "e.tool_name=?", "event_type": "e.event_type=?",
        }
        for key, clause in simple.items():
            value = filters.get(key)
            if value:
                sql += f" AND {clause}"
                args.append(str(value))
        if filters.get("rule_id"):
            sql += " AND EXISTS(SELECT 1 FROM rule_matches rf WHERE rf.decision_id=d.decision_id AND rf.rule_id=?)"
            args.append(str(filters["rule_id"]))
        if filters.get("since"):
            sql += " AND e.occurred_at>=?"
            args.append(str(filters["since"]))
        if filters.get("until"):
            sql += " AND e.occurred_at<=?"
            args.append(str(filters["until"]))
        if filters.get("has_approval") is not None:
            sql += " AND EXISTS(SELECT 1 FROM approvals af WHERE af.event_id=e.event_id)=?"
            args.append(int(bool(filters["has_approval"])))
        if filters.get("success") is not None:
            sql += " AND EXISTS(SELECT 1 FROM tool_results tf WHERE tf.event_id=e.event_id AND tf.success=?)"
            args.append(int(bool(filters["success"])))
        if filters.get("q"):
            value = f"%{str(filters['q'])[:200]}%"
            sql += (
                " AND (e.tool_name LIKE ? OR e.event_type LIKE ? OR e.session_key LIKE ? OR d.reason LIKE ? "
                "OR e.sanitized_json LIKE ? OR EXISTS(SELECT 1 FROM rule_matches rq WHERE rq.decision_id=d.decision_id AND rq.rule_id LIKE ?))"
            )
            args.extend([value, value, value, value, value, value])
        if cursor:
            decoded = self._decode_cursor(cursor)
            at, event_id = decoded.get("at"), decoded.get("id")
            if not at or not event_id:
                raise ValueError("invalid cursor")
            sql += " AND (e.occurred_at<? OR (e.occurred_at=? AND e.event_id<?))"
            args.extend([at, at, event_id])
        sql += " ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT ?"
        args.append(page_size + 1)
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(sql, args).fetchall()]
        more = len(rows) > page_size
        rows = rows[:page_size]
        items = []
        for row in rows:
            item = {
                "event_id": row["event_id"], "occurred_at": row["occurred_at"],
                "event_type": row["event_type"], "agent_id": row["agent_id"],
                "session_key": row["session_key"], "tool_name": row["tool_name"],
                "decision_id": row.get("decision_id"), "decision": row.get("decision"),
                "would_decide": row.get("would_decide"), "risk": row.get("risk"),
                "reason": row.get("reason"), "mode": row.get("mode"),
                "policy_digest": row.get("policy_digest"),
                "rule_ids": row.get("rule_ids", "").split(",") if row.get("rule_ids") else [],
                "tool_success": None if row.get("tool_success") is None else bool(row["tool_success"]),
                "has_approval": bool(row.get("has_approval")),
            }
            items.append(item)
        next_cursor = None
        if more and items:
            last = items[-1]
            next_cursor = self._encode_cursor({"at": last["occurred_at"], "id": last["event_id"]})
        return {"items": items, "next_cursor": next_cursor}

    def get_event_detail(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT e.*, d.decision_id, d.decision, d.would_decide, d.risk, d.reason, "
                "d.parameter_digest, d.mode, d.policy_digest, d.created_at AS decision_created_at "
                "FROM events e LEFT JOIN decisions d ON d.event_id=e.event_id WHERE e.event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["event"] = self._json(result.pop("sanitized_json"), {})
            result["rule_ids"] = [
                item[0] for item in self._connection.execute(
                    "SELECT rule_id FROM rule_matches WHERE decision_id=? ORDER BY rule_id", (result.get("decision_id"),)
                ).fetchall()
            ]
            tool_results = [dict(item) for item in self._connection.execute(
                "SELECT id, tool_call_id, success, exit_code, duration_ms, sanitized_output, error, created_at "
                "FROM tool_results WHERE event_id=? ORDER BY id", (event_id,)
            ).fetchall()]
            for item in tool_results:
                item["success"] = bool(item["success"])
                item["sanitized_output"] = self._json(item["sanitized_output"], item["sanitized_output"])
            result["tool_results"] = tool_results
            approval = self._connection.execute("SELECT * FROM approvals WHERE event_id=? ORDER BY expires_at DESC LIMIT 1", (event_id,)).fetchone()
            result["approval"] = dict(approval) if approval else None
            if result["approval"]:
                result["approval"]["display"] = self._json(result["approval"].pop("display_json"), {})
        return result

    def list_approvals_page(
        self, status: str | None = None, risk: str | None = None,
        cursor: str | None = None, limit: int = 50,
    ) -> dict[str, Any]:
        page_size = min(max(int(limit), 1), 200)
        sql = (
            "SELECT a.*, d.risk, d.reason, d.decision, d.would_decide, d.created_at AS created_at, "
            "(SELECT group_concat(rule_id, ',') FROM rule_matches rm WHERE rm.decision_id=d.decision_id) AS rule_ids "
            "FROM approvals a JOIN decisions d ON d.decision_id=a.decision_id WHERE 1=1"
        )
        args: list[Any] = []
        if status:
            sql += " AND a.status=?"
            args.append(status)
        if risk:
            sql += " AND d.risk=?"
            args.append(risk)
        if cursor:
            decoded = self._decode_cursor(cursor)
            at, approval_id = decoded.get("at"), decoded.get("id")
            if not at or not approval_id:
                raise ValueError("invalid cursor")
            sql += " AND (a.expires_at>? OR (a.expires_at=? AND a.approval_id>?))"
            args.extend([at, at, approval_id])
        sql += " ORDER BY a.expires_at, a.approval_id LIMIT ?"
        args.append(page_size + 1)
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(sql, args).fetchall()]
        more = len(rows) > page_size
        rows = rows[:page_size]
        for row in rows:
            row["display"] = self._json(row.pop("display_json"), {})
            row["rule_ids"] = row.get("rule_ids", "").split(",") if row.get("rule_ids") else []
        next_cursor = None
        if more and rows:
            last = rows[-1]
            next_cursor = self._encode_cursor({"at": last["expires_at"], "id": last["approval_id"]})
        return {"items": rows, "next_cursor": next_cursor}

    def get_approval_detail(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT a.*, d.risk, d.reason, d.decision, d.would_decide, d.mode, d.policy_digest "
                "FROM approvals a JOIN decisions d ON d.decision_id=a.decision_id WHERE a.approval_id=?",
                (approval_id,),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["display"] = self._json(result.pop("display_json"), {})
            result["rule_ids"] = [item[0] for item in self._connection.execute(
                "SELECT rule_id FROM rule_matches WHERE decision_id=? ORDER BY rule_id", (result["decision_id"],)
            ).fetchall()]
            event = self._connection.execute("SELECT sanitized_json FROM events WHERE event_id=?", (result["event_id"],)).fetchone()
            result["event"] = self._json(event[0], {}) if event else None
            return result

    def list_sessions_page(self, cursor: str | None = None, limit: int = 50) -> dict[str, Any]:
        page_size = min(max(int(limit), 1), 200)
        sql = (
            "SELECT e.session_key, min(e.occurred_at) AS started_at, max(e.occurred_at) AS last_seen, "
            "min(e.agent_id) AS agent_id, count(*) AS event_count, "
            "sum(CASE WHEN d.decision='DENY' THEN 1 ELSE 0 END) AS deny_count, "
            "sum(CASE WHEN a.status='pending' THEN 1 ELSE 0 END) AS pending_approvals, "
            "max(CASE d.risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS risk_rank, "
            "max(s.status) AS recorded_status FROM events e "
            "LEFT JOIN decisions d ON d.event_id=e.event_id "
            "LEFT JOIN approvals a ON a.event_id=e.event_id "
            "LEFT JOIN sessions s ON s.session_key=e.session_key WHERE 1=1"
        )
        args: list[Any] = []
        if cursor:
            decoded = self._decode_cursor(cursor)
            at, session_key = decoded.get("at"), decoded.get("id")
            if not at or not session_key:
                raise ValueError("invalid cursor")
            sql += " AND e.session_key IN (SELECT session_key FROM events GROUP BY session_key HAVING max(occurred_at)<? OR (max(occurred_at)=? AND session_key<?))"
            args.extend([at, at, session_key])
        sql += " GROUP BY e.session_key ORDER BY last_seen DESC, e.session_key DESC LIMIT ?"
        args.append(page_size + 1)
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(sql, args).fetchall()]
        more = len(rows) > page_size
        rows = rows[:page_size]
        risks = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        for row in rows:
            row["max_risk"] = risks.get(int(row.pop("risk_rank") or 0), "info")
            row["status"] = row.pop("recorded_status") or "inferred"
        next_cursor = None
        if more and rows:
            last = rows[-1]
            next_cursor = self._encode_cursor({"at": last["last_seen"], "id": last["session_key"]})
        return {"items": rows, "next_cursor": next_cursor}

    def get_session_detail(self, session_key: str) -> dict[str, Any] | None:
        page = self.list_events_page({"session": session_key}, limit=200)
        if not page["items"]:
            return None
        with self._lock:
            state = self._connection.execute("SELECT * FROM sessions WHERE session_key=?", (session_key,)).fetchone()
            rows = self._connection.execute(
                "SELECT e.event_id, e.sanitized_json, d.decision, d.would_decide, d.risk, d.reason, d.policy_digest "
                "FROM events e LEFT JOIN decisions d ON d.event_id=e.event_id WHERE e.session_key=? "
                "ORDER BY e.occurred_at DESC LIMIT 1000",
                (session_key,),
            ).fetchall()
            total = self._connection.execute("SELECT count(*) FROM events WHERE session_key=?", (session_key,)).fetchone()[0]
            matched_rules = self._connection.execute(
                "SELECT d.event_id, rm.rule_id FROM events e JOIN decisions d ON d.event_id=e.event_id "
                "JOIN rule_matches rm ON rm.decision_id=d.decision_id WHERE e.session_key=?",
                (session_key,),
            ).fetchall()
            result_rows = self._connection.execute(
                "SELECT tr.event_id, tr.sanitized_output FROM tool_results tr "
                "JOIN events e ON e.event_id=tr.event_id WHERE e.session_key=?",
                (session_key,),
            ).fetchall()
        rules_by_event: defaultdict[str, list[str]] = defaultdict(list)
        for matched in matched_rules:
            rules_by_event[matched["event_id"]].append(matched["rule_id"])
        timeline = []
        tool_counts: Counter[str] = Counter()
        rule_counts: Counter[str] = Counter()
        result_bytes: defaultdict[str, int] = defaultdict(int)
        for result_row in result_rows:
            summary = self._json(result_row["sanitized_output"], {})
            if isinstance(summary, dict):
                result_bytes[result_row["event_id"]] += int(summary.get("len", 0) or 0)
        read_bytes = 0
        write_bytes = 0
        risk_score = 0
        risk_weights = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}
        for row in reversed(rows):
            event = self._json(row["sanitized_json"], {})
            tool = ((event.get("tool") or {}).get("name") if isinstance(event, dict) else None) or "lifecycle"
            tool_counts[tool] += 1
            for rule in rules_by_event.get(row["event_id"], []):
                rule_counts[rule] += 1
            derived = event.get("derived", {}) if isinstance(event, dict) else {}
            actions = set(derived.get("actions", [])) if isinstance(derived, dict) else set()
            if "read" in actions:
                read_bytes += result_bytes[row["event_id"]]
            if actions & {"write", "delete"}:
                metrics = derived.get("file_metrics", {})
                write_bytes += int(metrics.get("total_bytes", 0) or 0) if isinstance(metrics, dict) else 0
            risk_score += risk_weights.get(row["risk"] or "info", 3)
            timeline.append({
                "event": event, "decision": row["decision"], "would_decide": row["would_decide"],
                "risk": row["risk"], "reason": row["reason"], "policy_digest": row["policy_digest"],
            })
        return {
            "session_key": session_key, "state": dict(state) if state else {"status": "inferred"},
            "timeline": timeline, "timeline_total": total, "timeline_truncated": total > len(timeline),
            "tool_counts": dict(tool_counts), "rule_counts": dict(rule_counts),
            "io_summary": {"read_bytes": read_bytes, "write_bytes": write_bytes},
            "risk_score": risk_score,
        }

    def overview_metrics(self, since: str, bucket: str = "hour") -> dict[str, Any]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT e.occurred_at, e.event_id, e.event_type, e.tool_name, d.decision, d.would_decide, d.risk "
                "FROM events e LEFT JOIN decisions d ON d.event_id=e.event_id WHERE e.occurred_at>=? ORDER BY e.occurred_at",
                (since,),
            ).fetchall()
            rule_rows = self._connection.execute(
                "SELECT rm.rule_id, count(*) AS total, sum(CASE WHEN d.decision='DENY' THEN 1 ELSE 0 END) AS denied, max(d.created_at) AS last_seen "
                "FROM rule_matches rm JOIN decisions d ON d.decision_id=rm.decision_id WHERE d.created_at>=? "
                "GROUP BY rm.rule_id ORDER BY total DESC, rm.rule_id LIMIT 10", (since,),
            ).fetchall()
        decision_counts: Counter[str] = Counter()
        would_counts: Counter[str] = Counter()
        risk_counts: Counter[str] = Counter()
        trend: defaultdict[str, int] = defaultdict(int)
        for row in rows:
            decision_counts[row["decision"] or "NO_DECISION"] += 1
            if row["would_decide"]:
                would_counts[row["would_decide"]] += 1
            risk_counts[row["risk"] or "none"] += 1
            try:
                occurred = datetime.fromisoformat(row["occurred_at"])
                if bucket == "five_minutes":
                    key = occurred.replace(minute=(occurred.minute // 5) * 5, second=0, microsecond=0).isoformat()
                elif bucket == "day":
                    key = occurred.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                else:
                    key = occurred.replace(minute=0, second=0, microsecond=0).isoformat()
            except ValueError:
                key = row["occurred_at"][:13]
            trend[key] += 1
        return {
            "events": len(rows), "bucket": bucket, "decisions": dict(decision_counts), "would_decide": dict(would_counts),
            "risks": dict(risk_counts), "trend": [{"at": key, "count": trend[key]} for key in sorted(trend)],
            "top_rules": [dict(row) for row in rule_rows],
        }

    def list_incidents_page(self, cursor: int | None = None, limit: int = 50) -> dict[str, Any]:
        page_size = min(max(int(limit), 1), 200)
        sql = "SELECT * FROM service_incidents"
        args: list[Any] = []
        if cursor is not None:
            sql += " WHERE id<?"
            args.append(cursor)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(page_size + 1)
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(sql, args).fetchall()]
        more = len(rows) > page_size
        rows = rows[:page_size]
        for row in rows:
            row["detail"] = self._json(row.pop("detail_json"), {})
        return {"items": rows, "next_cursor": rows[-1]["id"] if more and rows else None}

    def record_operator_action(
        self, action: str, operator: str, target_type: str,
        target_id: str | None = None, detail: Any = None,
    ) -> None:
        clean, _ = sanitize(detail, extra_patterns=self.secret_patterns)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO operator_actions(action, operator, target_type, target_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (action, operator, target_type, target_id, json.dumps(clean, ensure_ascii=False, default=str), self._now()),
            )

    def record_policy_revision(
        self, revision_id: str, digest: str, source_digest: str | None, mode: str,
        operator: str, comment: str, raw_text: str, result: str,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO policy_revisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (revision_id, digest, source_digest, mode, operator, comment[:500], raw_text, result, self._now()),
            )

    def list_policy_revisions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._connection.execute(
                "SELECT revision_id, digest, source_digest, mode, operator, comment, result, created_at "
                "FROM policy_revisions ORDER BY created_at DESC LIMIT ?", (min(max(limit, 1), 500),)
            ).fetchall()]

    def get_policy_revision(self, revision_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute("SELECT * FROM policy_revisions WHERE revision_id=?", (revision_id,)).fetchone()
            return dict(row) if row else None

    def mark_policy_revision_result(self, revision_id: str, result: str) -> None:
        with self._lock, self._connection:
            self._connection.execute("UPDATE policy_revisions SET result=? WHERE revision_id=?", (result, revision_id))

    def record_diagnostic_job(
        self, job_id: str, operator: str, status: str,
        result: Any = None, started_at: str | None = None, completed_at: str | None = None,
    ) -> None:
        clean, _ = sanitize(result, extra_patterns=self.secret_patterns)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO diagnostic_runs(job_id, operator, status, result_json, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(job_id) DO UPDATE SET status=excluded.status, result_json=excluded.result_json, completed_at=excluded.completed_at",
                (job_id, operator, status, json.dumps(clean, ensure_ascii=False, default=str) if result is not None else None,
                 started_at or self._now(), completed_at),
            )

    def list_diagnostic_jobs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(row) for row in self._connection.execute(
                "SELECT * FROM diagnostic_runs ORDER BY started_at DESC LIMIT ?", (min(max(limit, 1), 100),)
            ).fetchall()]
        for row in rows:
            row["result"] = self._json(row.pop("result_json"), None)
        return rows

    def purge_before(self, cutoff: str) -> dict[str, int]:
        """Apply configured retention without touching policy revisions or the hash values of retained events."""
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT e.event_id, d.decision_id FROM events e LEFT JOIN decisions d ON d.event_id=e.event_id WHERE e.occurred_at<?",
                (cutoff,),
            ).fetchall()
            event_ids = [row["event_id"] for row in rows]
            decision_ids = [row["decision_id"] for row in rows if row["decision_id"]]
            for event_id in event_ids:
                self._connection.execute("DELETE FROM tool_results WHERE event_id=?", (event_id,))
                self._connection.execute("DELETE FROM approvals WHERE event_id=?", (event_id,))
            for decision_id in decision_ids:
                self._connection.execute("DELETE FROM rule_matches WHERE decision_id=?", (decision_id,))
                self._connection.execute("DELETE FROM decisions WHERE decision_id=?", (decision_id,))
            if event_ids:
                self._connection.executemany("DELETE FROM events WHERE event_id=?", [(event_id,) for event_id in event_ids])
            self._connection.execute("DELETE FROM sessions WHERE session_key NOT IN (SELECT DISTINCT session_key FROM events)")
            incidents = self._connection.execute("DELETE FROM service_incidents WHERE created_at<?", (cutoff,)).rowcount
            actions = self._connection.execute("DELETE FROM operator_actions WHERE created_at<?", (cutoff,)).rowcount
            diagnostics = self._connection.execute("DELETE FROM diagnostic_runs WHERE started_at<?", (cutoff,)).rowcount
        return {"events": len(event_ids), "decisions": len(decision_ids), "incidents": incidents, "operator_actions": actions, "diagnostics": diagnostics}
