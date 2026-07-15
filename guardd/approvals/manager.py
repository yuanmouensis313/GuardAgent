from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from guardd.audit.store import AuditStore
from guardd.models.decisions import Decision
from guardd.models.events import GuardEvent
from guardd.security import sanitize


class ApprovalError(ValueError):
    pass


class ApprovalManager:
    def __init__(self, store: AuditStore, ttl_seconds: int = 60):
        self.store = store
        self.ttl_seconds = max(1, min(ttl_seconds, 600))
        now = datetime.now(timezone.utc).isoformat()
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "UPDATE approvals SET status='invalidated_restart', resolved_at=? WHERE status='pending'",
                (now,),
            )

    def create(self, event: GuardEvent, decision: Decision) -> UUID:
        approval_id = uuid4()
        expires = datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)
        display = {
            "agent": event.agent_id, "session": event.session_key,
            "channel": event.origin.channel, "sender": event.origin.sender_id,
            "tool": event.tool.model_dump() if event.tool else None,
            "targets": {"paths": event.derived.get("paths", []), "network": event.derived.get("network_targets", []), "commands": event.derived.get("commands", [])},
            "risk": decision.risk, "rule_ids": decision.rule_ids, "reason": decision.reason,
            "task_context": str(event.params.get("task_summary", "not provided by OpenClaw hook"))[:256],
            "allowed_decisions": ["allow-once", "deny"],
        }
        display, _ = sanitize(display, extra_patterns=self.store.secret_patterns)
        with self.store._lock, self.store._connection:
            self.store._connection.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, ?)",
                (str(approval_id), str(decision.decision_id), str(event.event_id), event.agent_id,
                 event.session_key, event.origin.sender_id, decision.parameter_digest,
                 expires.isoformat(), json.dumps(display, ensure_ascii=False, default=str)),
            )
        decision.approval_id = approval_id
        decision.expires_at = expires
        return approval_id

    def list(self, pending_only: bool = True) -> list[dict[str, Any]]:
        self.expire()
        sql = "SELECT * FROM approvals"
        if pending_only:
            sql += " WHERE status='pending'"
        sql += " ORDER BY expires_at"
        with self.store._lock:
            return [dict(row) for row in self.store._connection.execute(sql).fetchall()]

    def resolve(self, approval_id: UUID, allow: bool, operator: str = "local-terminal") -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        with self.store._lock, self.store._connection:
            row = self.store._connection.execute("SELECT * FROM approvals WHERE approval_id=?", (str(approval_id),)).fetchone()
            if not row:
                raise ApprovalError("approval not found")
            if row["status"] != "pending":
                raise ApprovalError(f"approval already {row['status']}")
            expires = datetime.fromisoformat(row["expires_at"])
            if now >= expires:
                self.store._connection.execute("UPDATE approvals SET status='expired', resolved_at=? WHERE approval_id=?", (now.isoformat(), str(approval_id)))
                raise ApprovalError("approval expired")
            created_row = self.store._connection.execute("SELECT created_at FROM decisions WHERE decision_id=?", (row["decision_id"],)).fetchone()
            created = datetime.fromisoformat(created_row[0]) if created_row else now
            status = "allowed_once" if allow else "denied"
            self.store._connection.execute(
                "UPDATE approvals SET status=?, resolved_at=?, operator=?, resolution_ms=? WHERE approval_id=?",
                (status, now.isoformat(), operator, (now - created).total_seconds() * 1000, str(approval_id)),
            )
            return {"approval_id": str(approval_id), "status": status, "event_id": row["event_id"], "parameter_digest": row["parameter_digest"]}

    def consume(self, approval_id: UUID, parameter_digest: str, event: GuardEvent) -> bool:
        with self.store._lock, self.store._connection:
            row = self.store._connection.execute("SELECT * FROM approvals WHERE approval_id=?", (str(approval_id),)).fetchone()
            if not row or row["status"] != "allowed_once":
                return False
            if datetime.now(timezone.utc) >= datetime.fromisoformat(row["expires_at"]):
                return False
            if row["parameter_digest"] != parameter_digest or row["agent_id"] != event.agent_id or row["session_key"] != event.session_key or (row["sender_id"] or None) != event.origin.sender_id:
                return False
            self.store._connection.execute("UPDATE approvals SET status='consumed' WHERE approval_id=?", (str(approval_id),))
            return True

    def expire(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.store._lock, self.store._connection:
            cursor = self.store._connection.execute("UPDATE approvals SET status='expired', resolved_at=? WHERE status='pending' AND expires_at<=?", (now, now))
            return cursor.rowcount
