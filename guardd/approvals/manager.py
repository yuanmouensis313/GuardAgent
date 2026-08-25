from __future__ import annotations

import hmac
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
    def __init__(
        self,
        store: AuditStore,
        ttl_seconds: int = 60,
        *,
        review_mode: str = "disabled",
        review_deny_confidence_threshold: float = 0.92,
        enforceable_review_threats: set[str] | None = None,
    ):
        self.store = store
        self.ttl_seconds = max(1, min(ttl_seconds, 600))
        self.review_mode = review_mode
        self.review_deny_confidence_threshold = min(1.0, max(0.0, review_deny_confidence_threshold))
        self.enforceable_review_threats = enforceable_review_threats or {
            "prompt_injection", "secret_exfiltration", "security_bypass", "destructive_action",
        }
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
            resolution_gate = None
            blocked_reason_code = None
            if decision.review_id and decision.review_status in {"pending", "queued", "running"}:
                review = self.store._connection.execute(
                    "SELECT j.status, r.verdict, r.confidence, r.threats_json, r.evidence_json "
                    "FROM llm_review_jobs j LEFT JOIN llm_reviews r ON r.review_id=j.review_id "
                    "WHERE j.review_id=?",
                    (str(decision.review_id),),
                ).fetchone()
                review_status = review["status"] if review else decision.review_status
                if review_status == "completed":
                    threats = set(json.loads(review["threats_json"] or "[]"))
                    evidence = json.loads(review["evidence_json"] or "[]")
                    blocks = (
                        self.review_mode == "enforce_tighten"
                        and review["verdict"] == "DENY"
                        and float(review["confidence"] or 0) >= self.review_deny_confidence_threshold
                        and bool(evidence)
                        and bool(threats & self.enforceable_review_threats)
                    )
                    resolution_gate = "blocked_by_review" if blocks else None
                    blocked_reason_code = "LLM_REVIEW_DENY" if blocks else None
                elif review_status in {"failed", "timed_out", "invalid", "cancelled"}:
                    resolution_gate = "review_degraded"
                    blocked_reason_code = "LLM_REVIEW_FAILED"
                else:
                    resolution_gate = "review_complete"
            self.store._connection.execute(
                "INSERT INTO approvals("
                "approval_id, decision_id, event_id, agent_id, session_key, sender_id, parameter_digest, "
                "status, expires_at, resolved_at, operator, resolution_ms, display_json, "
                "resolution_gate, blocking_review_id, blocked_reason_code"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, ?, ?, ?, ?)",
                (str(approval_id), str(decision.decision_id), str(event.event_id), event.agent_id,
                 event.session_key, event.origin.sender_id, decision.parameter_digest,
                 expires.isoformat(), json.dumps(display, ensure_ascii=False, default=str),
                 resolution_gate, str(decision.review_id) if decision.review_id else None,
                 blocked_reason_code),
            )
        decision.approval_id = approval_id
        decision.expires_at = expires
        return approval_id

    def list(self, pending_only: bool = True) -> list[dict[str, Any]]:
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
            if allow and row["resolution_gate"] == "review_complete":
                raise ApprovalError("REVIEW_PENDING")
            if allow and row["resolution_gate"] == "blocked_by_review":
                raise ApprovalError("approval blocked by semantic review")
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

    def override_review_block(
        self,
        approval_id: UUID,
        *,
        parameter_digest: str,
        operator: str,
        reason: str,
    ) -> dict[str, Any]:
        """Release only an LLM review gate; the underlying approval remains pending."""
        now = datetime.now(timezone.utc)
        clean_reason, _ = sanitize(reason, extra_patterns=self.store.secret_patterns)
        normalized_reason = str(clean_reason).strip()
        if len(normalized_reason) < 10:
            raise ApprovalError("security override reason must contain at least 10 characters")
        with self.store._lock, self.store._connection:
            row = self.store._connection.execute(
                "SELECT * FROM approvals WHERE approval_id=?",
                (str(approval_id),),
            ).fetchone()
            if row is None:
                raise ApprovalError("approval not found")
            if row["status"] != "pending":
                raise ApprovalError(f"approval already {row['status']}")
            if row["resolution_gate"] != "blocked_by_review":
                raise ApprovalError("approval is not blocked by semantic review")
            if not hmac.compare_digest(str(row["parameter_digest"]), parameter_digest):
                raise ApprovalError("parameter digest mismatch")
            if now >= datetime.fromisoformat(row["expires_at"]):
                self.store._connection.execute(
                    "UPDATE approvals SET status='expired', resolved_at=? WHERE approval_id=?",
                    (now.isoformat(), str(approval_id)),
                )
                raise ApprovalError("approval expired")
            self.store._connection.execute(
                "UPDATE approvals SET status='review_overridden', resolved_at=?, operator=?, "
                "resolution_gate=NULL, blocked_reason_code='LLM_REVIEW_OVERRIDE' "
                "WHERE approval_id=? AND resolution_gate='blocked_by_review'",
                (now.isoformat(), operator, str(approval_id)),
            )
            override_id = str(uuid4())
            self.store._connection.execute(
                "INSERT INTO llm_review_overrides("
                "override_id, review_id, approval_id, parameter_digest, operator, reason, created_at, expires_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    override_id, row["blocking_review_id"], str(approval_id), row["parameter_digest"],
                    operator, normalized_reason[:1000], now.isoformat(), row["expires_at"],
                ),
            )
            return {
                "override_id": override_id,
                "approval_id": str(approval_id),
                "status": "review_overridden",
                "event_id": row["event_id"],
                "parameter_digest": row["parameter_digest"],
                "blocking_review_id": row["blocking_review_id"],
                "override_reason": normalized_reason[:1000],
                "operator": operator,
                "expires_at": row["expires_at"],
            }

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
