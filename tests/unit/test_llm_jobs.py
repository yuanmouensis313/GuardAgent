from __future__ import annotations

import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from guardd.agents.safety_review import SafetyReviewAgent
from guardd.approvals import ApprovalManager
from guardd.audit import AuditStore
from guardd.llm import (
    ModelResponse,
    PromptRegistry,
    SafetyMemorySnapshot,
    SafetyReviewContextBuilder,
    SafetyReviewResult,
    SafetyReviewValidator,
)
from guardd.llm.jobs import ReviewTriggerPolicy
from guardd.models.decisions import Decision, DecisionKind
from guardd.models.events import GuardEvent
from guardd.security import digest_payload


class FakeProvider:
    name = "fake"

    def __init__(self, payload: dict | None = None):
        self.payload = payload or {
            "schema_version": "1.0",
            "verdict": "REQUIRE_APPROVAL",
            "risk": "high",
            "confidence": 0.9,
            "threats": ["scope_escape"],
            "intent_alignment": "partially_aligned",
            "evidence": [{
                "source": "local_signals",
                "path": "$.local_signals.task_verdict",
                "claim": "The task policy reports an out-of-scope action",
            }],
            "recommended_action": "REQUIRE_APPROVAL",
            "constraints": {"max_external_writes": 0},
            "summary": "Keep the approval requirement",
        }
        self.calls = 0

    def generate_structured(self, request, output_schema, timeout_ms):
        self.calls += 1
        return ModelResponse(
            request_id=request.request_id,
            provider=self.name,
            model=request.model,
            payload=self.payload,
            raw_response_digest=digest_payload(self.payload),
            token_input=20,
            token_output=10,
            latency_ms=5,
            finish_reason="stop",
        )


def review_input():
    event = GuardEvent.model_validate({
        "event_type": "tool.before",
        "source": "test",
        "agent_id": "main",
        "session_key": "session-jobs",
        "tool": {"name": "exec", "kind": "shell"},
        "derived": {
            "actions": ["remote_write"],
            "commands": [{"executable": "git", "argv": ["push"], "shell_features": []}],
            "task_policy": {"digest": f"sha256:{'b' * 64}", "verdict": "OUT_OF_SCOPE"},
        },
    })
    decision = Decision(
        event_id=event.event_id,
        decision=DecisionKind.REQUIRE_APPROVAL,
        risk="high",
        rule_ids=["TASK-POLICY-OUT-OF-SCOPE-001"],
        reason="out of scope",
        effective_mode="enforce",
        parameter_digest=digest_payload({}),
        task_policy_digest=f"sha256:{'b' * 64}",
        task_policy_verdict="OUT_OF_SCOPE",
    )
    memory = SafetyMemorySnapshot(
        session_key=event.session_key,
        snapshot_at=datetime.now(timezone.utc),
        risk_score=25,
    )
    return event, decision, SafetyReviewContextBuilder(b"x" * 32).build(
        event, decision, memory, objective_summary="Update documentation only",
    )


class ReviewJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = AuditStore(root / "guard.sqlite3", root / "emergency.jsonl")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_trigger_policy_never_reviews_deterministic_deny_for_relaxation(self) -> None:
        event, decision, _ = review_input()
        decision.decision = DecisionKind.DENY
        decision.would_decide = None
        self.assertEqual(
            ReviewTriggerPolicy(1.0).evaluate(decision, digest_payload(str(event.event_id))).value,
            "SKIP",
        )

    def test_trigger_policy_requires_scope_escape_review(self) -> None:
        event, decision, _ = review_input()
        self.assertEqual(
            ReviewTriggerPolicy(0.0).evaluate(decision, digest_payload(str(event.event_id))).value,
            "REVIEW_REQUIRED",
        )

    def test_agent_executes_persists_and_reuses_cached_review(self) -> None:
        event, _, input_document = review_input()
        provider = FakeProvider()
        agent = SafetyReviewAgent(
            store=self.store,
            provider=provider,
            model="fake-review",
            prompt=PromptRegistry().load("safety-review", "1"),
            validator=SafetyReviewValidator(),
            base_policy_digest=f"sha256:{'c' * 64}",
            max_concurrency=1,
            cache_ttl_minutes=5,
        )
        reference = agent.enqueue(input_document, subject_id=str(event.event_id), priority=100)
        self.assertIsNotNone(reference)
        agent.start()
        deadline = time.monotonic() + 3
        stored = None
        while time.monotonic() < deadline:
            stored = self.store.get_llm_review(str(reference.review_id))
            if stored and stored["status"] == "completed":
                break
            time.sleep(0.02)
        agent.close()
        self.assertIsNotNone(stored)
        self.assertEqual(stored["status"], "completed")
        self.assertEqual(stored["verdict"], "REQUIRE_APPROVAL")
        self.assertEqual(stored["threats"], ["scope_escape"])
        self.assertEqual(provider.calls, 1)
        cached = agent.enqueue(input_document, subject_id=str(event.event_id), priority=100)
        self.assertTrue(cached.cache_hit)
        self.assertEqual(cached.review_id, reference.review_id)

    def test_queue_capacity_fails_closed_for_new_jobs(self) -> None:
        event, _, input_document = review_input()
        agent = SafetyReviewAgent(
            store=self.store,
            provider=FakeProvider(),
            model="fake-review",
            prompt=PromptRegistry().load("safety-review", "1"),
            validator=SafetyReviewValidator(),
            base_policy_digest=f"sha256:{'d' * 64}",
            max_concurrency=1,
            queue_capacity=1,
        )
        first = agent.enqueue(input_document, subject_id=str(event.event_id), priority=1)
        self.assertIsNotNone(first)
        changed = input_document.model_copy(deep=True)
        changed.memory.risk_score = 36
        second = agent.enqueue(changed, subject_id="other", priority=1)
        self.assertIsNone(second)

    def test_pending_review_gates_allow_once_resolution(self) -> None:
        event, decision, _ = review_input()
        decision.review_id = __import__("uuid").uuid4()
        decision.review_status = "queued"
        approvals = ApprovalManager(self.store)
        approval_id = approvals.create(event, decision)
        with self.assertRaisesRegex(ValueError, "REVIEW_PENDING"):
            approvals.resolve(approval_id, True, "operator")
        denied = approvals.resolve(approval_id, False, "operator")
        self.assertEqual(denied["status"], "denied")


if __name__ == "__main__":
    unittest.main()
