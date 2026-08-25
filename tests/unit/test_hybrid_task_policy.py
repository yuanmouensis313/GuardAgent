from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from guardd.models.events import Origin
from guardd.task_policy.compiler import TaskPolicyCompiler, TaskPolicyProposalValidator
from guardd.task_policy.hybrid_synthesizer import TrustedTaskContextBuilder
from guardd.task_policy.proposal_models import TaskPolicyProposal
from guardd.task_policy.synthesizer import DeterministicTaskPolicySynthesizer


class HybridTaskPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name)
        self.prompt = "读取 docs/input.md 并写入 docs/output.md，不要发送消息"
        self.draft = DeterministicTaskPolicySynthesizer(
            self.workspace,
            b"h" * 32,
        ).synthesize(
            prompt=self.prompt,
            session_key="hybrid-session",
            agent_id="main",
            revision=1,
            base_policy_digest=f"sha256:{'a' * 64}",
            origin=Origin(channel="local", is_local_operator=True),
        )
        self.context = TrustedTaskContextBuilder().build(
            prompt=self.prompt,
            draft=self.draft,
            origin=Origin(channel="local", is_local_operator=True),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def proposal(self) -> TaskPolicyProposal:
        read_alias = next(item.alias for item in self.context.path_aliases if item.access == "read")
        write_alias = next(item.alias for item in self.context.path_aliases if item.access == "write")
        return TaskPolicyProposal.model_validate({
            "objective_summary": "读取输入并更新输出文档",
            "tools": {
                "required": ["read", "edit", "exec"],
                "optional": [],
                "deny": ["message_send"],
            },
            "files": {"read": [read_alias], "write": [write_alias]},
            "network": {"read": [], "write": []},
            "commands": {"allow_prefixes": ["powershell -enc"], "approval_categories": ["dynamic_eval"]},
            "limits": {
                "max_tool_calls": 12,
                "max_external_writes": 0,
                "max_files_changed": 1,
                "ttl_minutes": 30,
            },
            "uncertainties": ["是否需要执行格式化工具"],
            "evidence": [
                {"input_span": {"start": 0, "end": 8}, "supports": "$.tools.required[0]"},
                {"input_span": {"start": 0, "end": 8}, "supports": "$.tools.required[1]"},
                {"input_span": {"start": 0, "end": 8}, "supports": "$.tools.required[2]"},
                {"input_span": {"start": 0, "end": 16}, "supports": "$.files.read[0]"},
                {"input_span": {"start": 10, "end": 28}, "supports": "$.files.write[0]"},
            ],
        })

    def test_context_exposes_aliases_not_absolute_paths(self) -> None:
        serialized = self.context.model_dump_json()
        self.assertNotIn(str(self.workspace), serialized)
        self.assertIn("PATH_1", serialized)
        self.assertIn("不要发送消息", serialized)

    def test_compiler_keeps_explicit_scope_and_rejects_model_command_expansion(self) -> None:
        result = TaskPolicyCompiler().compile(
            context=self.context,
            draft=self.draft,
            proposal=self.proposal(),
            generation_id="generation-1",
            model="fake-task-model",
            prompt_digest=f"sha256:{'b' * 64}",
        )
        policy = result.policy
        self.assertEqual(policy.provenance.generator, "hybrid")
        self.assertEqual(policy.provenance.generation_id, "generation-1")
        self.assertIn("message_send", policy.tools.deny)
        self.assertNotIn("exec", policy.tools.allow)
        self.assertNotIn("powershell -enc", policy.commands.allow_prefixes)
        self.assertIn("dynamic_eval", policy.commands.approval_categories)
        self.assertEqual(policy.limits.max_tool_calls, 12)
        self.assertEqual(policy.limits.max_external_writes, 0)
        reasons = {item["reason"] for item in result.rejected_fields}
        self.assertIn("model_cannot_expand_sensitive_tool", reasons)
        self.assertIn("model_command_expansion_forbidden", reasons)

    def test_compiler_rejects_invented_alias_and_invalid_evidence(self) -> None:
        proposal = self.proposal()
        proposal.files.read = ["PATH_999"]
        proposal.evidence[-2].input_span.end = len(self.context.sanitized_user_prompt) + 100
        result = TaskPolicyCompiler().compile(
            context=self.context,
            draft=self.draft,
            proposal=proposal,
            generation_id="generation-2",
            model="fake",
            prompt_digest="sha256:test",
        )
        reasons = {item["reason"] for item in result.rejected_fields}
        self.assertIn("unknown_or_mismatched_alias", reasons)
        self.assertIn("invalid_evidence_span", reasons)

    def test_proposal_validator_rejects_secret_echo(self) -> None:
        payload = self.proposal().model_dump(mode="json")
        payload["uncertainties"] = ["api_key=sk-abcdefghijklmnopqrstuvwxyz123456"]
        with self.assertRaisesRegex(ValueError, "SECRET_ECHO"):
            TaskPolicyProposalValidator().validate(payload)


if __name__ == "__main__":
    unittest.main()
