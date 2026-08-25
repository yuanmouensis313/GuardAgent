from __future__ import annotations

import json
import threading
from collections import OrderedDict
from typing import Any, Callable
from uuid import UUID, uuid4

from guardd.agents.runtime import CircuitBreaker
from guardd.audit.store import AuditStore
from guardd.llm.models import ModelRequest
from guardd.llm.prompt_registry import PromptTemplate
from guardd.llm.provider import LLMProvider, ProviderError
from guardd.security import digest_payload
from guardd.task_policy.compiler import TaskPolicyCompiler, TaskPolicyProposalValidator
from guardd.task_policy.models import TaskPolicy
from guardd.task_policy.proposal_models import TaskPolicyProposal, TrustedTaskContext


class TaskPolicyAgent:
    def __init__(
        self,
        *,
        store: AuditStore,
        provider: LLMProvider,
        model: str,
        prompt: PromptTemplate,
        validator: TaskPolicyProposalValidator,
        compiler: TaskPolicyCompiler,
        on_compiled: Callable[[TaskPolicy, str], TaskPolicy | None],
        request_timeout_ms: int = 8000,
        max_input_bytes: int = 65_536,
        max_output_tokens: int = 2000,
        max_concurrency: int = 1,
        queue_capacity: int = 128,
        circuit_breaker_failures: int = 5,
        circuit_breaker_cooldown_seconds: int = 60,
    ):
        self.store = store
        self.provider = provider
        self.model = model
        self.prompt = prompt
        self.validator = validator
        self.compiler = compiler
        self.on_compiled = on_compiled
        self.request_timeout_ms = max(500, request_timeout_ms)
        self.max_input_bytes = max(4096, max_input_bytes)
        self.max_output_tokens = max(128, max_output_tokens)
        self.max_concurrency = max(1, min(max_concurrency, 8))
        self.queue_capacity = max(1, queue_capacity)
        self.model_config_digest = digest_payload({
            "provider": provider.name,
            "model": model,
            "max_output_tokens": self.max_output_tokens,
            "schema": "TaskPolicyProposalV1",
        })
        self.breaker = CircuitBreaker(circuit_breaker_failures, circuit_breaker_cooldown_seconds)
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self._context_lock = threading.RLock()
        self._contexts: OrderedDict[str, TrustedTaskContext] = OrderedDict()

    def start(self) -> None:
        if self._workers:
            return
        for index in range(self.max_concurrency):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(f"task-policy-{uuid4()}-{index}",),
                name=f"guard-task-policy-{index}",
                daemon=True,
            )
            self._workers.append(worker)
            worker.start()

    def close(self, timeout_seconds: float = 2.0) -> None:
        self._stop.set()
        for worker in self._workers:
            worker.join(timeout=max(0.0, timeout_seconds))
        self._workers.clear()
        with self._context_lock:
            self._contexts.clear()

    def enqueue(
        self,
        context: TrustedTaskContext,
        draft: TaskPolicy,
        *,
        priority: int = 50,
    ) -> dict[str, Any] | None:
        context_payload = context.model_dump(mode="json")
        context_digest = digest_payload(context_payload)
        fingerprint = digest_payload({
            "trusted_context_digest": context_digest,
            "deterministic_draft_digest": draft.policy_digest,
            "base_policy_digest": draft.base_policy_digest,
            "prompt_template_digest": self.prompt.digest,
            "model_config_digest": self.model_config_digest,
            "output_schema_version": "1.0",
        })
        generation_id = str(uuid4())
        persisted_context = context_payload.copy()
        persisted_context["sanitized_user_prompt"] = {
            "withheld": True,
            "digest": digest_payload(context.sanitized_user_prompt),
            "length": len(context.sanitized_user_prompt),
        }
        with self._context_lock:
            self._contexts[generation_id] = context
        row = self.store.enqueue_task_policy_generation(
            generation_id=generation_id,
            session_key=draft.session_key,
            draft_policy_id=str(draft.task_policy_id),
            revision=draft.revision,
            trusted_context_digest=context_digest,
            deterministic_draft_digest=draft.policy_digest,
            fingerprint=fingerprint,
            priority=priority,
            context_document=persisted_context,
            queue_capacity=self.queue_capacity,
        )
        with self._context_lock:
            if row is None:
                self._contexts.pop(generation_id, None)
            elif row.get("status") in {"queued", "running", "failed"}:
                stored_generation_id = str(row["generation_id"])
                if stored_generation_id != generation_id:
                    self._contexts.pop(generation_id, None)
                self._contexts[stored_generation_id] = context
                self._contexts.move_to_end(stored_generation_id)
            else:
                self._contexts.pop(generation_id, None)
            while len(self._contexts) > self.queue_capacity * 2:
                self._contexts.popitem(last=False)
        return row

    def health(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "provider": self.provider.name,
            "model": self.model,
            "workers": len(self._workers),
            "prompt_template_id": self.prompt.template_id,
            "prompt_template_version": self.prompt.version,
            "prompt_template_digest": self.prompt.digest,
            "model_config_digest": self.model_config_digest,
            "circuit_breaker": self.breaker.status(),
        }

    def _worker_loop(self, worker_id: str) -> None:
        while not self._stop.is_set():
            if not self.breaker.allow():
                self._stop.wait(0.25)
                continue
            job = self.store.claim_task_policy_generation(
                worker_id,
                lease_seconds=max(30, int(self.request_timeout_ms / 1000) + 10),
            )
            if job is None:
                self._stop.wait(0.2)
                continue
            self._run_job(job)

    def _run_job(self, job: dict[str, Any]) -> None:
        generation_id = str(job["generation_id"])
        try:
            with self._context_lock:
                context = self._contexts.get(generation_id)
            if context is None:
                raise ProviderError("TASK_POLICY_CONTEXT_NOT_AVAILABLE")
            draft = self.store.get_task_policy_by_id(str(job["draft_policy_id"]))
            if draft is None or draft.policy_digest != job["deterministic_draft_digest"]:
                raise ProviderError("TASK_POLICY_DRAFT_STALE")
            serialized = json.dumps(
                context.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(serialized) > self.max_input_bytes:
                raise ProviderError("TASK_POLICY_INPUT_TOO_LARGE")
            request = ModelRequest(
                request_id=UUID(generation_id),
                idempotency_key=str(job["fingerprint"]),
                system_template=self.prompt.content,
                input_document=context.model_dump(mode="json"),
                model=self.model,
                response_schema_name="TaskPolicyProposalV1",
                response_schema_version="1.0",
                temperature=0.0,
                max_output_tokens=self.max_output_tokens,
                tools_allowed=False,
            )
            response = self.provider.generate_structured(
                request,
                TaskPolicyProposal.model_json_schema(),
                self.request_timeout_ms,
            )
            proposal = self.validator.validate(response.payload)
            compiled = self.compiler.compile(
                context=context,
                draft=draft,
                proposal=proposal,
                generation_id=generation_id,
                model=response.model,
                prompt_digest=self.prompt.digest,
            )
            accepted = self.on_compiled(compiled.policy, generation_id)
            self.store.record_task_policy_proposal(
                generation_id=generation_id,
                proposal_digest=compiled.proposal_digest,
                proposal_document=proposal.model_dump(mode="json"),
                compiled_policy_digest=(
                    accepted.policy_digest if accepted is not None else compiled.policy.policy_digest
                ),
                accepted_fields=compiled.accepted_fields,
                rejected_fields=compiled.rejected_fields,
                uncertainties=compiled.uncertainties,
                provider=response.provider,
                model=response.model,
                prompt_template_digest=self.prompt.digest,
                model_config_digest=self.model_config_digest,
                token_input=response.token_input,
                token_output=response.token_output,
                latency_ms=response.latency_ms,
                finish_reason=response.finish_reason,
            )
            with self._context_lock:
                self._contexts.pop(generation_id, None)
            self.breaker.success()
        except ProviderError as exc:
            self.breaker.failure()
            self.store.fail_task_policy_generation(
                generation_id,
                exc.code,
                retryable=exc.retryable,
                max_attempts=2,
            )
        except ValueError as exc:
            self.breaker.failure()
            code = str(exc)
            if not code.startswith("TASK_POLICY_"):
                code = "TASK_POLICY_PROPOSAL_INVALID"
            self.store.fail_task_policy_generation(
                generation_id,
                code[:128],
                retryable=False,
            )
        except Exception:
            self.breaker.failure()
            self.store.fail_task_policy_generation(
                generation_id,
                "TASK_POLICY_AGENT_INTERNAL_ERROR",
                retryable=False,
            )
