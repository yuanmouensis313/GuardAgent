from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from guardd.agents.runtime import CircuitBreaker
from guardd.audit.store import AuditStore
from guardd.llm.models import (
    ModelRequest,
    ReviewJobStatus,
    ReviewReference,
    SafetyReviewInput,
    SafetyReviewResult,
)
from guardd.llm.prompt_registry import PromptTemplate
from guardd.llm.provider import LLMProvider, ProviderError
from guardd.llm.validator import SafetyReviewValidator
from guardd.security import digest_payload


class SafetyReviewAgent:
    def __init__(
        self,
        *,
        store: AuditStore,
        provider: LLMProvider,
        model: str,
        prompt: PromptTemplate,
        validator: SafetyReviewValidator,
        base_policy_digest: str,
        request_timeout_ms: int = 8000,
        max_input_bytes: int = 65_536,
        max_output_tokens: int = 1500,
        max_concurrency: int = 2,
        queue_capacity: int = 256,
        cache_ttl_minutes: int = 60,
        circuit_breaker_failures: int = 5,
        circuit_breaker_cooldown_seconds: int = 60,
        review_mode: str = "shadow",
        deny_confidence_threshold: float = 0.92,
        enforceable_threats: set[str] | None = None,
    ):
        self.store = store
        self.provider = provider
        self.model = model
        self.prompt = prompt
        self.validator = validator
        self.base_policy_digest = base_policy_digest
        self.request_timeout_ms = max(500, request_timeout_ms)
        self.max_input_bytes = max(4096, max_input_bytes)
        self.max_output_tokens = max(128, max_output_tokens)
        self.max_concurrency = max(1, min(max_concurrency, 32))
        self.queue_capacity = max(1, queue_capacity)
        self.cache_ttl_minutes = max(1, cache_ttl_minutes)
        self.review_mode = review_mode
        self.deny_confidence_threshold = min(1.0, max(0.0, deny_confidence_threshold))
        self.enforceable_threats = enforceable_threats or {
            "prompt_injection", "secret_exfiltration", "security_bypass", "destructive_action",
        }
        self.breaker = CircuitBreaker(circuit_breaker_failures, circuit_breaker_cooldown_seconds)
        self.model_config_digest = digest_payload({
            "provider": provider.name,
            "model": model,
            "max_output_tokens": self.max_output_tokens,
            "schema": "SafetyReviewResultV1",
        })
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []

    def update_base_policy_digest(self, digest: str) -> None:
        self.base_policy_digest = digest

    def start(self) -> None:
        if self._workers:
            return
        for index in range(self.max_concurrency):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"guard-llm-review-{index}",
                args=(f"worker-{uuid4()}-{index}",),
                daemon=True,
            )
            self._workers.append(worker)
            worker.start()

    def close(self, timeout_seconds: float = 2.0) -> None:
        self._stop.set()
        for worker in self._workers:
            worker.join(timeout=max(0.0, timeout_seconds))
        self._workers.clear()

    def fingerprint(self, input_document: SafetyReviewInput) -> str:
        memory = input_document.memory
        return digest_payload({
            "subject": input_document.subject.value,
            "objective": input_document.objective.model_dump(mode="json"),
            "event": input_document.event.model_dump(mode="json"),
            "local_signals": input_document.local_signals.model_dump(mode="json"),
            "trust_labels": input_document.trust_labels,
            "memory_binding": {
                "active_task_policy_digest": memory.active_task_policy_digest,
                "sensitive_access": [
                    {
                        "classification": item.classification,
                        "target_digest": item.target_digest,
                    }
                    for item in memory.sensitive_access
                ],
                "denied_patterns": memory.denied_patterns,
                "risk_bucket": memory.risk_score // 10,
            },
            "base_policy_digest": self.base_policy_digest,
            "task_policy_digest": input_document.objective.task_policy_digest,
            "prompt_template_digest": self.prompt.digest,
            "model_config_digest": self.model_config_digest,
            "output_schema_version": "1.0",
        })

    def enqueue(
        self,
        input_document: SafetyReviewInput,
        *,
        subject_id: str,
        priority: int,
    ) -> ReviewReference | None:
        fingerprint = self.fingerprint(input_document)
        cached = self.store.get_llm_review_by_fingerprint(fingerprint)
        if cached is not None:
            return ReviewReference(
                review_id=UUID(cached["review_id"]),
                fingerprint=fingerprint,
                status=ReviewJobStatus.COMPLETED,
                cache_hit=True,
            )
        review_id = uuid4()
        input_payload = input_document.model_dump(mode="json")
        input_digest = digest_payload(input_payload)
        row = self.store.enqueue_llm_review(
            review_id=str(review_id),
            subject_type=input_document.subject.value,
            subject_id=subject_id,
            session_key=input_document.memory.session_key,
            fingerprint=fingerprint,
            priority=priority,
            input_digest=input_digest,
            input_document=input_payload,
            base_policy_digest=self.base_policy_digest,
            task_policy_digest=input_document.objective.task_policy_digest,
            prompt_template_digest=self.prompt.digest,
            model_config_digest=self.model_config_digest,
            queue_capacity=self.queue_capacity,
        )
        if row is None:
            return None
        return ReviewReference(
            review_id=UUID(row["review_id"]),
            fingerprint=fingerprint,
            status=ReviewJobStatus(row["status"]),
            cache_hit=row["status"] == ReviewJobStatus.COMPLETED.value,
        )

    def get_cached(self, input_document: SafetyReviewInput) -> dict[str, Any] | None:
        return self.store.get_llm_review_by_fingerprint(self.fingerprint(input_document))

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
            job = self.store.claim_llm_review(
                worker_id,
                lease_seconds=max(30, int(self.request_timeout_ms / 1000) + 10),
            )
            if job is None:
                self._stop.wait(0.2)
                continue
            self._run_job(job)

    def _run_job(self, job: dict[str, Any]) -> None:
        review_id = str(job["review_id"])
        try:
            input_document = SafetyReviewInput.model_validate(job["input_document"])
            serialized = json.dumps(
                input_document.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(serialized) > self.max_input_bytes:
                raise ProviderError("LLM_INPUT_TOO_LARGE")
            request = ModelRequest(
                request_id=UUID(review_id),
                idempotency_key=str(job["fingerprint"]),
                system_template=self.prompt.content,
                input_document=input_document.model_dump(mode="json"),
                model=self.model,
                response_schema_name="SafetyReviewResultV1",
                response_schema_version="1.0",
                temperature=0.0,
                max_output_tokens=self.max_output_tokens,
                tools_allowed=False,
            )
            response = self.provider.generate_structured(
                request,
                SafetyReviewResult.model_json_schema(),
                self.request_timeout_ms,
            )
            validation = self.validator.validate(response.payload, input_document)
            result = validation.result
            result_payload = result.model_dump(mode="json")
            self.store.record_llm_review(
                review_id=review_id,
                fingerprint=str(job["fingerprint"]),
                input_digest=str(job["input_digest"]),
                result_digest=digest_payload(result_payload),
                schema_version=result.schema_version,
                verdict=result.verdict.value,
                risk=result.risk,
                confidence=result.confidence,
                threats=[item.value for item in result.threats],
                intent_alignment=result.intent_alignment.value,
                recommended_action=result.recommended_action.value,
                evidence=[item.model_dump(mode="json") for item in result.evidence],
                constraints=result.constraints.model_dump(mode="json"),
                sanitized_summary=result.summary,
                provider=response.provider,
                model=response.model,
                model_config_digest=str(job.get("model_config_digest") or self.model_config_digest),
                prompt_template_id=self.prompt.template_id,
                prompt_template_digest=str(job.get("prompt_template_digest") or self.prompt.digest),
                base_policy_digest=str(job.get("base_policy_digest") or self.base_policy_digest),
                task_policy_digest=job.get("task_policy_digest"),
                token_input=response.token_input,
                token_output=response.token_output,
                latency_ms=response.latency_ms,
                finish_reason=response.finish_reason,
                validation_issues=validation.issues,
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(minutes=self.cache_ttl_minutes)
                ).isoformat(),
                block_approval=(
                    self.review_mode == "enforce_tighten"
                    and result.verdict.value == "DENY"
                    and result.confidence >= self.deny_confidence_threshold
                    and bool(result.evidence)
                    and bool({item.value for item in result.threats} & self.enforceable_threats)
                ),
            )
            self.breaker.success()
        except ProviderError as exc:
            self.breaker.failure()
            self.store.fail_llm_review(
                review_id,
                exc.code,
                retryable=exc.retryable,
                max_attempts=2,
            )
        except Exception:
            self.breaker.failure()
            self.store.fail_llm_review(
                review_id,
                "LLM_REVIEW_INTERNAL_ERROR",
                retryable=False,
            )
