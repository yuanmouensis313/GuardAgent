from __future__ import annotations

import json
import time
import copy
from typing import Any, Protocol

import httpx

from guardd.llm.models import ModelRequest, ModelResponse
from guardd.security import digest_payload


class ProviderError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class LLMProvider(Protocol):
    name: str

    def generate_structured(
        self,
        request: ModelRequest,
        output_schema: dict[str, Any],
        timeout_ms: int,
    ) -> ModelResponse: ...


class DisabledProvider:
    name = "disabled"

    def generate_structured(
        self,
        request: ModelRequest,
        output_schema: dict[str, Any],
        timeout_ms: int,
    ) -> ModelResponse:
        raise ProviderError("LLM_PROVIDER_DISABLED")


class CompatibleHttpProvider:
    """Minimal OpenAI-compatible structured-output adapter.

    Business code depends only on LLMProvider. The adapter never logs bodies or
    credentials and rejects tool calls and oversized/non-JSON responses.
    """

    name = "compatible_http"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        endpoint: str = "/chat/completions",
        connect_timeout_ms: int = 1000,
        max_output_bytes: int = 16_384,
        client: httpx.Client | None = None,
    ):
        if not base_url:
            raise ValueError("LLM base_url is required")
        self.base_url = base_url.rstrip("/")
        self.endpoint = "/" + endpoint.lstrip("/")
        self.api_key = api_key
        self.connect_timeout_ms = max(100, connect_timeout_ms)
        self.max_output_bytes = max(1024, max_output_bytes)
        self._client = client

    def generate_structured(
        self,
        request: ModelRequest,
        output_schema: dict[str, Any],
        timeout_ms: int,
    ) -> ModelResponse:
        if request.tools_allowed:
            raise ProviderError("LLM_TOOLS_NOT_ALLOWED")
        body = {
            "model": request.model,
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            "messages": [
                {"role": "system", "content": request.system_template},
                {
                    "role": "user",
                    "content": json.dumps(request.input_document, ensure_ascii=False, separators=(",", ":")),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": request.response_schema_name,
                    "strict": True,
                    "schema": _strict_output_schema(output_schema),
                },
            },
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Idempotency-Key": request.idempotency_key,
        }
        timeout = httpx.Timeout(
            max(0.1, timeout_ms / 1000),
            connect=max(0.1, self.connect_timeout_ms / 1000),
        )
        started = time.perf_counter()
        client = self._client or httpx.Client(timeout=timeout)
        owns_client = self._client is None
        try:
            response = client.post(f"{self.base_url}{self.endpoint}", headers=headers, json=body, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise ProviderError("LLM_PROVIDER_TIMEOUT", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise ProviderError("LLM_PROVIDER_NETWORK", retryable=True) from exc
        finally:
            if owns_client:
                client.close()
        latency_ms = int((time.perf_counter() - started) * 1000)
        if response.status_code == 429:
            raise ProviderError("LLM_PROVIDER_RATE_LIMIT", retryable=True)
        if response.status_code >= 500:
            raise ProviderError("LLM_PROVIDER_SERVER_ERROR", retryable=True)
        if response.status_code >= 400:
            raise ProviderError("LLM_PROVIDER_REQUEST_REJECTED")
        if len(response.content) > self.max_output_bytes:
            raise ProviderError("LLM_PROVIDER_RESPONSE_TOO_LARGE")
        try:
            document = response.json()
        except ValueError as exc:
            raise ProviderError("LLM_PROVIDER_INVALID_JSON") from exc
        try:
            message = document["choices"][0]["message"]
            if message.get("tool_calls"):
                raise ProviderError("LLM_PROVIDER_RETURNED_TOOL_CALL")
            content = message["content"]
            payload = content if isinstance(content, dict) else json.loads(content)
            if not isinstance(payload, dict):
                raise TypeError("structured payload must be an object")
        except ProviderError:
            raise
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderError("LLM_PROVIDER_INVALID_RESPONSE") from exc
        usage = document.get("usage") if isinstance(document.get("usage"), dict) else {}
        return ModelResponse(
            request_id=request.request_id,
            provider=self.name,
            model=str(document.get("model") or request.model),
            payload=payload,
            raw_response_digest=digest_payload(document),
            token_input=_optional_nonnegative_int(usage.get("prompt_tokens")),
            token_output=_optional_nonnegative_int(usage.get("completion_tokens")),
            latency_ms=latency_ms,
            finish_reason=str(document["choices"][0].get("finish_reason") or "")[:128] or None,
        )


def _optional_nonnegative_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _strict_output_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Normalize Pydantic JSON Schema for strict structured-output providers."""
    normalized = copy.deepcopy(schema)

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            node.pop("default", None)
            properties = node.get("properties")
            if isinstance(properties, dict):
                node["additionalProperties"] = False
                node["required"] = list(properties)
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(normalized)
    return normalized
