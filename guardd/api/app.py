from __future__ import annotations

import asyncio
import hmac
import secrets
from contextlib import asynccontextmanager
from contextlib import suppress
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import FileResponse
from starlette.types import Scope
from pydantic import BaseModel

from guardd.api.ui import create_ui_router
from guardd.api.ui.auth import UiAuthManager
from guardd.approvals.manager import ApprovalError
from guardd.config import Settings
from guardd.diagnostics import DiagnosticJobManager
from guardd.inspections import (
    InspectionConfirmationRequest, InspectionError, McpDescriptorInspectionRequest, SkillInspectionRequest,
)
from guardd.models.events import DecisionRequest, GuardEvent, SessionEvent, ToolResultEvent
from guardd.realtime import EventBus
from guardd.security import ensure_token
from guardd.sanitization import SanitizationEventRequest
from guardd.service import GuardService
from guardd.task_policy import (
    TaskPolicyActivateRequest,
    TaskPolicyCaptureRequest,
    TaskPolicyCloseRequest,
    TaskPolicyContentRevisionRequest,
    TaskPolicyError,
    TaskPolicyRejectRequest,
)


class PolicyText(BaseModel):
    schema_version: str = "1.0"
    request_id: str
    policy: str


class ApprovalResolution(BaseModel):
    schema_version: str = "1.0"
    request_id: str
    operator: str = "local-operator"


class SPAStaticFiles(StaticFiles):
    def _index_response(self) -> HTMLResponse:
        nonce = secrets.token_urlsafe(24)
        text = (Path(self.directory or "") / "index.html").read_text(encoding="utf-8")
        text = text.replace("<head>", f'<head><meta name="guard-csp-nonce" content="{nonce}">', 1)
        response = HTMLResponse(text)
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' 'nonce-{nonce}'; "
            f"style-src-elem 'self' 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; worker-src 'self' blob:"
        )
        return response

    async def get_response(self, path: str, scope: Scope) -> Response:
        if path in {"", ".", "index.html"}:
            return self._index_response()
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and "." not in Path(path).name:
                return self._index_response()
            raise
        if response.status_code == 404 and "." not in Path(path).name:
            return self._index_response()
        return response


def create_app(settings: Settings | None = None, service: GuardService | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    service = service or GuardService(settings)
    token = ensure_token(settings.token_path)
    event_bus = EventBus()
    service.set_event_sink(event_bus.publish)
    ui_auth = UiAuthManager()
    diagnostics = DiagnosticJobManager(settings, service.store, event_bus.publish)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async def expire_approvals() -> None:
            while True:
                expired = service.approvals.expire()
                if expired:
                    event_bus.publish("approval.expired", {"count": expired})
                await asyncio.sleep(0.5)

        expiry_task = asyncio.create_task(expire_approvals())
        try:
            yield
        finally:
            expiry_task.cancel()
            with suppress(asyncio.CancelledError):
                await expiry_task
            diagnostics.close()
            service.close()

    app = FastAPI(
        title="GuardAgent",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.service = service
    app.state.settings = settings
    app.state.event_bus = event_bus
    app.state.ui_auth = ui_auth
    app.state.diagnostics = diagnostics

    @app.exception_handler(StarletteHTTPException)
    async def ui_http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if not request.url.path.startswith("/v1/ui"):
            return await http_exception_handler(request, exc)
        detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
        error = {
            "code": detail.get("code", "NOT_FOUND" if exc.status_code == 404 else "REQUEST_FAILED"),
            "message": detail.get("message", str(exc.detail)),
            "request_id": request.headers.get("x-request-id"),
            "details": detail.get("details", {}),
        }
        return JSONResponse({"error": error}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(Exception)
    async def ui_internal_error(request: Request, exc: Exception) -> Response:
        if not request.url.path.startswith("/v1/ui"):
            return JSONResponse({"detail": "Internal Server Error"}, status_code=500)
        try:
            service.store.incident("high", "ui_internal", "Unhandled UI API error", {"type": type(exc).__name__})
        except Exception:
            pass
        return JSONResponse(
            {"error": {"code": "INTERNAL_ERROR", "message": "internal server error", "request_id": request.headers.get("x-request-id"), "details": {}}},
            status_code=500,
        )

    @app.exception_handler(RequestValidationError)
    async def ui_validation_error(request: Request, exc: RequestValidationError) -> Response:
        if not request.url.path.startswith("/v1/ui"):
            return await request_validation_exception_handler(request, exc)
        return JSONResponse(
            {"error": {"code": "VALIDATION_FAILED", "message": "request validation failed", "request_id": request.headers.get("x-request-id"), "details": {"errors": exc.errors()}}},
            status_code=422,
        )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: Any) -> Response:
        content_length = request.headers.get("content-length")
        try:
            if content_length and int(content_length) > settings.request_limit_bytes:
                return JSONResponse({"detail": "request too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
        if request.method in {"POST", "PUT", "PATCH"} and request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            return JSONResponse({"detail": "Content-Type must be application/json"}, status_code=415)
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > settings.request_limit_bytes:
                return JSONResponse({"detail": "request too large"}, status_code=413)
        try:
            response = await call_next(request)
        except Exception as exc:
            if not request.url.path.startswith("/v1/ui"):
                raise
            try:
                service.store.incident("high", "ui_internal", "Unhandled UI API error", {"type": type(exc).__name__})
            except Exception:
                pass
            response = JSONResponse(
                {"error": {"code": "INTERNAL_ERROR", "message": "internal server error", "request_id": request.headers.get("x-request-id"), "details": {}}},
                status_code=500,
            )
        if request.url.path.startswith("/ui"):
            if "Content-Security-Policy" not in response.headers:
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                    "worker-src 'self' blob:"
                )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
            if request.url.path.startswith("/ui/assets/"):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            elif request.url.path.endswith("index.html") or "." not in Path(request.url.path).name:
                response.headers["Cache-Control"] = "no-cache"
        if request.url.path.startswith("/v1/ui"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def authenticate(authorization: str | None = Header(default=None)) -> None:
        if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:], token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")

    @app.get("/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "schema_version": "1.0"}

    @app.get("/v1/status", dependencies=[Depends(authenticate)])
    def get_status() -> dict[str, Any]:
        return service.status()

    @app.get("/v1/capabilities", dependencies=[Depends(authenticate)])
    def get_capabilities() -> Any:
        return service.capabilities()

    @app.post("/v1/decisions/tool", dependencies=[Depends(authenticate)])
    def tool_decision(request: DecisionRequest) -> Any:
        request.event.derived["request_id"] = request.request_id
        return service.decide(request.event)

    @app.post("/v1/decisions/message", dependencies=[Depends(authenticate)])
    def message_decision(request: DecisionRequest) -> Any:
        request.event.derived["request_id"] = request.request_id
        return service.decide(request.event)

    @app.post("/v1/events/tool-result", status_code=202, dependencies=[Depends(authenticate)])
    def tool_result(result: ToolResultEvent) -> dict[str, bool]:
        service.tool_result(result)
        return {"accepted": True}

    @app.post("/v1/events/sanitization", status_code=202, dependencies=[Depends(authenticate)])
    def sanitization_event(event: SanitizationEventRequest) -> Any:
        return service.sanitization_event(event)

    @app.get("/v1/sanitization/events", dependencies=[Depends(authenticate)])
    def sanitization_events(session_key: str | None = None, limit: int = 100) -> Any:
        return service.store.list_sanitization_events(session_key, min(max(limit, 1), 500))

    @app.get("/v1/sanitization/metrics", dependencies=[Depends(authenticate)])
    def sanitization_metrics() -> Any:
        return service.store.sanitization_metrics()

    @app.post("/v1/inspections/skill", dependencies=[Depends(authenticate)])
    def inspect_skill(body: SkillInspectionRequest) -> Any:
        try:
            return service.inspect_skill(body)
        except InspectionError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/inspections/mcp-descriptors", dependencies=[Depends(authenticate)])
    def inspect_mcp_descriptors(body: McpDescriptorInspectionRequest) -> Any:
        try:
            return service.inspect_mcp(body)
        except InspectionError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/inspections/mcp-server", dependencies=[Depends(authenticate)])
    def inspect_mcp_server(body: McpDescriptorInspectionRequest) -> Any:
        try:
            return service.inspect_mcp(body)
        except InspectionError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/v1/inspections", dependencies=[Depends(authenticate)])
    def list_inspections(kind: str | None = None, limit: int = 100) -> Any:
        return service.store.list_inspections(kind, min(max(limit, 1), 500))

    @app.get("/v1/inspections/{content_digest}", dependencies=[Depends(authenticate)])
    def get_inspection(content_digest: str) -> Any:
        try:
            return service.inspections.get(content_digest)
        except InspectionError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/v1/inspections/{content_digest}/confirm", dependencies=[Depends(authenticate)])
    def confirm_inspection(content_digest: str, body: InspectionConfirmationRequest) -> Any:
        try:
            return service.confirm_inspection(content_digest, body)
        except InspectionError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/inspections/{content_digest}/invalidate", dependencies=[Depends(authenticate)])
    def invalidate_inspection(content_digest: str, body: ApprovalResolution) -> Any:
        try:
            result = service.inspections.invalidate(content_digest)
            service.store.record_operator_action("inspection.invalidate", body.operator, "content_artifact", content_digest)
            return result
        except InspectionError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/events/session", status_code=202, dependencies=[Depends(authenticate)])
    def session_event(request: SessionEvent) -> dict[str, bool]:
        request.event.derived["request_id"] = request.request_id
        service.session_event(request.event)
        return {"accepted": True}

    @app.get("/v1/events", dependencies=[Depends(authenticate)])
    def events(session: str | None = None, risk: str | None = None, limit: int = 100) -> Any:
        return service.store.list_events(session, risk, limit)

    @app.get("/v1/approvals", dependencies=[Depends(authenticate)])
    def approvals(pending_only: bool = True) -> Any:
        return service.approvals.list(pending_only)

    @app.get("/v1/approvals/{approval_id}", dependencies=[Depends(authenticate)])
    def approval(approval_id: UUID) -> Any:
        rows = [item for item in service.approvals.list(False) if item["approval_id"] == str(approval_id)]
        if not rows:
            raise HTTPException(404, "approval not found")
        return rows[0]

    def resolve(approval_id: UUID, body: ApprovalResolution, allow: bool) -> Any:
        try:
            return service.resolve_approval(approval_id, allow, body.operator)
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/approvals/{approval_id}/allow-once", dependencies=[Depends(authenticate)])
    def allow_once(approval_id: UUID, body: ApprovalResolution) -> Any:
        return resolve(approval_id, body, True)

    @app.post("/v1/approvals/{approval_id}/deny", dependencies=[Depends(authenticate)])
    def deny(approval_id: UUID, body: ApprovalResolution) -> Any:
        return resolve(approval_id, body, False)

    @app.post("/v1/policy/validate", dependencies=[Depends(authenticate)])
    def validate_policy(body: PolicyText) -> Any:
        return service.validate_policy(body.policy)

    @app.post("/v1/policy/simulate", dependencies=[Depends(authenticate)])
    def simulate_policy(body: DecisionRequest) -> Any:
        return service.simulate(body.event)

    @app.post("/v1/policy/reload", dependencies=[Depends(authenticate)])
    def reload_policy(body: ApprovalResolution) -> Any:
        return service.reload_policy(body.operator)

    @app.post("/v1/task-policies/capture", dependencies=[Depends(authenticate)])
    def capture_task_policy(body: TaskPolicyCaptureRequest) -> Any:
        try:
            return service.capture_task_policy(
                body.prompt, body.session_key, body.agent_id, body.parent_session_key,
                body.origin,
            )
        except TaskPolicyError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/v1/task-policies/{session_key}", dependencies=[Depends(authenticate)])
    def get_task_policy(session_key: str, policy_status: str | None = None) -> Any:
        try:
            return service.get_task_policy(session_key, policy_status)
        except (TaskPolicyError, ValueError) as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/v1/task-policies/{session_key}/activate", dependencies=[Depends(authenticate)])
    def activate_task_policy(session_key: str, body: TaskPolicyActivateRequest) -> Any:
        try:
            return service.activate_task_policy(
                session_key, body.candidate_digest, body.expected_active_revision, body.operator,
            )
        except TaskPolicyError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/task-policies/{session_key}/reject", dependencies=[Depends(authenticate)])
    def reject_task_policy(session_key: str, body: TaskPolicyRejectRequest) -> Any:
        try:
            return service.reject_task_policy(session_key, body.candidate_digest, body.operator)
        except TaskPolicyError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/task-policies/{session_key}/revise-content", dependencies=[Depends(authenticate)])
    def revise_task_policy_content(session_key: str, body: TaskPolicyContentRevisionRequest) -> Any:
        try:
            return service.revise_task_policy_content(
                session_key, body.kind, body.name, body.content_digest,
                body.expected_active_revision, body.operator, body.artifact_digest,
            )
        except (TaskPolicyError, InspectionError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/task-policies/{session_key}/close", dependencies=[Depends(authenticate)])
    def close_task_policy(session_key: str, body: TaskPolicyCloseRequest) -> Any:
        try:
            return service.close_task_policy(session_key, body.operator)
        except TaskPolicyError as exc:
            raise HTTPException(409, str(exc)) from exc

    if settings.ui_enabled:
        app.include_router(create_ui_router(settings, service, token, ui_auth, event_bus, diagnostics))

    ui_static = Path(__file__).parents[1] / "ui" / "static"
    if settings.ui_enabled and (ui_static / "index.html").is_file():
        app.mount("/ui", SPAStaticFiles(directory=ui_static, html=True), name="guard-ui")
    else:
        @app.get("/ui/{path:path}", include_in_schema=False)
        def ui_unavailable(path: str = "") -> JSONResponse:
            return JSONResponse(
                {"detail": "GuardAgent UI is disabled or its assets are not installed; machine API remains available"},
                status_code=503,
            )

    return app
