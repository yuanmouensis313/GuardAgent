from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from guardd.approvals.manager import ApprovalError
from guardd.config import Settings
from guardd.models.events import DecisionRequest, GuardEvent, SessionEvent, ToolResultEvent
from guardd.security import ensure_token
from guardd.service import GuardService


class PolicyText(BaseModel):
    schema_version: str = "1.0"
    request_id: str
    policy: str


class ApprovalResolution(BaseModel):
    schema_version: str = "1.0"
    request_id: str
    operator: str = "local-operator"


def create_app(settings: Settings | None = None, service: GuardService | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    service = service or GuardService(settings)
    token = ensure_token(settings.token_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
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
        return await call_next(request)

    def authenticate(authorization: str | None = Header(default=None)) -> None:
        if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:], token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")

    @app.get("/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "schema_version": "1.0"}

    @app.get("/v1/status", dependencies=[Depends(authenticate)])
    def get_status() -> dict[str, Any]:
        return service.status()

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

    return app
