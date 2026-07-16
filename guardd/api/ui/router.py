from __future__ import annotations

import asyncio
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from guardd.api.ui.auth import UI_COOKIE_NAME, UiAuthError, UiAuthManager, UiSession
from guardd.api.ui.schemas import (
    BootstrapRequest,
    BootstrapResponse,
    ItemResponse,
    ItemsResponse,
    OperatorRequest,
    OverviewResponse,
    PageResponse,
    PolicyCandidateRequest,
    PolicyPublishRequest,
    PolicyRegressionRequest,
    PolicyRestoreRequest,
    PolicySimulationRequest,
    ReplayRequest,
    SessionRequest,
    SettingsResponse,
    StatusResponse,
    UiErrorEnvelope,
    UiSessionResponse,
)
from guardd.approvals.manager import ApprovalError
from guardd.config import Settings
from guardd.diagnostics import DiagnosticJobError, DiagnosticJobManager
from guardd.models.events import GuardEvent
from guardd.policy import PolicyValidationError
from guardd.realtime import EventBus
from guardd.service import GuardService


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _page(value: dict[str, Any]) -> dict[str, Any]:
    return {**value, "server_time": _now()}


def create_ui_router(
    settings: Settings,
    service: GuardService,
    token: str,
    auth: UiAuthManager,
    bus: EventBus,
    diagnostics: DiagnosticJobManager,
) -> APIRouter:
    router = APIRouter(
        prefix="/v1/ui", tags=["local-ui"],
        responses={
            401: {"model": UiErrorEnvelope, "description": "UI session missing or expired"},
            403: {"model": UiErrorEnvelope, "description": "Origin or CSRF validation failed"},
            409: {"model": UiErrorEnvelope, "description": "State conflict"},
            422: {"model": UiErrorEnvelope, "description": "Validation failed"},
        },
    )
    allowed_origins = {
        f"http://127.0.0.1:{settings.port}",
        f"http://localhost:{settings.port}",
        f"http://[::1]:{settings.port}",
    }

    def validate_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        fetch_site = request.headers.get("sec-fetch-site")
        if origin not in allowed_origins:
            service.store.incident("medium", "ui_origin", "UI request origin is not allowed", {"origin": origin})
            raise HTTPException(status_code=403, detail={"code": "ORIGIN_INVALID", "message": "request origin is not allowed"})
        if referer and not any(referer.startswith(f"{item}/") for item in allowed_origins):
            service.store.incident("medium", "ui_origin", "UI request referer is not allowed")
            raise HTTPException(status_code=403, detail={"code": "ORIGIN_INVALID", "message": "request referer is not allowed"})
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            service.store.incident("medium", "ui_origin", "cross-site UI request was blocked", {"sec_fetch_site": fetch_site})
            raise HTTPException(status_code=403, detail={"code": "ORIGIN_INVALID", "message": "cross-site request is not allowed"})

    def bearer(authorization: str | None = Header(default=None)) -> None:
        if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:], token):
            service.store.incident("medium", "ui_auth", "invalid bearer token used for UI bootstrap")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "UNAUTHENTICATED", "message": "invalid bearer token"})

    def session(
        guard_ui_session: str | None = Cookie(default=None, alias=UI_COOKIE_NAME),
    ) -> UiSession:
        try:
            return auth.validate(guard_ui_session)
        except UiAuthError as exc:
            service.store.incident("low", "ui_auth", "missing or expired UI session")
            raise HTTPException(status_code=401, detail={"code": "SESSION_EXPIRED", "message": str(exc)}) from exc

    def write_session(
        request: Request,
        current: UiSession = Depends(session),
        csrf: str | None = Header(default=None, alias="X-Guard-CSRF"),
    ) -> UiSession:
        validate_origin(request)
        if not csrf or not hmac.compare_digest(csrf, current.csrf_token):
            service.store.incident("medium", "ui_csrf", "invalid UI CSRF token", {"operator": current.operator})
            raise HTTPException(status_code=403, detail={"code": "CSRF_INVALID", "message": "CSRF token is invalid"})
        return current

    @router.post("/auth/bootstrap", dependencies=[Depends(bearer)], response_model=BootstrapResponse)
    def create_bootstrap(_: BootstrapRequest) -> dict[str, Any]:
        code, expires = auth.create_bootstrap()
        service.store.record_operator_action("ui.bootstrap", "local-cli", "ui_session", detail={"expires_at": expires.isoformat()})
        return {"code": code, "expires_at": expires.isoformat(), "server_time": _now()}

    @router.post("/auth/session", response_model=UiSessionResponse)
    def create_session(body: SessionRequest, response: Response, request: Request) -> dict[str, Any]:
        validate_origin(request)
        try:
            raw_session, current = auth.consume_bootstrap(body.code)
        except UiAuthError as exc:
            service.store.incident("medium", "ui_auth", "invalid or reused UI bootstrap code")
            raise HTTPException(status_code=401, detail={"code": "BOOTSTRAP_INVALID", "message": str(exc)}) from exc
        response.set_cookie(
            UI_COOKIE_NAME, raw_session, httponly=True, samesite="strict", secure=False,
            path="/", max_age=8 * 60 * 60,
        )
        service.store.record_operator_action("ui.login", current.operator, "ui_session")
        return {**current.public(), "server_time": _now()}

    @router.get("/auth/session", response_model=UiSessionResponse)
    def get_session(
        guard_ui_session: str | None = Cookie(default=None, alias=UI_COOKIE_NAME),
    ) -> dict[str, Any]:
        try:
            current = auth.validate(guard_ui_session, rotate_csrf=True)
        except UiAuthError as exc:
            raise HTTPException(status_code=401, detail={"code": "SESSION_EXPIRED", "message": str(exc)}) from exc
        return {**current.public(), "server_time": _now()}

    @router.delete("/auth/session", response_model=StatusResponse)
    def delete_session(
        response: Response,
        guard_ui_session: str | None = Cookie(default=None, alias=UI_COOKIE_NAME),
        current: UiSession = Depends(write_session),
    ) -> dict[str, Any]:
        auth.destroy(guard_ui_session)
        response.delete_cookie(UI_COOKIE_NAME, path="/")
        service.store.record_operator_action("ui.logout", current.operator, "ui_session")
        return {"status": "logged_out", "server_time": _now()}

    @router.get("/overview", response_model=OverviewResponse)
    def overview(range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"), _: UiSession = Depends(session)) -> dict[str, Any]:
        delta = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[range]
        bucket = "five_minutes" if range == "1h" else "day" if range == "30d" else "hour"
        metrics = service.store.overview_metrics((datetime.now(timezone.utc) - delta).isoformat(), bucket)
        pending = service.store.list_approvals_page(status="pending", limit=5)
        incidents = service.store.list_incidents_page(limit=5)
        high_risk = service.store.list_events_page({"risk": "high"}, limit=5)["items"]
        critical = service.store.list_events_page({"risk": "critical"}, limit=5)["items"]
        recent_high_risk = sorted(high_risk + critical, key=lambda item: item["occurred_at"], reverse=True)[:5]
        return {
            "status": service.status(), "metrics": metrics,
            "pending_approvals": pending["items"], "recent_incidents": incidents["items"],
            "recent_high_risk": recent_high_risk,
            "range": range, "server_time": _now(),
        }

    @router.get("/events", response_model=PageResponse)
    def list_events(
        cursor: str | None = None, limit: int = Query(default=50, ge=1, le=200),
        session_key: str | None = None, risk: str | None = None, decision: str | None = None,
        would_decide: str | None = None,
        agent: str | None = None, tool: str | None = None, event_type: str | None = None,
        rule_id: str | None = None, since: str | None = None, until: str | None = None,
        has_approval: bool | None = None, success: bool | None = None, q: str | None = None,
        _: UiSession = Depends(session),
    ) -> dict[str, Any]:
        try:
            page = service.store.list_events_page({
                "session": session_key, "risk": risk, "decision": decision, "would_decide": would_decide, "agent": agent,
                "tool": tool, "event_type": event_type, "rule_id": rule_id, "since": since,
                "until": until, "has_approval": has_approval, "success": success, "q": q,
            }, cursor, limit)
        except ValueError as exc:
            raise HTTPException(422, detail={"code": "CURSOR_INVALID", "message": str(exc)}) from exc
        return _page(page)

    @router.get("/events/{event_id}", response_model=ItemResponse)
    def event_detail(event_id: UUID, _: UiSession = Depends(session)) -> dict[str, Any]:
        result = service.store.get_event_detail(str(event_id))
        if result is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "event not found"})
        return {"item": result, "server_time": _now()}

    @router.get("/approvals", response_model=PageResponse)
    def list_approvals(
        approval_status: str | None = Query(default="pending", alias="status"), risk: str | None = None,
        cursor: str | None = None, limit: int = Query(default=50, ge=1, le=200),
        _: UiSession = Depends(session),
    ) -> dict[str, Any]:
        try:
            return _page(service.store.list_approvals_page(approval_status or None, risk, cursor, limit))
        except ValueError as exc:
            raise HTTPException(422, detail={"code": "CURSOR_INVALID", "message": str(exc)}) from exc

    @router.get("/approvals/{approval_id}", response_model=ItemResponse)
    def approval_detail(approval_id: UUID, _: UiSession = Depends(session)) -> dict[str, Any]:
        result = service.store.get_approval_detail(str(approval_id))
        if result is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "approval not found"})
        return {"item": result, "server_time": _now()}

    def resolve_approval(approval_id: UUID, current: UiSession, allow: bool) -> dict[str, Any]:
        try:
            result = service.resolve_approval(approval_id, allow, current.operator)
            return {"item": result, "server_time": _now()}
        except ApprovalError as exc:
            code = "APPROVAL_EXPIRED" if "expired" in str(exc) else "APPROVAL_RESOLVED"
            raise HTTPException(409, detail={"code": code, "message": str(exc)}) from exc

    @router.post("/approvals/{approval_id}/allow-once", response_model=ItemResponse)
    def allow_once(approval_id: UUID, _: OperatorRequest, current: UiSession = Depends(write_session)) -> dict[str, Any]:
        return resolve_approval(approval_id, current, True)

    @router.post("/approvals/{approval_id}/deny", response_model=ItemResponse)
    def deny(approval_id: UUID, _: OperatorRequest, current: UiSession = Depends(write_session)) -> dict[str, Any]:
        return resolve_approval(approval_id, current, False)

    @router.get("/sessions", response_model=PageResponse)
    def sessions(cursor: str | None = None, limit: int = Query(default=50, ge=1, le=200), _: UiSession = Depends(session)) -> dict[str, Any]:
        try:
            return _page(service.store.list_sessions_page(cursor, limit))
        except ValueError as exc:
            raise HTTPException(422, detail={"code": "CURSOR_INVALID", "message": str(exc)}) from exc

    @router.get("/sessions/{session_key}", response_model=ItemResponse)
    def session_detail(session_key: str, _: UiSession = Depends(session)) -> dict[str, Any]:
        result = service.store.get_session_detail(session_key)
        if result is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "session not found"})
        return {"item": result, "server_time": _now()}

    @router.get("/sessions/{session_key}/export")
    def session_export(session_key: str, _: UiSession = Depends(session)) -> JSONResponse:
        result = service.store.get_session_detail(session_key)
        if result is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "session not found"})
        return JSONResponse(
            result,
            headers={"Content-Disposition": f'attachment; filename="guard-session-{session_key[:12]}.json"', "Cache-Control": "no-store"},
        )

    @router.post("/sessions/{session_key}/replay", response_model=ItemResponse)
    def replay_session(session_key: str, body: ReplayRequest, current: UiSession = Depends(write_session)) -> dict[str, Any]:
        policy = body.policy or service.get_policy()["text"]
        result = service.regression_policy(policy, session_key)
        service.store.record_operator_action("session.replay", current.operator, "session", session_key, {"candidate": body.policy is not None})
        return {"item": result, "server_time": _now()}

    @router.get("/policy", response_model=ItemResponse)
    def policy(_: UiSession = Depends(session)) -> dict[str, Any]:
        return {"item": service.get_policy(), "server_time": _now()}

    @router.post("/policy/validate", response_model=ItemResponse)
    def validate_policy(body: PolicyCandidateRequest, _: UiSession = Depends(write_session)) -> dict[str, Any]:
        return {"item": service.validate_policy(body.policy), "server_time": _now()}

    @router.post("/policy/diff", response_model=ItemResponse)
    def diff_policy(body: PolicyCandidateRequest, _: UiSession = Depends(write_session)) -> dict[str, Any]:
        try:
            return {"item": service.policy_diff(body.policy), "server_time": _now()}
        except PolicyValidationError as exc:
            raise HTTPException(422, detail={"code": "VALIDATION_FAILED", "message": str(exc)}) from exc

    @router.post("/policy/simulate", response_model=ItemResponse)
    def simulate_policy(body: PolicySimulationRequest, _: UiSession = Depends(write_session)) -> dict[str, Any]:
        try:
            result = service.simulate_candidate(body.policy, body.event)
            return {"item": {**result.model_dump(mode="json"), "dry_run": True}, "server_time": _now()}
        except PolicyValidationError as exc:
            raise HTTPException(422, detail={"code": "VALIDATION_FAILED", "message": str(exc)}) from exc

    @router.post("/policy/regression", response_model=ItemResponse)
    def regression_policy(body: PolicyRegressionRequest, _: UiSession = Depends(write_session)) -> dict[str, Any]:
        try:
            return {"item": service.regression_policy(body.policy, body.session_key), "server_time": _now()}
        except PolicyValidationError as exc:
            raise HTTPException(422, detail={"code": "VALIDATION_FAILED", "message": str(exc)}) from exc

    @router.post("/policy/publish", response_model=ItemResponse)
    def publish_policy(body: PolicyPublishRequest, current: UiSession = Depends(write_session)) -> dict[str, Any]:
        try:
            result = service.publish_policy(body.policy, body.expected_digest, current.operator, body.comment, body.confirmation)
            return {"item": result, "server_time": _now()}
        except PolicyValidationError as exc:
            code = "DIGEST_CONFLICT" if "digest conflict" in str(exc) else "VALIDATION_FAILED"
            raise HTTPException(409 if code == "DIGEST_CONFLICT" else 422, detail={"code": code, "message": str(exc)}) from exc

    @router.get("/policy/revisions", response_model=ItemsResponse)
    def policy_revisions(_: UiSession = Depends(session)) -> dict[str, Any]:
        return {"items": service.store.list_policy_revisions(), "server_time": _now()}

    @router.post("/policy/revisions/{revision_id}/restore", response_model=ItemResponse)
    def restore_policy(revision_id: str, body: PolicyRestoreRequest, current: UiSession = Depends(write_session)) -> dict[str, Any]:
        try:
            result = service.restore_policy_revision(revision_id, body.expected_digest, current.operator, body.confirmation)
            return {"item": result, "server_time": _now()}
        except PolicyValidationError as exc:
            code = "DIGEST_CONFLICT" if "digest conflict" in str(exc) else "VALIDATION_FAILED"
            raise HTTPException(409 if code == "DIGEST_CONFLICT" else 422, detail={"code": code, "message": str(exc)}) from exc

    @router.post("/diagnostics/jobs", response_model=ItemResponse)
    def start_diagnostics(_: OperatorRequest, current: UiSession = Depends(write_session)) -> dict[str, Any]:
        try:
            job = diagnostics.start(current.operator)
            service.store.record_operator_action("diagnostic.start", current.operator, "diagnostic", job["job_id"])
            return {"item": job, "server_time": _now()}
        except DiagnosticJobError as exc:
            raise HTTPException(409, detail={"code": "JOB_ALREADY_RUNNING", "message": str(exc)}) from exc

    @router.get("/diagnostics/jobs", response_model=ItemsResponse)
    def diagnostic_jobs(_: UiSession = Depends(session)) -> dict[str, Any]:
        return {"items": service.store.list_diagnostic_jobs(), "server_time": _now()}

    @router.get("/diagnostics/jobs/{job_id}", response_model=ItemResponse)
    def diagnostic_job(job_id: str, _: UiSession = Depends(session)) -> dict[str, Any]:
        job = diagnostics.get(job_id)
        if job is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "diagnostic job not found"})
        return {"item": job, "server_time": _now()}

    @router.get("/incidents", response_model=PageResponse)
    def incidents(cursor: int | None = None, limit: int = Query(default=50, ge=1, le=200), _: UiSession = Depends(session)) -> dict[str, Any]:
        return _page(service.store.list_incidents_page(cursor, limit))

    @router.get("/settings", response_model=SettingsResponse)
    def read_settings(_: UiSession = Depends(session)) -> dict[str, Any]:
        item = {
            "host": settings.host, "port": settings.port, "workspace": str(settings.workspace),
            "policy_path": str(settings.policy_path), "state_dir": str(settings.state_dir),
            "database": str(settings.db_path), "approval_ttl_seconds": settings.approval_ttl_seconds,
            "audit_retention_days": settings.audit_retention_days, "plugin_timeout_ms": settings.plugin_timeout_ms,
            "request_limit_bytes": settings.request_limit_bytes, "ui_enabled": settings.ui_enabled,
        }
        sources = {
            "host": "GUARDD_HOST", "port": "GUARDD_PORT", "workspace": "GUARD_AGENT_WORKSPACE",
            "policy_path": "GUARD_AGENT_POLICY", "state_dir": "GUARD_AGENT_STATE_DIR",
            "database": "derived from GUARD_AGENT_STATE_DIR", "approval_ttl_seconds": "GUARDD_APPROVAL_TTL",
            "audit_retention_days": "GUARDD_RETENTION_DAYS", "plugin_timeout_ms": "GUARDD_PLUGIN_TIMEOUT_MS",
            "request_limit_bytes": "GUARDD_REQUEST_LIMIT", "ui_enabled": "GUARDD_UI_ENABLED",
        }
        return {"item": item, "sources": sources, "restart_required": True, "server_time": _now()}

    @router.get("/stream")
    async def stream(
        request: Request,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
        guard_ui_session: str | None = Cookie(default=None, alias=UI_COOKIE_NAME),
        _: UiSession = Depends(session),
    ) -> StreamingResponse:
        try:
            cursor = int(last_event_id or 0)
        except ValueError:
            cursor = 0

        async def generate():
            nonlocal cursor
            last_heartbeat = datetime.now(timezone.utc)
            yield "retry: 2000\n\n"
            while not await request.is_disconnected():
                try:
                    auth.validate(guard_ui_session, touch=False)
                except UiAuthError:
                    break
                events = bus.after(cursor)
                for item in events:
                    cursor = item.event_id
                    yield item.encode()
                now = datetime.now(timezone.utc)
                if now - last_heartbeat >= timedelta(seconds=30):
                    yield f"event: heartbeat\ndata: {json.dumps({'server_time': now.isoformat()})}\n\n"
                    last_heartbeat = now
                await asyncio.sleep(0.5)

        return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    return router
