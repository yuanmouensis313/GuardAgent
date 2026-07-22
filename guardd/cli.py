from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
import typer

from guardd.config import Settings
from guardd.doctor import run_doctor
from guardd.models.events import GuardEvent
from guardd.policy import PolicyEngine, PolicyLoader, PolicyValidationError
from guardd.security import ensure_token, sanitize
from guardd.task_policy import TaskPolicy


app = typer.Typer(help="GuardAgent management CLI", no_args_is_help=True)
events_app = typer.Typer(help="Audit events")
approvals_app = typer.Typer(help="Single-use approvals")
policy_app = typer.Typer(help="Policy validation and simulation")
task_policy_app = typer.Typer(help="Session task policy inspection and confirmation")
sanitization_app = typer.Typer(help="Data-path sanitization inspection and tests")
inspections_app = typer.Typer(help="Skill and MCP content inspection management")
app.add_typer(events_app, name="events")
app.add_typer(approvals_app, name="approvals")
app.add_typer(policy_app, name="policy")
app.add_typer(task_policy_app, name="task-policy")
app.add_typer(sanitization_app, name="sanitization")
app.add_typer(inspections_app, name="inspections")


def _settings() -> Settings:
    return Settings.from_env()


def _client() -> httpx.Client:
    settings = _settings()
    token = ensure_token(settings.token_path)
    return httpx.Client(base_url=f"http://{settings.host}:{settings.port}", headers={"Authorization": f"Bearer {token}"}, timeout=5)


def _print(value: Any) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _task_policy_get(client: httpx.Client, session: str, status: str | None = None) -> dict[str, Any] | None:
    response = client.get(
        f"/v1/task-policies/{quote(session, safe='')}",
        params={"policy_status": status} if status else None,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


@app.command("status")
def status_command() -> None:
    with _client() as client:
        response = client.get("/v1/status")
        response.raise_for_status()
        _print(response.json())


@app.command("ui")
def ui_command(no_open: bool = typer.Option(False, "--no-open", help="Print the secure local UI URL without opening a browser")) -> None:
    """Create a short-lived local UI session and open the GuardAgent console."""
    settings = _settings()
    with _client() as client:
        health = client.get("/v1/health")
        health.raise_for_status()
        response = client.post(
            "/v1/ui/auth/bootstrap",
            json={"schema_version": "1.0", "request_id": f"guardctl-ui-{uuid4()}"},
        )
        response.raise_for_status()
        code = response.json()["code"]
    url = f"http://{settings.host}:{settings.port}/ui/#/bootstrap?code={quote(code, safe='')}"
    if no_open:
        typer.echo(url)
        return
    if not webbrowser.open(url, new=2):
        typer.echo(url)
        raise typer.Exit(1)
    typer.echo(f"GuardAgent UI opened at http://{settings.host}:{settings.port}/ui/")


@events_app.command("list")
def list_events(session: str | None = typer.Option(None), risk: str | None = typer.Option(None), limit: int = typer.Option(100)) -> None:
    with _client() as client:
        response = client.get("/v1/events", params={"session": session, "risk": risk, "limit": limit})
        response.raise_for_status()
        _print(response.json())


@approvals_app.command("list")
def list_approvals(all_records: bool = typer.Option(False, "--all")) -> None:
    with _client() as client:
        response = client.get("/v1/approvals", params={"pending_only": not all_records})
        response.raise_for_status()
        _print(response.json())


def _resolve(approval_id: UUID, action: str) -> None:
    with _client() as client:
        response = client.post(f"/v1/approvals/{approval_id}/{action}", json={"schema_version": "1.0", "request_id": f"guardctl-{approval_id}", "operator": "local-terminal"})
        response.raise_for_status()
        _print(response.json())


@approvals_app.command("allow-once")
def allow_once(approval_id: UUID) -> None:
    _resolve(approval_id, "allow-once")


@approvals_app.command("deny")
def deny(approval_id: UUID) -> None:
    _resolve(approval_id, "deny")


@policy_app.command("validate")
def validate(path: Path | None = typer.Argument(None)) -> None:
    settings = _settings()
    source = path or settings.policy_path
    try:
        policy = PolicyLoader().load(source)
    except (OSError, PolicyValidationError) as exc:
        _print({"valid": False, "errors": [str(exc)]})
        raise typer.Exit(1)
    _print({"valid": True, "digest": policy.digest, "mode": policy.mode, "rules": len(policy.document.get("rules", []))})


def _load_event(path: Path) -> GuardEvent:
    document = json.loads(path.read_text(encoding="utf-8"))
    return GuardEvent.model_validate(document.get("event", document))


@policy_app.command("simulate")
def simulate(path: Path) -> None:
    settings = _settings()
    policy = PolicyLoader().load(settings.policy_path)
    decision = PolicyEngine(policy, settings.workspace).decide(_load_event(path))
    _print(decision.model_dump(mode="json"))


@policy_app.command("test")
def test_fixture(path: Path) -> None:
    settings = _settings()
    document = json.loads(path.read_text(encoding="utf-8"))
    decision = PolicyEngine(PolicyLoader().load(settings.policy_path), settings.workspace).decide(GuardEvent.model_validate(document["event"]))
    expected = document["expected"]
    failures = []
    proposed = decision.would_decide or decision.decision
    if proposed.value != expected["decision"]:
        failures.append(f"decision: {proposed.value} != {expected['decision']}")
    if decision.risk != expected["risk"]:
        failures.append(f"risk: {decision.risk} != {expected['risk']}")
    if not set(expected.get("rule_ids", [])) <= set(decision.rule_ids):
        failures.append("missing expected rules")
    _print({"passed": not failures, "failures": failures, "actual": decision.model_dump(mode="json")})
    if failures:
        raise typer.Exit(1)


@task_policy_app.command("show")
def show_task_policy(session: str = typer.Option(..., "--session")) -> None:
    with _client() as client:
        policy = _task_policy_get(client, session)
    if policy is None:
        _print({"session_key": session, "task_policy": None})
        raise typer.Exit(1)
    _print(policy)


@task_policy_app.command("candidate")
def show_task_policy_candidate(session: str = typer.Option(..., "--session")) -> None:
    with _client() as client:
        policy = _task_policy_get(client, session, "candidate")
    if policy is None:
        _print({"session_key": session, "candidate": None})
        raise typer.Exit(1)
    _print(policy)


@task_policy_app.command("approve")
def approve_task_policy(
    session: str = typer.Option(..., "--session"),
    digest: str = typer.Option(..., "--digest"),
) -> None:
    with _client() as client:
        active = _task_policy_get(client, session, "active")
        response = client.post(
            f"/v1/task-policies/{quote(session, safe='')}/activate",
            json={
                "schema_version": "1.0", "request_id": f"guardctl-task-{uuid4()}",
                "candidate_digest": digest,
                "expected_active_revision": active.get("revision") if active else None,
                "operator": "local-terminal",
            },
        )
        response.raise_for_status()
        _print(response.json())


@task_policy_app.command("reject")
def reject_task_policy(
    session: str = typer.Option(..., "--session"),
    digest: str = typer.Option(..., "--digest"),
) -> None:
    with _client() as client:
        response = client.post(
            f"/v1/task-policies/{quote(session, safe='')}/reject",
            json={
                "schema_version": "1.0", "request_id": f"guardctl-task-{uuid4()}",
                "candidate_digest": digest, "operator": "local-terminal",
            },
        )
        response.raise_for_status()
        _print(response.json())


@task_policy_app.command("simulate")
def simulate_task_policy(path: Path) -> None:
    """Validate and summarize a task-policy JSON document without activating it."""
    try:
        policy = TaskPolicy.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _print({"valid": False, "errors": [str(exc)]})
        raise typer.Exit(1)
    _print({
        "valid": True, "session_key": policy.session_key, "revision": policy.revision,
        "status": policy.status.value, "digest": policy.policy_digest,
        "summary": policy.objective.summary,
        "permissions": {
            "tools": policy.tools.allow, "read_paths": policy.files.read,
            "write_paths": policy.files.write, "network_read": policy.network.read,
            "network_write": policy.network.write,
        },
    })


@task_policy_app.command("allow-content")
def allow_task_content(
    session: str = typer.Option(..., "--session"),
    kind: str = typer.Option(..., "--kind"),
    name: str = typer.Option(..., "--name"),
    digest: str = typer.Option(..., "--digest"),
    artifact_digest: str | None = typer.Option(None, "--artifact-digest"),
) -> None:
    if kind not in {"skill", "mcp"}:
        raise typer.BadParameter("kind must be skill or mcp")
    with _client() as client:
        active = _task_policy_get(client, session, "active")
        if active is None:
            _print({"error": "no active task policy", "session_key": session})
            raise typer.Exit(1)
        response = client.post(
            f"/v1/task-policies/{quote(session, safe='')}/revise-content",
            json={
                "schema_version": "1.0", "request_id": f"guardctl-task-{uuid4()}",
                "kind": kind, "name": name, "content_digest": digest,
                "artifact_digest": artifact_digest, "expected_active_revision": active["revision"],
                "operator": "local-terminal",
            },
        )
        response.raise_for_status()
        _print(response.json())


@sanitization_app.command("events")
def sanitization_events(
    session: str | None = typer.Option(None, "--session"),
    limit: int = typer.Option(100, "--limit", min=1, max=500),
) -> None:
    with _client() as client:
        response = client.get(
            "/v1/sanitization/events",
            params={"session_key": session, "limit": limit},
        )
        response.raise_for_status()
        _print(response.json())


@sanitization_app.command("test")
def test_sanitization_fixture(path: Path) -> None:
    """Run the Python audit sanitizer against a local JSON fixture."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _print({"valid": False, "errors": [str(exc)]})
        raise typer.Exit(1)
    clean, classifications = sanitize(payload)
    _print({"valid": True, "classifications": classifications, "sanitized": clean})


@inspections_app.command("list")
def list_inspections(
    kind: str | None = typer.Option(None, "--kind"),
    limit: int = typer.Option(100, "--limit", min=1, max=500),
) -> None:
    if kind not in {None, "skill", "mcp"}:
        raise typer.BadParameter("kind must be skill or mcp")
    with _client() as client:
        response = client.get("/v1/inspections", params={"kind": kind, "limit": limit})
        response.raise_for_status()
        _print(response.json())


@inspections_app.command("show")
def show_inspection(content_digest: str) -> None:
    with _client() as client:
        response = client.get(f"/v1/inspections/{quote(content_digest, safe='')}")
        response.raise_for_status()
        _print(response.json())


def _confirm_inspection(content_digest: str, decision: str, scope: str, session: str | None) -> None:
    with _client() as client:
        response = client.post(
            f"/v1/inspections/{quote(content_digest, safe='')}/confirm",
            json={
                "schema_version": "1.0", "request_id": f"guardctl-inspection-{uuid4()}",
                "operator": "local-terminal", "decision": decision, "scope": scope,
                "session_key": session,
            },
        )
        response.raise_for_status()
        _print(response.json())


@inspections_app.command("approve")
def approve_inspection(
    content_digest: str,
    scope: str = typer.Option("allow-this-digest", "--scope"),
    session: str | None = typer.Option(None, "--session"),
) -> None:
    _confirm_inspection(content_digest, "approve", scope, session)


@inspections_app.command("deny")
def deny_inspection(content_digest: str) -> None:
    _confirm_inspection(content_digest, "deny", "allow-this-digest", None)


@inspections_app.command("invalidate")
def invalidate_inspection(content_digest: str) -> None:
    with _client() as client:
        response = client.post(
            f"/v1/inspections/{quote(content_digest, safe='')}/invalidate",
            json={"schema_version": "1.0", "request_id": f"guardctl-inspection-{uuid4()}", "operator": "local-terminal"},
        )
        response.raise_for_status()
        _print(response.json())


@inspections_app.command("rescan")
def rescan_skill(
    source: Path,
    name: str = typer.Option(..., "--name"),
    source_identity: str = typer.Option("local-cli", "--source-identity"),
) -> None:
    with _client() as client:
        response = client.post(
            "/v1/inspections/skill",
            json={
                "schema_version": "1.0", "request_id": f"guardctl-inspection-{uuid4()}",
                "source_path": str(source.resolve()), "canonical_name": name,
                "source_identity": source_identity, "builtin_findings": [],
            },
        )
        response.raise_for_status()
        _print(response.json())


@app.command("replay")
def replay(session: str = typer.Option(..., "--session")) -> None:
    with _client() as client:
        response = client.get("/v1/events", params={"session": session, "limit": 1000})
        response.raise_for_status()
        rows = response.json()
    settings = _settings()
    engine = PolicyEngine(PolicyLoader().load(settings.policy_path), settings.workspace)
    results = []
    for row in reversed(rows):
        try:
            event = GuardEvent.model_validate(json.loads(row["sanitized_json"]))
            replayed = engine.decide(event)
            proposed = replayed.would_decide or replayed.decision
            results.append({
                "event_id": row["event_id"], "recorded_decision": row.get("decision"),
                "replayed_decision": proposed.value, "risk": replayed.risk,
                "rule_ids": replayed.rule_ids, "changed": row.get("decision") not in {replayed.decision.value, proposed.value},
            })
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            results.append({"event_id": row.get("event_id"), "error": str(exc)})
    _print({"session": session, "events": results})


@app.command("doctor")
def doctor() -> None:
    report = run_doctor(_settings())
    _print(report)
    if report["overall"] == "fail":
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
