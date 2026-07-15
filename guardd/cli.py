from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import typer

from guardd.config import Settings
from guardd.doctor import run_doctor
from guardd.models.events import GuardEvent
from guardd.policy import PolicyEngine, PolicyLoader, PolicyValidationError
from guardd.security import ensure_token


app = typer.Typer(help="GuardAgent management CLI", no_args_is_help=True)
events_app = typer.Typer(help="Audit events")
approvals_app = typer.Typer(help="Single-use approvals")
policy_app = typer.Typer(help="Policy validation and simulation")
app.add_typer(events_app, name="events")
app.add_typer(approvals_app, name="approvals")
app.add_typer(policy_app, name="policy")


def _settings() -> Settings:
    return Settings.from_env()


def _client() -> httpx.Client:
    settings = _settings()
    token = ensure_token(settings.token_path)
    return httpx.Client(base_url=f"http://{settings.host}:{settings.port}", headers={"Authorization": f"Bearer {token}"}, timeout=5)


def _print(value: Any) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, indent=2, default=str))


@app.command("status")
def status_command() -> None:
    with _client() as client:
        response = client.get("/v1/status")
        response.raise_for_status()
        _print(response.json())


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
