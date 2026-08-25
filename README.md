# GuardAgent

GuardAgent is a local, deterministic policy service and typed OpenClaw plugin for controlling actions with real side effects. It implements the MVP described in `docs/OPENCLAW_GUARD_AGENT_REQUIREMENTS.md`.

## Highlights

- Deterministic allow, approval, and deny decisions backed by versioned YAML policy.
- Typed OpenClaw hooks for tool calls, outbound messages, lifecycle events, and installation.
- Fail-closed degraded behavior when the local policy service is unavailable.
- Secret redaction, correlation controls, single-use approvals, and hash-chained SQLite audit records.
- Session-scoped `R_task` policies with digest-bound confirmation, safe revisions, limits, and child-session inheritance.
- Optional asynchronous LLM safety-review agent with strict structured output, evidence validation, circuit breaking, cache/lease jobs, and a fusion rule that can only tighten deterministic decisions.
- Optional hybrid `R_task` generation: the model proposes against aliases and trusted H0 input; a deterministic compiler rejects unsupported expansion before operator activation.
- Synchronous inbound/outbound data-path sanitization with execution transformation plans and sanitization audit.
- Digest-bound Skill and MCP descriptor inspection; a fail-closed stdio MCP proxy removes rejected descriptors before model visibility.
- Local Chinese web console for live approvals, event/session review, policy simulation and publishing, and diagnostics.
- Unit, integration, adversarial, and performance tests for the Python service and TypeScript plugin.

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run this command from the repository root:

```powershell
uv run guardagent
```

On the first run, uv selects Python 3.12, creates `.venv`, and installs the locked runtime dependencies. GuardAgent validates the policy, initializes its protected local state, and starts the API plus the packaged web console on `127.0.0.1:8787`.

Keep the server terminal open. In a second terminal, inspect the service or securely open the console:

```powershell
uv run guardctl status
uv run guardctl ui
```

Run the startup command from another directory only when `GUARD_AGENT_POLICY` and `GUARD_AGENT_WORKSPACE` point to the intended absolute paths. Node.js 22 or newer is needed only when changing or rebuilding the OpenClaw plugin or web-console source; it is not required to serve the packaged console.

The existing editable-install workflow remains supported when uv is unavailable:

```powershell
python -m pip install -e ".[test]"
python scripts/init_guard.py
guardd
```

The deterministic control planes default to Observe and all LLM features default to disabled. Inspect them with `guardctl task-policy`,
`guardctl sanitization`, and `guardctl inspections`; do not enable their Enforce
modes until the deployment gates have been completed.

To stage the reviewer, set `GUARD_LLM_ENABLED=true`, a model/base URL, and start with
`GUARD_LLM_REVIEW_MODE=shadow`. Use `guardctl llm health` and `guardctl llm reviews`.
Never start with `enforce_tighten`; follow the privacy, evaluation, and rollback gates in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). The model is not an authorization authority:
it has no tools and cannot loosen `R_base` or a deterministic deny.

The service listens on `127.0.0.1:8787` by default. The generated bearer token is stored outside the workspace by default, under the current user's GuardAgent state directory. See `docs/DEPLOYMENT.md` before enabling Enforce mode.

`guardctl ui` creates a 60-second single-use browser bootstrap and opens `http://127.0.0.1:8787/ui/`. The browser receives a short-lived HttpOnly UI session; the long-lived service bearer token is never placed in the URL or browser storage.

GuardAgent does not replace OpenClaw sandboxing, tool policy, exec approvals, sender allowlists, or host isolation. Start with Observe mode and review [deployment and rollback](docs/DEPLOYMENT.md) plus the [implementation status](docs/IMPLEMENTATION_STATUS.md). The status file explicitly lists target-host gates that repository tests cannot prove.

## Validation status

The service, CLI, policy engine, UI API, and web console have been tested with repository fixtures and command-line-created events. The OpenClaw plugin has been type-checked and tested against mocked hook interactions, but this version has **not yet been exercised end to end against a real OpenClaw Gateway, workspace, or channel adapter**. Do not treat the visual console or automated test results as production integration evidence; complete the target-host gates in [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) first.

## Build and test

Run the Python suite from the repository root:

```powershell
python -m pytest
```

Build and test the OpenClaw plugin:

```powershell
cd plugins/guard-openclaw
npm ci --ignore-scripts
npm run check
npm test
npm run build
```

The generated `plugins/guard-openclaw/dist/` directory is committed because it is the plugin runtime entry. CI verifies that it stays synchronized with `src/`.

Build and test the local web console:

```powershell
cd web
npm ci --ignore-scripts
npm test
npm run build
```

The production build is packaged under `guardd/ui/static/` and served by the same loopback-only FastAPI process.
Set `GUARDD_UI_ENABLED=false` to disable the browser control plane without disabling the machine API or OpenClaw plugin.

## Repository layout

- `guardd/`: Python policy service, API, CLI, normalization, approvals, and audit storage.
- `guardd/llm/`, `guardd/agents/`: bounded model contracts, providers, validators, job workers, and decision fusion.
- `guardd/task_policy/`, `guardd/sanitization/`, `guardd/inspections/`: task scope, hybrid compiler, data-path, and content-admission controls.
- `guardd/mcp_proxy.py`: digest-bound stdio MCP compatibility proxy.
- `plugins/guard-openclaw/`: typed OpenClaw plugin source, tests, and runtime build.
- `policies/`: default policy and JSON Schemas.
- `config/`: conservative OpenClaw and execution-approval baselines.
- `fixtures/`: expected allow, approval, and deny decisions.
- `tests/`: unit, integration, adversarial, and performance coverage.
- `web/`: React/TypeScript source for the local visual console.
- `docs/`: requirements, deployment guidance, feature inventory, and implementation evidence.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not put sensitive details in a public issue.

GuardAgent is licensed under the [Apache License 2.0](LICENSE).
