# GuardAgent

GuardAgent is a local, deterministic policy service and typed OpenClaw plugin for controlling actions with real side effects. It implements the MVP described in `docs/OPENCLAW_GUARD_AGENT_REQUIREMENTS.md`.

## Highlights

- Deterministic allow, approval, and deny decisions backed by versioned YAML policy.
- Typed OpenClaw hooks for tool calls, outbound messages, lifecycle events, and installation.
- Fail-closed degraded behavior when the local policy service is unavailable.
- Secret redaction, correlation controls, single-use approvals, and hash-chained SQLite audit records.
- Unit, integration, adversarial, and performance tests for the Python service and TypeScript plugin.

## Quick start

Prerequisites are Python 3.12 or newer and Node.js 22 or newer.

```powershell
python -m pip install -e ".[test]"
python scripts/init_guard.py
guardd
guardctl status
```

The service listens on `127.0.0.1:8787` by default. The generated bearer token is stored outside the workspace by default, under the current user's GuardAgent state directory. See `docs/DEPLOYMENT.md` before enabling Enforce mode.

GuardAgent does not replace OpenClaw sandboxing, tool policy, exec approvals, sender allowlists, or host isolation. Start with Observe mode and review [deployment and rollback](docs/DEPLOYMENT.md) plus the [implementation status](docs/IMPLEMENTATION_STATUS.md). The status file explicitly lists target-host gates that repository tests cannot prove.

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

## Repository layout

- `guardd/`: Python policy service, API, CLI, normalization, approvals, and audit storage.
- `plugins/guard-openclaw/`: typed OpenClaw plugin source, tests, and runtime build.
- `policies/`: default policy and JSON Schemas.
- `config/`: conservative OpenClaw and execution-approval baselines.
- `fixtures/`: expected allow, approval, and deny decisions.
- `tests/`: unit, integration, adversarial, and performance coverage.
- `docs/`: requirements, deployment guidance, feature inventory, and implementation evidence.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not put sensitive details in a public issue.

GuardAgent is licensed under the [Apache License 2.0](LICENSE).
