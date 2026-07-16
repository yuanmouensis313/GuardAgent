# Contributing to GuardAgent

Thank you for helping improve GuardAgent. Security-sensitive changes should be small, reviewable, and backed by tests.

## Development setup

Prerequisites:

- Python 3.12 or newer
- Node.js 22 or newer

Install the Python package and test dependencies:

```powershell
python -m pip install -e ".[test]"
```

Install the plugin dependencies without running dependency lifecycle scripts:

```powershell
cd plugins/guard-openclaw
npm ci --ignore-scripts
```

## Checks

Run the Python suite from the repository root:

```powershell
python -m pytest
```

Run the plugin checks:

```powershell
cd plugins/guard-openclaw
npm run check
npm test
npm run build
git diff --exit-code -- dist
```

The generated `dist/` runtime files are committed. Update them whenever `src/` changes.

Run the web-console checks:

```powershell
cd web
npm run lint
npm test
npm run build
git diff --exit-code -- ../guardd/ui/static
```

The generated `guardd/ui/static/` production console is committed. Update it whenever `web/src/` changes.

## Change workflow

1. Create a focused branch such as `feat/policy-rule` or `fix/audit-redaction`.
2. Keep commits narrow and use a clear prefix such as `feat:`, `fix:`, `docs:`, or `test:`.
3. Add tests for policy, normalization, approval, audit, degraded-mode, API, or web-console behavior changes.
4. Update deployment and implementation-status documentation when operational behavior changes.
5. Open a pull request and wait for all required checks to pass.

Do not weaken fail-closed behavior, approval binding, redaction, loopback restrictions, or audit integrity without documenting the threat-model impact.

## Reporting vulnerabilities

Do not disclose suspected vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).
