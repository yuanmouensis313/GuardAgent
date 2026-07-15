# GuardAgent MVP implementation and verification status

Date: 2026-07-14

This file distinguishes repository implementation evidence from deployment evidence. A green repository test does not prove that a particular OpenClaw host has sandboxing, channel allowlists, or exec approvals configured correctly.

## Implemented repository scope

| Requirement area | Evidence |
|---|---|
| Typed plugin interception | `plugins/guard-openclaw/src/index.ts`: tool, result, input, outbound message/reply, session, agent, subagent, install, and Gateway hooks |
| Fail-closed degradation | `plugins/guard-openclaw/src/emergency.ts`; bounded observation queue and 450 ms request ceiling in `client.ts` |
| Event and decision schemas | `guardd/models/events.py`, `guardd/models/decisions.py` |
| Command/path/network normalization | `guardd/normalizers/`; shell splitting, inline eval, patch paths, canonical paths, DNS/IP classification, URL query redaction |
| Deterministic policy | `guardd/policy/`, `policies/default.yaml`, JSON Schema; strict decision ordering and Observe/Approval/Enforce modes |
| Cross-event controls | `guardd/correlation.py`: sensitive-read/exfil, denial evasion, tool/repeat/subagent/bulk budgets, bounded session/sender state, restart restoration |
| Approval | GuardAgent approval record plus OpenClaw `requireApproval`, allow-once/deny only, expiry, exact digest and identity binding, restart invalidation |
| Audit | SQLite WAL/busy timeout/integrity, required tables, hash chain, policy versions, summary-only params/tool output, emergency JSONL |
| Local API | All required `/v1` routes, loopback-only configuration, bearer token file, body size/Content-Type/schema enforcement |
| CLI | Required status, events, approvals, policy validate/test/simulate, replay, and doctor commands |
| Native baseline assets | `config/openclaw-security-baseline.json5`, `config/exec-approvals.baseline.json`, fail-closed operator install policy |
| Operations | Initialization, benchmark, consistent backup, deployment, rollback, break-glass, and troubleshooting instructions |

Current policy inventory: 37 base rules. Current fixture inventory: 40 individual allow/approval/deny JSON fixtures (the count is verified in tests and must remain at least 30).

## Automated evidence

- Final local run: 48 Python tests passed; 1 symlink test was skipped because the Windows process lacks symlink creation permission. Nine TypeScript plugin tests passed, TypeScript strict checking passed, and the runtime build completed.
- Python unit/integration/adversarial tests cover policy schema/precedence, fixtures, shell parsing, canonical paths, apply_patch, network/DNS, secrets, approvals, audit, correlation, restart, API, and install policy.
- Plugin tests run against the OpenClaw 2026.7.1 SDK and cover allow/deny/approval, rewritten params, outbound cancellation, disconnect fallback, result/session correlation, required hook registration, prompt input gate, install fail-closed, and pre-redaction.
- The performance test sends 10,000 persisted events and checks bounded process state; the benchmark separately checks 10,000 deterministic decisions and 100 concurrent decisions against the 20/100 ms budgets.
- Final benchmark on this host: P50 0.713 ms, P95 0.892 ms, and 100-concurrent P95 12.439 ms.
- TypeScript compilation generates the declared `dist/index.js` runtime entry.
- `openclaw config validate --json` from the pinned OpenClaw 2026.7.1 development dependency accepts `config/openclaw-security-baseline.json5`; expected warnings remain until deployment placeholders are supplied and the plugin is installed.
- A real loopback smoke run started `guardd`, queried `guardctl status` and `events list`, reported SQLite integrity `ok`, then stopped and removed its temporary state.

## External deployment gates not proven in this workspace

The following are intentionally not marked complete because they require the user's actual OpenClaw Gateway, channels, workspace, and operating environment:

1. `guardctl doctor` currently reports that a global OpenClaw CLI is not installed/on PATH and that the runtime token has not been initialized.
2. The six OpenClaw baseline commands have not been run successfully against a real configured Gateway.
3. Hook behavior has been SDK-compiled and mock-integrated, but not exercised against the user's live Gateway and real tool/channel adapters.
4. The required 3–7 day Observe run and 24-hour stability run have not elapsed.
5. Message channel allowlists/pairing, workspace root, initial domain allowlist, retention, and normal command allowlist still require operator-specific values. Until supplied, the repository uses the documented conservative defaults.
6. Windows junction creation was unavailable to the test process, so that real-filesystem test is skipped; canonical resolution logic and ordinary symlink escape behavior are covered, but the target host should rerun the test with junction permission.

Do not switch a live deployment to Enforce until these gates pass. Repository completion is not a substitute for the rollout gate in section 24.2 of the requirements.

## Reproducible verification

```powershell
python -m guardd.cli policy validate
python -m unittest discover -s tests -p "test_*.py" -v
python scripts/benchmark.py

cd plugins/guard-openclaw
npm ci --ignore-scripts
npm run check
npm test
npm run build
```

After installation on the target host, run the deployment commands in `docs/DEPLOYMENT.md` and attach their outputs to the deployment record.
