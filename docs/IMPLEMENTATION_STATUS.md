# GuardAgent MVP implementation and verification status

Date: 2026-08-02

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
| Session task policy | `guardd/task_policy/`: H0-only deterministic synthesis, digest/revision confirmation, expansion pause, automatic narrowing, durable limits, sender/agent binding, and child-session intersection |
| LLM safety reviewer | `guardd/llm/`, `guardd/agents/safety_review.py`: strict structured contracts, summary-only context, async lease jobs, cache, retry, circuit breaker, evidence/secret validation, and tighten-only fusion |
| Hybrid task policy | Trusted H0 context with path/domain aliases, proposal schema, deterministic compiler, provenance/diff persistence, parent intersection, generation API/UI, and deterministic fallback |
| Data-path sanitization | Versioned Python/TypeScript patterns, local policy/execution/model views, transformation-plan binding, synchronous `tool_result_persist`, outbound secret blocking, and sanitization audit/API/UI |
| Skill inspection | Bounded pre-install/startup/runtime scans, HMAC evidence, capability manifests, digest cache invalidation, static-critical non-overridable deny, confirmation UI/CLI |
| MCP inspection | Recursive tool/prompt/resource descriptor scan plus `guard-mcp-proxy` stdio admission filtering, call digest binding, list-change invalidation, fail-closed guardd dependency, and result sanitization |
| Approval | GuardAgent approval record plus OpenClaw `requireApproval`, allow-once/deny only, expiry, exact digest and identity binding, restart invalidation |
| Audit | SQLite WAL/busy timeout/integrity, required tables, hash chain, policy versions, summary-only params/tool output, emergency JSONL |
| Local API | All required `/v1` routes, loopback-only configuration, bearer token file, body size/Content-Type/schema enforcement |
| CLI | Status, events, approvals, policy, replay, doctor, LLM health/review/retry, explicit event review, and digest-bound security override commands |
| Local visual console | React/TypeScript SPA under `/ui/`; short-lived HttpOnly UI sessions, CSRF/origin controls, live approvals, events/sessions, policy workbench, diagnostics, incidents, and settings |
| UI operator API | Dedicated `/v1/ui/*` routes, cursor pagination, aggregate queries, SSE replay buffer, atomic policy publishing/revisions, and background doctor jobs |
| Retention and migrations | UI schema migration marker, pre-migration SQLite backup, query indexes, and configured retention cleanup |
| Native baseline assets | `config/openclaw-security-baseline.json5`, `config/exec-approvals.baseline.json`, fail-closed operator install policy |
| Operations | Initialization, benchmark, consistent backup, deployment, rollback, break-glass, and troubleshooting instructions |

Current policy inventory: 37 base rules. Current fixture inventory: 40 individual allow/approval/deny JSON fixtures (the count is verified in tests and must remain at least 30).

## Automated evidence

- Repository suites cover the original MVP plus R_task, sanitization, Skill/MCP inspection, and a real-process stdio MCP proxy integration test. Exact counts are reported by the current CI/test run rather than kept as a stale fixed number here.
- Python unit/integration/adversarial tests cover policy schema/precedence, fixtures, shell parsing, canonical paths, apply_patch, network/DNS, secrets, approvals, audit, correlation, restart, API, and install policy.
- UI integration and unit tests cover single-use bootstrap, HttpOnly sessions, CSRF/origin enforcement, static SPA routing/security headers, approval races, cursor pagination and combined event filters, event/session queries, policy dry-run/publish rollback/digest conflicts, correlation budget reload, retention, migration backup, diagnostic jobs/history, and token non-disclosure.
- The web console passes strict TypeScript compilation, a Vite production build, and Vitest component/helper tests. The latest production build is packaged under `guardd/ui/static/`, is about 445 KB gzip, uses route-level page chunks, and has no runtime CDN. Regenerate it with `npm run build` whenever `web/src/` changes.
- Plugin tests run against the OpenClaw 2026.7.1 SDK and cover allow/deny/approval, rewritten execution params, outbound cancellation/audit, disconnect fallback, synchronous result sanitization, R_task capture, subagent binding, Skill admission, required hook registration, and Observe/Enforce failure behavior.
- LLM tests cover provider isolation, schema/evidence validation, deterministic-deny immutability, shadow/advisory/enforce fusion, lease/cache/retry behavior, approval race handling, exact-digest override, canary non-disclosure, H0 tool-result pollution, and hybrid expansion rejection.
- The performance test sends 10,000 persisted events and checks bounded process state; the benchmark separately checks 10,000 deterministic decisions and 100 concurrent decisions against the 20/100 ms budgets.
- Final benchmark on this host: P50 0.948 ms, P95 1.375 ms, and 100-concurrent P95 14.994 ms; all remain below the 20/100 ms budgets.
- TypeScript compilation generates the declared `dist/index.js` runtime entry.
- `openclaw config validate --json` from the pinned OpenClaw 2026.7.1 development dependency accepts `config/openclaw-security-baseline.json5`; expected warnings remain until deployment placeholders are supplied and the plugin is installed.
- A real loopback smoke run started `guardd`, queried `guardctl status` and `events list`, reported SQLite integrity `ok`, then stopped and removed its temporary state.

## External deployment gates not proven in this workspace

The following are intentionally not marked complete because they require the user's actual OpenClaw Gateway, channels, workspace, and operating environment:

Current UI evidence is based on repository tests and events created through CLI/API test inputs. It is not evidence of an end-to-end OpenClaw integration.

1. `guardctl doctor` currently reports that a global OpenClaw CLI is not installed/on PATH. The local token, pattern parity, result hooks, MCP gate, policy, loopback bind, and state isolation checks pass.
2. The six OpenClaw baseline commands have not been run successfully against a real configured Gateway.
3. Hook behavior has been SDK-compiled and mock-integrated, but `tool_result_persist` ordering has not yet been exercised against the user's live Gateway and real tool/channel adapters. Inbound sanitization must remain Observe there until this is proven.
4. The required 3–7 day Observe run and 24-hour stability run have not elapsed.
5. Message channel allowlists/pairing, workspace root, initial domain allowlist, retention, and normal command allowlist still require operator-specific values. Until supplied, the repository uses the documented conservative defaults.
6. Windows junction creation was unavailable to the test process, so that real-filesystem test is skipped; canonical resolution logic and ordinary symlink escape behavior are covered, but the target host should rerun the test with junction permission.
7. The compatibility MCP proxy currently protects stdio servers. SSE and Streamable HTTP transports are reported as unprotected capabilities and must not be advertised or operated as GuardAgent-protected until corresponding interceptors are implemented or OpenClaw exposes a pre-model descriptor hook.
8. OpenClaw does not expose an authoritative Skill-use identity on every run. GuardAgent can gate installation, scan configured roots at startup, and bind runtime calls when the host supplies content identity; every enabled Skill root must therefore be configured and verified on the target Gateway before content-inspection Enforce is claimed.
9. No real remote or local model endpoint has been qualified in this repository run. Provider privacy terms, target-model structured-output quality, 3–7 day shadow metrics, false-deny review, cost/latency limits, and key rotation must be proven before `enforce_tighten` or hybrid candidate rollout.

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

cd ../../web
npm ci --ignore-scripts
npm test
npm run build
```

After installation on the target host, run the deployment commands in `docs/DEPLOYMENT.md` and attach their outputs to the deployment record.
