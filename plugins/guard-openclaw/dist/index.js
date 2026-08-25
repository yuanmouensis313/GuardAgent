import { createHash, randomUUID } from "node:crypto";
import { readdir } from "node:fs/promises";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { GuardClient, configFor, hashLocal, unifiedEvent } from "./client.js";
import { emergencyDecision } from "./emergency.js";
import { sanitizeToolMessage, sanitizeValue } from "./sanitizer.js";
import { SANITIZATION_PATTERN_DIGEST } from "./generated-sanitization-patterns.js";
const clients = new Map();
const calls = new Map();
const parentSessions = new Map();
const startupInspectionErrors = new Map();
const configKey = (config) => `${config.serviceUrl}\n${config.tokenFile}`;
function contentDigest(value) {
    return `sha256:${createHash("sha256").update(JSON.stringify(value) ?? String(value)).digest("hex")}`;
}
async function inspectSkillPath(client, sourcePath, name, sourceIdentity) {
    return client.request("/v1/inspections/skill", {
        schema_version: "1.0", request_id: randomUUID(), source_path: sourcePath,
        canonical_name: name, source_identity: sourceIdentity.slice(0, 512), builtin_findings: [],
    });
}
async function scanConfiguredSkillRoots(client, config) {
    for (const root of (config.skillRoots ?? []).slice(0, 32)) {
        const entries = await readdir(root, { withFileTypes: true });
        for (const entry of entries.slice(0, 500)) {
            if (!entry.isDirectory() || entry.isSymbolicLink())
                continue;
            const inspected = await inspectSkillPath(client, `${root}/${entry.name}`, entry.name, `gateway-root:${root}`);
            const effective = String(inspected.effective_decision ?? inspected.verdict?.decision ?? "QUARANTINE");
            if (config.contentInspectionMode === "enforce" && effective !== "ALLOW") {
                throw new Error(`skill ${entry.name} is not admitted (${effective})`);
            }
        }
    }
}
function withParent(ctx) {
    const session = String(ctx?.sessionKey ?? ctx?.sessionId ?? "");
    const parentSessionKey = session ? parentSessions.get(session) : undefined;
    return parentSessionKey ? { ...ctx, parentSessionKey } : ctx;
}
function clientFor(config) {
    const key = `${config.serviceUrl}\n${config.tokenFile}`;
    let client = clients.get(key);
    if (!client) {
        client = new GuardClient(config);
        clients.set(key, client);
    }
    return client;
}
function approvalResult(decision, client, params) {
    return {
        ...(params ? { params } : {}),
        requireApproval: {
            title: `GuardAgent: ${decision.rule_ids[0] ?? "policy review"}`.slice(0, 80),
            description: `${decision.reason} [risk=${decision.risk}; approval=${decision.approval_id ?? "n/a"}]`.slice(0, 512),
            severity: decision.risk === "critical" ? "critical" : decision.risk === "high" ? "warning" : "info",
            timeoutMs: 60_000,
            allowedDecisions: ["allow-once", "deny"],
            pluginId: "guard-openclaw",
            onResolution(resolution) {
                if (!decision.approval_id)
                    return;
                const action = resolution === "allow-once" ? "allow-once" : "deny";
                client.observe(`/v1/approvals/${decision.approval_id}/${action}`, {
                    schema_version: "1.0", request_id: randomUUID(), operator: `openclaw:${resolution}`,
                }, "POST", true);
            },
        },
    };
}
function sameJson(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
}
function executionView(decision, raw, local, config) {
    if (decision.execution_params && decision.rewritten_params && !sameJson(decision.execution_params, decision.rewritten_params)) {
        return { blockReason: "GuardAgent returned conflicting execution_params and rewritten_params" };
    }
    const serviceParams = decision.execution_params ?? decision.rewritten_params ?? undefined;
    const actions = new Set((decision.transformation_plan ?? []).map((item) => item.action));
    if (local.classifications.length && config.sanitizationMode === "enforce") {
        const planned = new Set((decision.transformation_plan ?? []).map((item) => item.classification));
        if (!local.classifications.every((item) => planned.has(item))) {
            return { blockReason: "GuardAgent transformation plan does not cover every locally detected classification" };
        }
        if (actions.has("block") || actions.has("require_approval")) {
            return { blockReason: "GuardAgent blocked secret-bearing execution parameters" };
        }
        if (serviceParams) {
            return { blockReason: "A policy rewrite cannot safely reconstruct locally held secret values" };
        }
        if (actions.has("redact") || actions.has("drop"))
            return { params: local.value };
        if (actions.has("preserve"))
            return { params: raw };
        return { blockReason: "Secret-bearing parameters have no explicit execution transformation" };
    }
    return serviceParams ? { params: serviceParams } : {};
}
function emergencyResult(event, config, outbound = false) {
    const fallback = emergencyDecision(event, config, outbound);
    if (fallback.kind === "allow")
        return undefined;
    if (fallback.kind === "deny")
        return { block: true, blockReason: fallback.reason };
    return {
        requireApproval: {
            title: "GuardAgent degraded-mode approval",
            description: fallback.reason,
            severity: "warning",
            timeoutMs: 60_000,
            allowedDecisions: ["allow-once", "deny"],
            pluginId: "guard-openclaw",
        },
    };
}
async function beforeTool(event, ctx, config) {
    ctx = withParent(ctx);
    const client = clientFor(config);
    const startupInspectionError = startupInspectionErrors.get(configKey(config));
    if (config.contentInspectionMode === "enforce" && startupInspectionError) {
        return { block: true, blockReason: startupInspectionError };
    }
    if (event.contentKind === "skill" && typeof event.contentSourcePath === "string") {
        try {
            const inspected = await inspectSkillPath(client, event.contentSourcePath, String(event.contentName ?? "unknown-skill"), "runtime-skill");
            event = { ...event, contentDigest: String(inspected.content_digest ?? "") };
            const effective = String(inspected.effective_decision ?? inspected.verdict?.decision ?? "QUARANTINE");
            if (config.contentInspectionMode === "enforce" && effective !== "ALLOW") {
                return { block: true, blockReason: `GuardAgent skill inspection verdict is ${effective}` };
            }
        }
        catch {
            if (config.contentInspectionMode === "enforce")
                return { block: true, blockReason: "GuardAgent runtime skill reinspection failed closed" };
        }
    }
    const rawParams = event.params ?? {};
    const local = sanitizeValue(rawParams);
    const normalized = unifiedEvent(event, ctx, "tool.before", config, {
        params: local.value, classifications: local.classifications,
    });
    const eventId = String(normalized.event_id);
    const toolCallId = String(event.toolCallId ?? ctx?.toolCallId ?? "");
    if (toolCallId) {
        calls.set(toolCallId, eventId);
        if (calls.size > 5_000)
            calls.delete(calls.keys().next().value);
    }
    try {
        const decision = await client.decide(normalized);
        if (decision.decision === "DENY")
            return { block: true, blockReason: decision.reason };
        if (decision.rule_ids.includes("TASK-POLICY-PENDING-001")) {
            const digest = decision.task_policy_digest?.slice(0, 16) ?? "unknown";
            const revision = decision.task_policy_revision ?? "unknown";
            return {
                block: true,
                blockReason: `${decision.reason} [R_task revision=${revision}; digest=${digest}; run guardctl task-policy approve --session <session> --digest <full-digest>, then retry]`,
            };
        }
        if (decision.rule_ids.includes("LLM-REVIEW-PENDING-001")) {
            return {
                block: true,
                blockReason: `${decision.reason} [semantic review=${decision.review_status ?? "pending"}; review_id=${decision.review_id ?? "unavailable"}; retry the exact action after review completes]`,
            };
        }
        const execution = executionView(decision, rawParams, local, config);
        if (execution.blockReason)
            return { block: true, blockReason: execution.blockReason };
        if (decision.decision === "REQUIRE_APPROVAL")
            return approvalResult(decision, client, execution.params);
        return execution.params ? { params: execution.params } : undefined;
    }
    catch {
        if (config.sanitizationMode === "enforce" && local.classifications.length) {
            return { block: true, blockReason: "GuardAgent sanitization unavailable for secret-bearing tool parameters" };
        }
        return emergencyResult(event, config);
    }
}
async function outboundDecision(event, ctx, payload, config) {
    ctx = withParent(ctx);
    const client = clientFor(config);
    const local = sanitizeValue(payload);
    const outboundEvent = unifiedEvent(event, ctx, "message.before", config, {
        toolName: "message_send", params: local.value, classifications: local.classifications,
    });
    if ((config.sanitizationMode ?? "observe") !== "disabled" && local.classifications.length) {
        client.observe("/v1/events/sanitization", {
            schema_version: "1.0", request_id: randomUUID(), sanitizer_event_id: randomUUID(),
            direction: "outbound", session_key: hashLocal(ctx?.sessionKey) ?? "local:unknown",
            tool_name: "message_send", classifications: local.classifications,
            transformations: local.transformations, original_size: local.original_size,
            result_size: local.result_size, truncated: local.truncated,
            blocked: config.sanitizationMode === "enforce",
            pattern_digest: SANITIZATION_PATTERN_DIGEST, content_digest: contentDigest(local.value),
        });
    }
    try {
        const decision = await client.decide(outboundEvent, true);
        if (config.sanitizationMode === "enforce" && local.classifications.length) {
            return { cancel: true, cancelReason: "GuardAgent blocked secret-bearing outbound content", metadata: { classifications: local.classifications } };
        }
        if (decision.decision === "DENY" || decision.decision === "REQUIRE_APPROVAL") {
            return { cancel: true, cancelReason: decision.reason, metadata: { guardDecisionId: decision.decision_id, risk: decision.risk } };
        }
        return undefined;
    }
    catch {
        return { cancel: true, cancelReason: emergencyDecision(event, config, true).reason };
    }
}
function lifecycle(event, ctx, eventType, config) {
    try {
        const normalized = unifiedEvent(event, ctx, eventType, config, { toolName: "lifecycle", params: event });
        clientFor(config).observe("/v1/events/session", { schema_version: "1.0", request_id: randomUUID(), event: normalized });
    }
    catch {
        // Lifecycle telemetry must never weaken tool enforcement.
    }
}
export default definePluginEntry({
    id: "guard-openclaw",
    name: "GuardAgent OpenClaw Guard",
    description: "Local deterministic policy enforcement, approval, and audit hooks",
    register(api) {
        const config = configFor({}, { pluginConfig: api.pluginConfig });
        api.on("before_tool_call", (event, ctx) => beforeTool(event, ctx, config), { priority: 10_000, timeoutMs: 10_000 });
        api.on("after_tool_call", (event, ctx) => {
            try {
                const toolCallId = String(event.toolCallId ?? ctx?.toolCallId ?? "");
                const eventId = calls.get(toolCallId);
                if (!eventId)
                    return;
                calls.delete(toolCallId);
                clientFor(config).observe("/v1/events/tool-result", {
                    schema_version: "1.0", request_id: randomUUID(), event_id: eventId,
                    tool_call_id: toolCallId || undefined,
                    success: event.error == null,
                    exit_code: event.exitCode,
                    duration_ms: event.durationMs,
                    output: event.result,
                    error: event.error ? String(event.error).slice(0, 2_048) : undefined,
                }, "POST", event.error != null);
            }
            catch {
                // Decision-time controls remain authoritative if result telemetry fails.
            }
        });
        api.on("tool_result_persist", (event, ctx) => {
            if ((config.sanitizationMode ?? "observe") === "disabled")
                return undefined;
            try {
                const clean = sanitizeToolMessage(event.message, String(event.toolName ?? ctx?.toolName ?? "unknown"));
                clientFor(config).observe("/v1/events/sanitization", {
                    schema_version: "1.0", request_id: randomUUID(), sanitizer_event_id: randomUUID(),
                    direction: "inbound", session_key: hashLocal(ctx?.sessionKey) ?? "local:unknown",
                    tool_name: String(event.toolName ?? ctx?.toolName ?? "unknown"),
                    tool_call_id: String(event.toolCallId ?? ctx?.toolCallId ?? "") || undefined,
                    classifications: clean.classifications, transformations: clean.transformations,
                    original_size: clean.original_size, result_size: clean.result_size,
                    truncated: clean.truncated, blocked: false,
                    pattern_digest: SANITIZATION_PATTERN_DIGEST,
                    content_digest: contentDigest(clean.value),
                });
                if ((config.sanitizationMode ?? "observe") === "enforce")
                    return { message: clean.value };
                return undefined;
            }
            catch {
                return {
                    message: {
                        role: "tool", toolCallId: event.toolCallId,
                        content: [{ type: "text", text: "<GUARD_SANITIZATION_FAILED original_content_removed=\"true\">" }],
                    },
                };
            }
        }, { priority: 10_000 });
        api.on("before_message_write", (event, ctx) => {
            if ((config.sanitizationMode ?? "observe") !== "enforce")
                return undefined;
            try {
                const clean = sanitizeValue(event.message);
                return { message: clean.value };
            }
            catch {
                return { block: true };
            }
        }, { priority: 10_000 });
        api.on("message_sending", (event, ctx) => outboundDecision(event, ctx, { content: event.content ?? "", ...event }, config), { priority: 10_000, timeoutMs: 500 });
        api.on("reply_payload_sending", (event, ctx) => outboundDecision(event, ctx, event.payload ?? event, config), { priority: 10_000, timeoutMs: 500 });
        api.on("before_agent_run", async (event, ctx) => {
            ctx = withParent(ctx);
            const inspectionError = startupInspectionErrors.get(configKey(config));
            if (config.contentInspectionMode === "enforce" && inspectionError) {
                return {
                    outcome: "block", reason: inspectionError,
                    message: "GuardAgent blocked the run because startup Skill inspection did not complete",
                    category: "content-inspection",
                };
            }
            const client = clientFor(config);
            if (config.captureTaskPolicy !== false && typeof event.prompt === "string" && event.prompt.trim()) {
                try {
                    await client.captureTaskPolicy(event, ctx);
                }
                catch {
                    // A missing task policy is handled conservatively by guardd at the
                    // first tool boundary when task-policy enforcement is enabled.
                }
            }
            if (!config.observeInputInjection)
                return undefined;
            const text = JSON.stringify(event);
            if (/(ignore|disregard).{0,40}(previous|system).{0,100}(tool|shell|credential|policy)/is.test(text)) {
                const normalized = unifiedEvent(event, ctx, "agent.before", config, { toolName: "agent_input", params: { prompt: event.prompt ?? "", messages: event.messages ?? [] } });
                try {
                    const decision = await client.decide(normalized);
                    if (decision.decision === "OBSERVE" || decision.decision === "ALLOW")
                        return undefined;
                    return {
                        outcome: "block", reason: decision.reason,
                        message: "GuardAgent blocked a high-risk input before the agent run",
                        category: "prompt-injection", metadata: { decisionId: decision.decision_id, risk: decision.risk },
                    };
                }
                catch {
                    return {
                        outcome: "block", reason: "guardd unavailable during input-injection review",
                        message: "GuardAgent blocked a suspicious input while running in degraded mode",
                        category: "prompt-injection",
                    };
                }
            }
            return undefined;
        }, { priority: 10_000, timeoutMs: 500 });
        api.on("before_install", async (event, ctx) => {
            const client = clientFor(config);
            if (String(event.targetType ?? "").toLowerCase() === "skill" && typeof event.sourcePath === "string") {
                try {
                    const inspected = await client.request("/v1/inspections/skill", {
                        schema_version: "1.0", request_id: randomUUID(), source_path: event.sourcePath,
                        canonical_name: String(event.targetName ?? "unknown-skill"),
                        source_identity: String(event.source ?? event.request ?? "openclaw-install").slice(0, 512),
                        expected_content_digest: typeof event.contentDigest === "string" ? event.contentDigest : undefined,
                        builtin_findings: Array.isArray(event.findings) ? event.findings :
                            event.builtinScan && typeof event.builtinScan === "object" && Array.isArray(event.builtinScan.findings) ? event.builtinScan.findings :
                                Array.isArray(event.builtinFindings) ? event.builtinFindings : [],
                    });
                    const verdict = inspected.verdict;
                    const contentDigest = String(inspected.content_digest ?? "");
                    const contentDecision = String(inspected.effective_decision ?? verdict?.decision ?? "QUARANTINE");
                    if (config.contentInspectionMode === "enforce" && ["DENY", "QUARANTINE", "STALE"].includes(contentDecision)) {
                        return { block: true, blockReason: `GuardAgent ${contentDecision.toLowerCase()} verdict for skill digest ${contentDigest.slice(0, 20)}` };
                    }
                    if (config.contentInspectionMode === "enforce" && contentDecision === "REQUIRE_APPROVAL") {
                        return {
                            block: true,
                            blockReason: `GuardAgent requires digest-bound skill confirmation for ${contentDigest}. Review it in the local UI or run guardctl inspections approve ${contentDigest}, then retry installation.`,
                        };
                    }
                }
                catch {
                    if (config.contentInspectionMode === "enforce") {
                        return { block: true, blockReason: "GuardAgent skill inspection failed closed" };
                    }
                    // Inspection is an optional observer here; allow the mandatory base
                    // install-policy decision to make one immediate request rather than
                    // inheriting this endpoint's transient circuit-breaker delay.
                    client.retryNow();
                }
            }
            const normalized = unifiedEvent(event, ctx, "install.before", config, { toolName: "install", params: event });
            try {
                const decision = await client.decide(normalized);
                if (decision.decision === "DENY" || decision.risk === "critical")
                    return { block: true, blockReason: decision.reason };
                return undefined;
            }
            catch {
                return { block: true, blockReason: "GuardAgent unavailable: install failed closed; security.installPolicy remains authoritative" };
            }
        }, { priority: 10_000, timeoutMs: 10_000 });
        for (const name of ["session_start", "session_end", "agent_end"]) {
            api.on(name, (event, ctx) => lifecycle(event, ctx, name.replace("_", "."), config));
        }
        api.on("subagent_spawned", (event, ctx) => {
            const child = String(event.childSessionKey ?? ctx?.childSessionKey ?? "");
            const parent = String(ctx?.requesterSessionKey ?? ctx?.sessionKey ?? "");
            if (child && parent)
                parentSessions.set(child, parent);
            lifecycle(event, ctx, "subagent.spawned", config);
        });
        api.on("subagent_ended", (event, ctx) => {
            const child = String(event.targetSessionKey ?? ctx?.childSessionKey ?? "");
            if (child)
                parentSessions.delete(child);
            lifecycle(event, ctx, "subagent.ended", config);
        });
        api.on("gateway_start", async (event, ctx) => {
            const client = clientFor(config);
            try {
                await client.negotiateCapabilities(SANITIZATION_PATTERN_DIGEST);
                await scanConfiguredSkillRoots(client, config);
                startupInspectionErrors.delete(configKey(config));
            }
            catch {
                // In enforce mode the client retains the incompatibility and guarded
                // actions fall back to the embedded fail-closed policy.
                if (config.contentInspectionMode === "enforce") {
                    startupInspectionErrors.set(configKey(config), "GuardAgent capability or Skill inspection failed during Gateway startup");
                }
            }
            lifecycle(event, ctx, "gateway.start", config);
        });
        api.on("gateway_stop", (event, ctx) => lifecycle(event, ctx, "gateway.stop", config));
    },
});
