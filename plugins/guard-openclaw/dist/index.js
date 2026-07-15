import { randomUUID } from "node:crypto";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { GuardClient, configFor, unifiedEvent } from "./client.js";
import { emergencyDecision } from "./emergency.js";
const clients = new Map();
const calls = new Map();
function clientFor(config) {
    const key = `${config.serviceUrl}\n${config.tokenFile}`;
    let client = clients.get(key);
    if (!client) {
        client = new GuardClient(config);
        clients.set(key, client);
    }
    return client;
}
function approvalResult(decision, client) {
    return {
        ...(decision.rewritten_params ? { params: decision.rewritten_params } : {}),
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
    const client = clientFor(config);
    const normalized = unifiedEvent(event, ctx, "tool.before", config);
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
        if (decision.decision === "REQUIRE_APPROVAL")
            return approvalResult(decision, client);
        return decision.rewritten_params ? { params: decision.rewritten_params } : undefined;
    }
    catch {
        return emergencyResult(event, config);
    }
}
async function outboundDecision(event, ctx, payload, config) {
    const client = clientFor(config);
    const outboundEvent = unifiedEvent(event, ctx, "message.before", config, { toolName: "message_send", params: payload });
    try {
        const decision = await client.decide(outboundEvent, true);
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
        api.on("before_tool_call", (event, ctx) => beforeTool(event, ctx, config), { priority: 10_000, timeoutMs: 500 });
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
        api.on("message_sending", (event, ctx) => outboundDecision(event, ctx, { content: event.content ?? "", ...event }, config), { priority: 10_000, timeoutMs: 500 });
        api.on("reply_payload_sending", (event, ctx) => outboundDecision(event, ctx, event.payload ?? event, config), { priority: 10_000, timeoutMs: 500 });
        api.on("before_agent_run", async (event, ctx) => {
            if (!config.observeInputInjection)
                return undefined;
            const text = JSON.stringify(event);
            if (/(ignore|disregard).{0,40}(previous|system).{0,100}(tool|shell|credential|policy)/is.test(text)) {
                const client = clientFor(config);
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
        }, { priority: 10_000, timeoutMs: 500 });
        for (const name of ["session_start", "session_end", "agent_end", "subagent_spawned", "subagent_ended"]) {
            api.on(name, (event, ctx) => lifecycle(event, ctx, name.replace("_", "."), config));
        }
        api.on("gateway_start", (event, ctx) => {
            lifecycle(event, ctx, "gateway.start", config);
            try {
                clientFor(config).observe("/v1/health", undefined, "GET");
            }
            catch {
                // The first guarded action applies the embedded fail-closed policy.
            }
        });
        api.on("gateway_stop", (event, ctx) => lifecycle(event, ctx, "gateway.stop", config));
    },
});
