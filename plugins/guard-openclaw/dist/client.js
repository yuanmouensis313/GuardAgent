import { readFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
const SECRET_KEY = /(token|secret|password|cookie|authorization|pairing)/i;
const SECRET_VALUES = [
    ["private_key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
    ["jwt", /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g],
    ["api_key", /\b(?:sk-(?:proj-)?|sk-ant-|gh[pousr]_)[A-Za-z0-9_-]{20,}\b/g],
];
function marker(kind, value) {
    const digest = createHash("sha256").update(value).digest("hex").slice(0, 12);
    return `<SECRET type="${kind}" len="${value.length}" sha256="${digest}">`;
}
export function redact(value, key = "") {
    if (SECRET_KEY.test(key)) {
        return { value: marker("sensitive_field", String(value)), classifications: ["sensitive_field"] };
    }
    if (typeof value === "string") {
        const classifications = [];
        let output = value;
        for (const [kind, pattern] of SECRET_VALUES) {
            output = output.replace(pattern, (matched) => {
                classifications.push(kind);
                return marker(kind, matched);
            });
        }
        return { value: output, classifications: [...new Set(classifications)] };
    }
    if (Array.isArray(value)) {
        const classifications = [];
        const output = value.map((item) => {
            const clean = redact(item);
            classifications.push(...clean.classifications);
            return clean.value;
        });
        return { value: output, classifications: [...new Set(classifications)] };
    }
    if (value && typeof value === "object") {
        const classifications = [];
        const output = {};
        for (const [childKey, childValue] of Object.entries(value)) {
            const clean = redact(childValue, childKey);
            output[childKey] = clean.value;
            classifications.push(...clean.classifications);
        }
        return { value: output, classifications: [...new Set(classifications)] };
    }
    return { value, classifications: [] };
}
export function hashLocal(value) {
    if (value === undefined || value === null || value === "")
        return undefined;
    return `sha256:${createHash("sha256").update(String(value)).digest("hex")}`;
}
function context(event, ctx) {
    return { ...(event.context ?? {}), ...(ctx ?? {}) };
}
export function configFor(event, ctx) {
    const candidate = context(event, ctx).pluginConfig;
    if (!candidate)
        throw new Error("guard-openclaw plugin configuration is missing");
    const url = new URL(candidate.serviceUrl);
    if (!["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)) {
        throw new Error("guardd serviceUrl must be loopback");
    }
    return candidate;
}
export function unifiedEvent(event, ctx, eventType, config, override) {
    const sourceContext = context(event, ctx);
    const rawParams = override?.params ?? event.params ?? {};
    const clean = redact(rawParams);
    const sessionKey = hashLocal(sourceContext.sessionKey ?? sourceContext.sessionId) ?? "local:unknown";
    return {
        schema_version: "1.0",
        event_id: randomUUID(),
        event_type: eventType,
        occurred_at: new Date().toISOString(),
        source: "openclaw",
        gateway_id: config.gatewayId ?? "local-gateway",
        agent_id: String(sourceContext.agentId ?? "unknown"),
        session_key: sessionKey,
        session_id: hashLocal(sourceContext.sessionId),
        run_id: String(event.runId ?? sourceContext.runId ?? "") || undefined,
        tool_call_id: String(event.toolCallId ?? "") || undefined,
        origin: {
            channel: String(sourceContext.messageProvider ?? sourceContext.channelId ?? "local"),
            channel_id: hashLocal(sourceContext.channelId),
            sender_id: hashLocal(sourceContext.senderId),
            is_local_operator: sourceContext.isLocalOperator === true,
        },
        tool: {
            name: override?.toolName ?? event.toolName ?? "unknown",
            kind: String(event.toolKind ?? sourceContext.toolKind ?? "unknown"),
            input_kind: event.toolInputKind ?? sourceContext.toolInputKind,
        },
        params: clean.value,
        derived: {
            host_derived_paths: event.derivedPaths ? [...event.derivedPaths] : [],
            guard_openclaw_version: "0.1.0",
            openclaw_version: sourceContext.openclawVersion,
        },
        data_classification: clean.classifications,
        trace: {
            trace_id: sourceContext.traceId,
            span_id: sourceContext.spanId,
        },
    };
}
export class GuardClient {
    config;
    token;
    failures = 0;
    nextAttempt = 0;
    queue = [];
    draining = false;
    static MAX_QUEUE = 256;
    constructor(config) {
        this.config = config;
    }
    async bearer() {
        if (!this.token)
            this.token = (await readFile(resolve(this.config.tokenFile), "utf8")).trim();
        if (this.token.length < 32)
            throw new Error("invalid guardd token file");
        return this.token;
    }
    async request(path, body, method = "POST") {
        if (Date.now() < this.nextAttempt)
            throw new Error("guardd reconnect backoff active");
        const timeout = Math.min(this.config.timeoutMs ?? 400, 450);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);
        try {
            const response = await fetch(`${this.config.serviceUrl}${path}`, {
                method,
                headers: { Authorization: `Bearer ${await this.bearer()}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
                body: body === undefined ? undefined : JSON.stringify(body),
                signal: controller.signal,
            });
            if (!response.ok)
                throw new Error(`guardd HTTP ${response.status}`);
            this.failures = 0;
            this.nextAttempt = 0;
            return await response.json();
        }
        catch (error) {
            this.failures += 1;
            this.nextAttempt = Date.now() + Math.min(30_000, 250 * 2 ** Math.min(this.failures, 7));
            if (String(error).includes("401"))
                this.token = undefined;
            throw error;
        }
        finally {
            clearTimeout(timer);
        }
    }
    decide(event, message = false) {
        return this.request(message ? "/v1/decisions/message" : "/v1/decisions/tool", {
            schema_version: "1.0", request_id: randomUUID(), event,
        });
    }
    observe(path, body, method = "POST", critical = false) {
        if (this.queue.length >= GuardClient.MAX_QUEUE) {
            if (critical) {
                // Critical/approval observations bypass a saturated low-risk queue.
                void this.request(path, body, method).catch(() => undefined);
            }
            return;
        }
        this.queue.push({ path, body, method });
        void this.drain();
    }
    async drain() {
        if (this.draining)
            return;
        this.draining = true;
        try {
            while (this.queue.length) {
                const job = this.queue.shift();
                try {
                    await this.request(job.path, job.body, job.method);
                }
                catch {
                    // Low-risk result/lifecycle details may be discarded during degradation.
                }
            }
        }
        finally {
            this.draining = false;
            if (this.queue.length)
                void this.drain();
        }
    }
}
