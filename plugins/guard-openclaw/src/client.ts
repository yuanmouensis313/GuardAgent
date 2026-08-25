import { readFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { sanitizeValue } from "./sanitizer.js";
import type { GuardConfig, GuardDecision, HookEvent } from "./types.js";

export function redact(value: unknown, key = ""): { value: unknown; classifications: string[] } {
  const wrapped = key ? { [key]: value } : value;
  const clean = sanitizeValue(wrapped);
  return {
    value: key && clean.value && typeof clean.value === "object" ? (clean.value as Record<string, unknown>)[key] : clean.value,
    classifications: clean.classifications,
  };
}

export function hashLocal(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return `sha256:${createHash("sha256").update(String(value)).digest("hex")}`;
}

function context(event: HookEvent, ctx?: Record<string, unknown>): Record<string, unknown> {
  return { ...(event.context ?? {}), ...(ctx ?? {}) };
}

export function configFor(event: HookEvent, ctx?: Record<string, unknown>): GuardConfig {
  const candidate = context(event, ctx).pluginConfig as GuardConfig | undefined;
  if (!candidate) throw new Error("guard-openclaw plugin configuration is missing");
  const url = new URL(candidate.serviceUrl);
  if (!["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)) {
    throw new Error("guardd serviceUrl must be loopback");
  }
  return candidate;
}

export function unifiedEvent(
  event: HookEvent,
  ctx: Record<string, unknown> | undefined,
  eventType: string,
  config: GuardConfig,
  override?: { toolName?: string; params?: Record<string, unknown>; classifications?: string[] },
): Record<string, unknown> {
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
    parent_session_key: hashLocal(sourceContext.parentSessionKey ?? event.parentSessionKey),
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
    data_classification: [...new Set([...clean.classifications, ...(override?.classifications ?? [])])],
    trace: {
      trace_id: sourceContext.traceId,
      span_id: sourceContext.spanId,
    },
    content_identity: sourceContext.contentKind || event.contentKind ? {
      kind: String(sourceContext.contentKind ?? event.contentKind),
      name: String(sourceContext.contentName ?? event.contentName ?? event.toolName ?? "unknown"),
      digest: String(sourceContext.contentDigest ?? event.contentDigest ?? "") || undefined,
      artifact_digest: String(sourceContext.artifactDigest ?? event.artifactDigest ?? "") || undefined,
      server_identity: String(sourceContext.serverIdentity ?? event.serverIdentity ?? "") || undefined,
    } : undefined,
  };
}

export class GuardClient {
  private token?: string;
  private failures = 0;
  private nextAttempt = 0;
  private capabilityError?: string;

  retryNow(): void {
    this.nextAttempt = 0;
  }
  private readonly queue: Array<{ path: string; body: unknown; method: string }> = [];
  private draining = false;
  private static readonly MAX_QUEUE = 256;

  constructor(private readonly config: GuardConfig) {}

  private async bearer(): Promise<string> {
    if (!this.token) this.token = (await readFile(resolve(this.config.tokenFile), "utf8")).trim();
    if (this.token.length < 32) throw new Error("invalid guardd token file");
    return this.token;
  }

  async request<T>(path: string, body?: unknown, method = "POST"): Promise<T> {
    if (Date.now() < this.nextAttempt) throw new Error("guardd reconnect backoff active");
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
      if (!response.ok) throw new Error(`guardd HTTP ${response.status}`);
      this.failures = 0;
      this.nextAttempt = 0;
      return await response.json() as T;
    } catch (error) {
      this.failures += 1;
      this.nextAttempt = Date.now() + Math.min(30_000, 250 * 2 ** Math.min(this.failures, 7));
      if (String(error).includes("401")) this.token = undefined;
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  decide(event: Record<string, unknown>, message = false): Promise<GuardDecision> {
    if (this.capabilityError && this.config.sanitizationMode === "enforce") {
      return Promise.reject(new Error(this.capabilityError));
    }
    return this.request<GuardDecision>(message ? "/v1/decisions/message" : "/v1/decisions/tool", {
      schema_version: "1.0", request_id: randomUUID(), event,
    });
  }

  async negotiateCapabilities(expectedPatternDigest: string): Promise<void> {
    const capabilities = await this.request<Record<string, unknown>>("/v1/capabilities", undefined, "GET");
    const sanitization = capabilities.sanitization as Record<string, unknown> | undefined;
    const actual = String(sanitization?.pattern_digest ?? "");
    if (this.config.sanitizationMode === "enforce" && sanitization?.enabled !== true) {
      this.capabilityError = "guardd sanitization is disabled while the plugin requires enforce mode";
      throw new Error(this.capabilityError);
    }
    if (actual !== expectedPatternDigest) {
      this.capabilityError = `sanitization pattern digest mismatch: plugin=${expectedPatternDigest} guardd=${actual || "missing"}`;
      throw new Error(this.capabilityError);
    }
    if (sanitization?.tool_result_persist_required !== true) {
      this.capabilityError = "guardd capability contract does not require tool_result_persist";
      throw new Error(this.capabilityError);
    }
    const llmReview = capabilities.llm_review as Record<string, unknown> | undefined;
    if (llmReview?.enabled === true && llmReview.can_loosen_base_policy !== false) {
      this.capabilityError = "guardd LLM review capability must declare can_loosen_base_policy=false";
      throw new Error(this.capabilityError);
    }
    this.capabilityError = undefined;
  }

  captureTaskPolicy(event: HookEvent, ctx: Record<string, unknown> | undefined): Promise<Record<string, unknown>> {
    const normalized = unifiedEvent(event, ctx, "task.capture", this.config, {
      toolName: "task_policy",
      params: {},
    });
    return this.request<Record<string, unknown>>("/v1/task-policies/capture", {
      schema_version: "1.0",
      request_id: randomUUID(),
      session_key: normalized.session_key,
      parent_session_key: normalized.parent_session_key,
      agent_id: normalized.agent_id,
      prompt: String(event.prompt ?? ""),
      origin: normalized.origin,
    });
  }

  observe(path: string, body: unknown, method = "POST", critical = false): void {
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

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length) {
        const job = this.queue.shift()!;
        try {
          await this.request(job.path, job.body, job.method);
        } catch {
          // Low-risk result/lifecycle details may be discarded during degradation.
        }
      }
    } finally {
      this.draining = false;
      if (this.queue.length) void this.drain();
    }
  }
}
