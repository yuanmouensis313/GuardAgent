export type GuardConfig = {
  serviceUrl: string;
  tokenFile: string;
  workspaceRoot: string;
  timeoutMs?: number;
  gatewayId?: string;
  observeInputInjection?: boolean;
};

export type GuardDecision = {
  decision_id: string;
  event_id: string;
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "OBSERVE";
  would_decide?: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "OBSERVE" | null;
  risk: "info" | "low" | "medium" | "high" | "critical";
  rule_ids: string[];
  reason: string;
  parameter_digest: string;
  approval_id?: string | null;
  expires_at?: string | null;
  rewritten_params?: Record<string, unknown> | null;
};

export type HookEvent = Record<string, unknown> & {
  context?: Record<string, unknown>;
  toolName?: string;
  toolKind?: string;
  toolInputKind?: string;
  toolCallId?: string;
  runId?: string;
  params?: Record<string, unknown>;
  derivedPaths?: readonly string[];
  content?: string;
  payload?: Record<string, unknown>;
};
