export type GuardConfig = {
  serviceUrl: string;
  tokenFile: string;
  workspaceRoot: string;
  timeoutMs?: number;
  gatewayId?: string;
  observeInputInjection?: boolean;
  captureTaskPolicy?: boolean;
  sanitizationMode?: "disabled" | "observe" | "enforce";
  contentInspectionMode?: "disabled" | "observe" | "enforce";
  skillRoots?: string[];
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
  execution_params?: Record<string, unknown> | null;
  transformation_plan?: Array<{ classification: string; action: string; scope?: string; source?: string }>;
  transformation_digest?: string | null;
  task_policy_digest?: string | null;
  task_policy_revision?: number | null;
  task_policy_verdict?: string | null;
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
  parentSessionKey?: string;
  message?: unknown;
  contentKind?: "native" | "skill" | "mcp";
  contentName?: string;
  contentDigest?: string;
  artifactDigest?: string;
  serverIdentity?: string;
  contentSourcePath?: string;
};
