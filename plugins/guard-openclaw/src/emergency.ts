import { isAbsolute, relative, resolve } from "node:path";
import type { GuardConfig, HookEvent } from "./types.js";

const WRITE_TOOLS = new Set(["write", "edit", "apply_patch", "delete", "remove", "move", "copy"]);
const READ_TOOLS = new Set(["read", "search", "glob", "list"]);
const SENSITIVE = /(\.env(?:\.|$)|[\\/]\.ssh[\\/]|id_(?:rsa|ed25519)|credentials|exec-approvals\.json|\.openclaw[\\/].*(?:config|approval))/i;
const DYNAMIC = /(?:-encodedcommand|\b(?:python(?:3)?\s+-c|node\s+(?:-e|--eval)|invoke-expression|\biex\b|eval\s)|\$\(|`)/i;
const EXFIL = /(?:message|send|email|upload|webhook)/i;
const SECURITY = /(?:guardagent|exec-approvals\.json|installpolicy|sandbox|security[= ]full|ask[= ]off|tools\.elevated|yolo)/i;

export type EmergencyDecision = { kind: "allow" | "deny" | "approval"; reason: string; risk: "low" | "high" | "critical" };

function strings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value && typeof value === "object") return Object.values(value).flatMap(strings);
  return [];
}

function inside(candidate: string, workspace: string): boolean {
  const absolute = resolve(workspace, candidate);
  const rel = relative(resolve(workspace), absolute);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export function emergencyDecision(event: HookEvent, config: GuardConfig, outbound = false): EmergencyDecision {
  const tool = String(event.toolName ?? "unknown").toLowerCase();
  const values = strings(event.params ?? {});
  const joined = values.join(" ");
  if (outbound || EXFIL.test(tool)) return { kind: "deny", reason: "guardd unavailable: outbound action failed closed", risk: "critical" };
  if (SECURITY.test(joined)) return { kind: "deny", reason: "guardd unavailable: security configuration is protected", risk: "critical" };
  if (DYNAMIC.test(joined)) return { kind: "deny", reason: "guardd unavailable: dynamic execution failed closed", risk: "critical" };
  if (event.params?.elevated === true || event.params?.host === "gateway" || event.params?.host === "node") {
    return { kind: "deny", reason: "guardd unavailable: host or elevated execution failed closed", risk: "critical" };
  }
  if (WRITE_TOOLS.has(tool)) {
    const paths = values.filter((value) => /(?:[\\/]|^[A-Za-z]:)/.test(value));
    if (!paths.length || paths.some((path) => !inside(path, config.workspaceRoot) || SENSITIVE.test(path))) {
      return { kind: "deny", reason: "guardd unavailable: unverified or external write failed closed", risk: "critical" };
    }
    return { kind: "approval", reason: "guardd unavailable: workspace write requires native one-time approval", risk: "high" };
  }
  if (READ_TOOLS.has(tool)) {
    const paths = values.filter((value) => /(?:[\\/]|^[A-Za-z]:)/.test(value));
    if (paths.length && paths.every((path) => inside(path, config.workspaceRoot) && !SENSITIVE.test(path))) {
      return { kind: "allow", reason: "guardd unavailable: embedded workspace-read allowlist", risk: "low" };
    }
    return { kind: "deny", reason: "guardd unavailable: external or sensitive read failed closed", risk: "critical" };
  }
  return { kind: "approval", reason: "guardd unavailable: native one-time approval required", risk: "high" };
}
