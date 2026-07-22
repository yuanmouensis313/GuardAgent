export type SanitizationAction = "preserve" | "redact" | "drop" | "late_bind" | "block" | "require_approval";

export type Transformation = {
  json_path: string;
  classification: string;
  length: number;
  source: string;
  proposed_action: SanitizationAction;
  ref: string;
};

export type SanitizationResult<T = unknown> = {
  value: T;
  classifications: string[];
  transformations: Transformation[];
  original_size: number;
  result_size: number;
  truncated: boolean;
};

const SENSITIVE_KEY = new RegExp(SENSITIVE_FIELD_TOKENS.map((item) => item.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "i");
const SECRET_PATTERNS = GENERATED_SECRET_PATTERNS;

const byteLength = (value: unknown) => Buffer.byteLength(typeof value === "string" ? value : JSON.stringify(value) ?? String(value), "utf8");

function truncateUtf8(value: string, maxBytes: number): { value: string; truncated: boolean } {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return { value, truncated: false };
  let low = 0; let high = value.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(value.slice(0, middle), "utf8") <= maxBytes) low = middle;
    else high = middle - 1;
  }
  return { value: `${value.slice(0, low)}\n<GUARD_TRUNCATED unscanned_tail_removed="true">`, truncated: true };
}

export function sanitizeValue<T = unknown>(input: T, maxScanBytes = SANITIZATION_MAX_SCAN_BYTES): SanitizationResult<T> {
  const transformations: Transformation[] = [];
  let counter = 0;
  let truncated = false;
  const marker = (kind: string, length: number) => `<GUARD_REDACTED type="${kind}" length="${length}" ref="event-local-${++counter}">`;

  const walk = (value: unknown, path: string, key = ""): unknown => {
    if (SENSITIVE_KEY.test(key)) {
      const length = byteLength(value);
      const ref = `event-local-${counter + 1}`;
      transformations.push({ json_path: path, classification: "sensitive_field", length, source: "field-name", proposed_action: "redact", ref });
      return marker("sensitive_field", length);
    }
    if (typeof value === "string") {
      const bounded = truncateUtf8(value, maxScanBytes);
      truncated ||= bounded.truncated;
      let output = bounded.value;
      for (const [kind, pattern] of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        output = output.replace(pattern, (match) => {
          const ref = `event-local-${counter + 1}`;
          transformations.push({ json_path: path, classification: kind, length: Buffer.byteLength(match, "utf8"), source: "value-pattern", proposed_action: "redact", ref });
          return marker(kind, Buffer.byteLength(match, "utf8"));
        });
      }
      return output;
    }
    if (value instanceof Uint8Array) {
      const ref = `event-local-${counter + 1}`;
      transformations.push({ json_path: path, classification: "binary", length: value.byteLength, source: "binary-value", proposed_action: "drop", ref });
      return marker("binary", value.byteLength);
    }
    if (Array.isArray(value)) return value.map((item, index) => walk(item, `${path}[${index}]`));
    if (value && typeof value === "object") {
      const output: Record<string, unknown> = {};
      for (const [childKey, childValue] of Object.entries(value)) {
        output[childKey] = walk(childValue, `${path}.${childKey}`, childKey);
      }
      return output;
    }
    return value;
  };

  const value = walk(input, "$") as T;
  return {
    value,
    classifications: [...new Set(transformations.map((item) => item.classification))].sort(),
    transformations,
    original_size: byteLength(input),
    result_size: byteLength(value),
    truncated,
  };
}

function tagText(value: string, toolName: string): string {
  const safeTool = toolName.replace(/["<>]/g, "_").slice(0, 128);
  if (value.startsWith("<UNTRUSTED_TOOL_CONTENT ")) return value;
  return `<UNTRUSTED_TOOL_CONTENT tool="${safeTool}" trust="untrusted_external">\n${value}\n</UNTRUSTED_TOOL_CONTENT>`;
}

export function sanitizeToolMessage(message: unknown, toolName = "unknown"): SanitizationResult<unknown> {
  const result = sanitizeValue(message);
  const value = result.value;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    if (typeof record.content === "string") record.content = tagText(record.content, toolName);
    if (Array.isArray(record.content)) {
      record.content = record.content.map((block) => {
        if (!block || typeof block !== "object") return block;
        const copy = { ...(block as Record<string, unknown>) };
        if (typeof copy.text === "string") copy.text = tagText(copy.text, toolName);
        return copy;
      });
    }
    if (typeof record.text === "string") record.text = tagText(record.text, toolName);
  }
  result.result_size = byteLength(result.value);
  return result;
}
import {
  GENERATED_SECRET_PATTERNS,
  SANITIZATION_MAX_SCAN_BYTES,
  SENSITIVE_FIELD_TOKENS,
} from "./generated-sanitization-patterns.js";
