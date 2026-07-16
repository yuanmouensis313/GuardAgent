export type ApiErrorBody = { code?: string; message?: string; request_id?: string; details?: Record<string, unknown> };

export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message || `请求失败（${status}）`);
    this.status = status;
    this.code = body.code || "REQUEST_FAILED";
    this.details = body.details || {};
  }
}

let csrfToken = "";

export function setCsrf(value: string | undefined) {
  csrfToken = value || "";
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method || "GET").toUpperCase();
  const unsafe = !["GET", "HEAD", "OPTIONS"].includes(method);
  const headers = new Headers(init.headers);
  if (!headers.has("X-Request-ID")) headers.set("X-Request-ID", crypto.randomUUID());
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (unsafe && csrfToken) headers.set("X-Guard-CSRF", csrfToken);
  const response = await fetch(`/v1/ui${path}`, { ...init, headers, credentials: "same-origin" });
  const text = await response.text();
  let body: any = {};
  if (text) {
    try { body = JSON.parse(text); } catch { body = { detail: text }; }
  }
  if (!response.ok) {
    const detail = body?.detail && typeof body.detail === "object" ? body.detail : body?.error || { message: body?.detail || response.statusText };
    if (response.status === 401 && path !== "/auth/session") window.dispatchEvent(new Event("guard-session-expired"));
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

export const requestId = () => `ui-${crypto.randomUUID()}`;
export const postBody = (payload: Record<string, unknown> = {}) => JSON.stringify({ schema_version: "1.0", request_id: requestId(), ...payload });

export type SessionInfo = {
  operator: string;
  csrf_token: string;
  created_at: string;
  last_seen: string;
  expires_at: string;
  server_time: string;
};

export async function restoreSession() {
  const result = await api<SessionInfo>("/auth/session");
  setCsrf(result.csrf_token);
  return result;
}

export async function consumeBootstrap(code: string) {
  const result = await api<SessionInfo>("/auth/session", { method: "POST", body: postBody({ code }) });
  setCsrf(result.csrf_token);
  return result;
}

export function short(value?: string | null, length = 12) {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

export function formatTime(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat("zh-CN", { dateStyle: "short", timeStyle: "medium" }).format(date);
}
