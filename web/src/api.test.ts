import { describe, expect, it, vi } from "vitest";
import { api, ApiError, formatTime, short } from "./api";

describe("API helpers", () => {
  it("shortens identifiers without exposing the full value", () => {
    expect(short("abcdefghijklmnopqrstuvwxyz", 8)).toBe("abcdefgh…");
    expect(short("short", 8)).toBe("short");
    expect(short(null)).toBe("—");
  });

  it("formats valid timestamps and preserves invalid input", () => {
    expect(formatTime("not-a-date")).toBe("not-a-date");
    expect(formatTime(null)).toBe("—");
    expect(formatTime("2026-07-15T00:00:00Z")).not.toBe("2026-07-15T00:00:00Z");
  });

  it("creates structured API errors", () => {
    const error = new ApiError(409, { code: "DIGEST_CONFLICT", message: "conflict", details: { current: "x" } });
    expect(error.status).toBe(409);
    expect(error.code).toBe("DIGEST_CONFLICT");
    expect(error.details.current).toBe("x");
  });

  it("announces an expired authenticated UI session", async () => {
    const expired = vi.fn();
    window.addEventListener("guard-session-expired", expired);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "SESSION_EXPIRED", message: "expired" } }), { status: 401 })));
    await expect(api("/events")).rejects.toMatchObject({ code: "SESSION_EXPIRED" });
    expect(expired).toHaveBeenCalledOnce();
    window.removeEventListener("guard-session-expired", expired);
    vi.unstubAllGlobals();
  });
});
