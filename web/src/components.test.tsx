import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Badge, DataTable, Empty, ErrorState, KeyValue } from "./components";
import { ApiError } from "./api";
import { Countdown } from "./pages/Approvals";

describe("shared UI components", () => {
  it("renders risk and decision badges with text semantics", () => {
    render(<><Badge value="critical" /><Badge value="REQUIRE_APPROVAL" /></>);
    expect(screen.getByText("critical")).toHaveClass("badge-critical");
    expect(screen.getByText("REQUIRE_APPROVAL")).toHaveClass("badge-require-approval");
  });

  it("renders a readable structured error", () => {
    render(<ErrorState error={new ApiError(403, { code: "CSRF_INVALID", message: "令牌无效" })} />);
    expect(screen.getByRole("alert")).toHaveTextContent("CSRF_INVALID：令牌无效");
  });

  it("renders empty and key/value states", () => {
    const { rerender } = render(<Empty title="没有审批" />);
    expect(screen.getByText("没有审批")).toBeInTheDocument();
    rerender(<KeyValue items={[["模式", "observe"]]} />);
    expect(screen.getByText("模式")).toBeInTheDocument();
    expect(screen.getByText("observe")).toBeInTheDocument();
  });

  it("calibrates approval countdown from server time", () => {
    const serverTime = new Date().toISOString();
    const expires = new Date(new Date(serverTime).getTime() + 5_000).toISOString();
    render(<Countdown expires={expires} serverTime={serverTime} />);
    expect(screen.getByText("5s")).toHaveClass("countdown");
  });

  it("opens an accessible table row from the keyboard", () => {
    const open = vi.fn();
    render(<DataTable label="事件列表" rows={[{ event_id: "event-1", name: "测试事件" }]} columns={[{ key: "name", label: "名称" }]} onRow={open} />);
    expect(screen.getByRole("table", { name: "事件列表" })).toBeInTheDocument();
    fireEvent.keyDown(screen.getByRole("row", { name: "测试事件" }), { key: "Enter" });
    expect(open).toHaveBeenCalledOnce();
  });
});
