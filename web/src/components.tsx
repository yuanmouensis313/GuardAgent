import { ReactNode, useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { LineChart, PieChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";
import { ApiError, formatTime, short } from "./api";

echarts.use([LineChart, PieChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

export function Badge({ value, kind }: { value?: string | null; kind?: string }) {
  const normalized = (kind || value || "unknown").toLowerCase().replaceAll("_", "-");
  return <span className={`badge badge-${normalized}`}>{value || "unknown"}</span>;
}

export function PageHeader({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return <header className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</header>;
}

export function Panel({ title, subtitle, children, className = "" }: { title?: string; subtitle?: string; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{title && <div className="panel-title"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div></div>}<div className="panel-body">{children}</div></section>;
}

export function Metric({ label, value, note, tone = "" }: { label: string; value: ReactNode; note?: string; tone?: string }) {
  return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong>{note && <small>{note}</small>}</div>;
}

export function Empty({ title = "暂无数据", description = "当前筛选条件下没有记录。" }: { title?: string; description?: string }) {
  return <div className="empty"><span aria-hidden>◇</span><strong>{title}</strong><p>{description}</p></div>;
}

export function Loading({ label = "正在加载…" }: { label?: string }) {
  return <div className="loading" role="status"><i /><span>{label}</span></div>;
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof ApiError ? `${error.code}：${error.message}` : error instanceof Error ? error.message : "发生未知错误";
  return <div className="error-state" role="alert"><strong>无法完成请求</strong><p>{message}</p>{onRetry && <button className="button ghost" onClick={onRetry}>重试</button>}</div>;
}

export function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}

export function Chart({ option, label, height = 260 }: { option: EChartsCoreOption; label: string; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: "canvas" });
    chart.setOption(option);
    const resize = () => chart.resize();
    window.addEventListener("resize", resize);
    return () => { window.removeEventListener("resize", resize); chart.dispose(); };
  }, [option]);
  return <div ref={ref} role="img" aria-label={label} style={{ height }} />;
}

export function DataTable({ columns, rows, onRow, label = "数据表" }: { columns: Array<{ key: string; label: string; render?: (row: any) => ReactNode }>; rows: any[]; onRow?: (row: any) => void; label?: string }) {
  if (!rows.length) return <Empty />;
  return <div className="table-wrap"><table aria-label={label}><thead><tr>{columns.map(c => <th key={c.key}>{c.label}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={row.event_id || row.approval_id || row.session_key || row.id || index} onClick={() => onRow?.(row)} className={onRow ? "clickable" : ""} tabIndex={onRow ? 0 : undefined} onKeyDown={e => { if (onRow && (e.key === "Enter" || e.key === " ")) onRow(row); }}>{columns.map(c => <td key={c.key}>{c.render ? c.render(row) : row[c.key] ?? "—"}</td>)}</tr>)}</tbody></table></div>;
}

export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const drawerRef = useRef<HTMLElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  useEffect(() => {
    previousFocus.current = document.activeElement as HTMLElement | null;
    const focusable = () => Array.from(drawerRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])') || []);
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "Tab") {
        const items = focusable();
        if (!items.length) { event.preventDefault(); drawerRef.current?.focus(); return; }
        const first = items[0], last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", handler);
    window.requestAnimationFrame(() => (focusable()[0] || drawerRef.current)?.focus());
    return () => { window.removeEventListener("keydown", handler); previousFocus.current?.focus(); };
  }, [onClose]);
  return <div className="drawer-backdrop" onMouseDown={e => { if (e.currentTarget === e.target) onClose(); }}><aside ref={drawerRef} tabIndex={-1} className="drawer" role="dialog" aria-modal="true" aria-label={title}><header><h2>{title}</h2><button className="icon-button" onClick={onClose} aria-label="关闭">×</button></header><div className="drawer-content">{children}</div></aside></div>;
}

export function KeyValue({ items }: { items: Array<[string, ReactNode]> }) {
  return <dl className="key-value">{items.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>;
}

export const cell = {
  time: (row: any) => formatTime(row.occurred_at || row.created_at || row.last_seen || row.expires_at),
  id: (field: string) => (row: any) => <code>{short(row[field])}</code>,
  badge: (field: string) => (row: any) => <Badge value={row[field]} />,
};
