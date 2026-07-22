import { useQuery } from "@tanstack/react-query";
import { api, formatTime, short } from "../api";
import { Badge, DataTable, Empty, ErrorState, JsonView, Loading, PageHeader, Panel } from "../components";

export default function Sanitization() {
  const metrics = useQuery({ queryKey: ["sanitization", "metrics"], queryFn: () => api<any>("/sanitization/metrics") });
  const events = useQuery({ queryKey: ["sanitization", "events"], queryFn: () => api<any>("/sanitization/events?limit=100") });
  const item = metrics.data?.item;
  return <>
    <PageHeader title="脱敏观测" description="仅展示分类、位置、变换和大小；控制台不会展示原始秘密或稳定的秘密哈希。" />
    <div className="stat-grid">
      {[["脱敏事件", item?.total], ["已阻断", item?.blocked], ["已截断", item?.truncated], ["原始字节", item?.original_size], ["结果字节", item?.result_size]].map(([label, value]) =>
        <article className="stat-card" key={String(label)}><small>{label}</small><strong>{Number(value || 0).toLocaleString()}</strong></article>)}
    </div>
    <Panel title="最近数据通路事件" subtitle="ref 只在单个事件内有效，不能用于跨会话关联秘密">
      {events.isLoading || metrics.isLoading ? <Loading /> : events.error || metrics.error ? <ErrorState error={events.error || metrics.error} /> : events.data?.items?.length ? <DataTable rows={events.data.items} columns={[
        { key: "created_at", label: "时间", render: row => formatTime(row.created_at) },
        { key: "direction", label: "方向", render: row => <Badge value={row.direction} /> },
        { key: "tool_name", label: "工具" },
        { key: "session_key", label: "会话", render: row => <code>{short(row.session_key, 18)}</code> },
        { key: "classifications", label: "分类", render: row => (row.classifications || []).join(", ") || "none" },
        { key: "sizes", label: "大小", render: row => `${row.original_size} → ${row.result_size}` },
        { key: "blocked", label: "结果", render: row => <Badge value={row.blocked ? "blocked" : row.truncated ? "truncated" : "sanitized"} /> },
        { key: "transformations", label: "变换", render: row => <details onClick={event => event.stopPropagation()}><summary>{row.transformations?.length || 0} 项</summary><JsonView value={row.transformations || []} /></details> },
      ]} /> : <Empty title="尚无脱敏事件" />}
    </Panel>
  </>;
}
