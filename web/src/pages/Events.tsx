import { FormEvent, useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, formatTime, short } from "../api";
import { Badge, DataTable, Drawer, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

type EventFilters = {
  q: string; risk: string; decision: string; would_decide: string; tool: string; agent: string;
  session_key: string; event_type: string; rule_id: string; has_approval: string;
  success: string; since: string; until: string;
};
const initialFilters: EventFilters = {
  q: "", risk: "", decision: "", would_decide: "", tool: "", agent: "", session_key: "",
  event_type: "", rule_id: "", has_approval: "", success: "", since: "", until: "",
};
function filtersFrom(params: URLSearchParams): EventFilters {
  return Object.fromEntries(Object.keys(initialFilters).map(key => [key, params.get(key) || ""])) as EventFilters;
}
function searchFor(filters: EventFilters, cursor?: string) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value) params.set(key, key === "since" || key === "until" ? new Date(value).toISOString() : value);
  });
  params.set("limit", "50"); if (cursor) params.set("cursor", cursor); return params.toString();
}

export default function Events() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<EventFilters>(() => filtersFrom(searchParams));
  const [applied, setApplied] = useState<EventFilters>(() => filtersFrom(searchParams));
  const [selected, setSelected] = useState<string | undefined>(() => searchParams.get("event") || undefined);
  const query = useInfiniteQuery({ queryKey: ["events", applied], initialPageParam: "", queryFn: ({ pageParam }) => api<any>(`/events?${searchFor(applied, pageParam)}`), getNextPageParam: last => last.next_cursor || undefined });
  const detail = useQuery({ queryKey: ["event", selected], queryFn: () => api<any>(`/events/${selected}`), enabled: !!selected });
  const rows = query.data?.pages.flatMap(page => page.items) || [];
  const update = (key: keyof EventFilters, value: string) => setFilters(current => ({ ...current, [key]: value }));
  const submit = (event: FormEvent) => { event.preventDefault(); setApplied({ ...filters }); setSearchParams(Object.fromEntries(Object.entries(filters).filter(([, value]) => value))); };
  const reset = () => { setFilters(initialFilters); setApplied(initialFilters); setSearchParams({}); };
  const selectEvent = (eventId?: string) => {
    setSelected(eventId); const next = new URLSearchParams(searchParams);
    if (eventId) next.set("event", eventId); else next.delete("event"); setSearchParams(next, { replace: true });
  };
  return <>
    <PageHeader title="事件中心" description="检索已脱敏的事件、规则命中、判定与工具执行结果。" />
    <Panel className="filter-panel"><form className="filters filters-expanded" onSubmit={submit}>
      <input placeholder="搜索工具、会话、原因、规则或脱敏目标" value={filters.q} onChange={event => update("q", event.target.value)} />
      <select value={filters.risk} onChange={event => update("risk", event.target.value)}><option value="">全部风险</option>{["info", "low", "medium", "high", "critical"].map(value => <option key={value}>{value}</option>)}</select>
      <select value={filters.decision} onChange={event => update("decision", event.target.value)}><option value="">全部有效决策</option>{["ALLOW", "DENY", "REQUIRE_APPROVAL", "OBSERVE"].map(value => <option key={value}>{value}</option>)}</select>
      <select value={filters.would_decide} onChange={event => update("would_decide", event.target.value)}><option value="">全部建议决策</option>{["ALLOW", "DENY", "REQUIRE_APPROVAL"].map(value => <option key={value}>{value}</option>)}</select>
      <input placeholder="工具名称" value={filters.tool} onChange={event => update("tool", event.target.value)} /><input placeholder="Agent ID" value={filters.agent} onChange={event => update("agent", event.target.value)} /><input placeholder="Session Key" value={filters.session_key} onChange={event => update("session_key", event.target.value)} /><input placeholder="事件类型" value={filters.event_type} onChange={event => update("event_type", event.target.value)} /><input placeholder="规则 ID" value={filters.rule_id} onChange={event => update("rule_id", event.target.value)} />
      <select value={filters.has_approval} onChange={event => update("has_approval", event.target.value)}><option value="">全部审批状态</option><option value="true">有审批</option><option value="false">无审批</option></select>
      <select value={filters.success} onChange={event => update("success", event.target.value)}><option value="">全部执行结果</option><option value="true">执行成功</option><option value="false">执行失败</option></select>
      <label className="compact-label">起始时间<input type="datetime-local" value={filters.since} onChange={event => update("since", event.target.value)} /></label><label className="compact-label">结束时间<input type="datetime-local" value={filters.until} onChange={event => update("until", event.target.value)} /></label>
      <div className="filter-actions"><button className="button primary" type="submit">应用筛选</button><button className="button ghost" type="button" onClick={reset}>清空</button></div>
    </form></Panel>
    <Panel>{query.isLoading ? <Loading /> : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} /> : <>
      <DataTable rows={rows} onRow={row => selectEvent(row.event_id)} columns={[
        { key: "occurred_at", label: "时间", render: row => formatTime(row.occurred_at) }, { key: "event_type", label: "事件" }, { key: "tool_name", label: "工具" },
        { key: "agent_id", label: "Agent / Session", render: row => <>{short(row.agent_id, 14)}<br /><code>{short(row.session_key, 14)}</code></> },
        { key: "decision", label: "有效 / 建议决策", render: row => <><Badge value={row.decision || "none"} />{row.would_decide && <> <Badge value={row.would_decide} /></>}</> },
        { key: "risk", label: "风险", render: row => <Badge value={row.risk || "none"} /> }, { key: "rule_ids", label: "规则", render: row => short((row.rule_ids || []).join(", "), 36) },
        { key: "tool_success", label: "结果", render: row => row.tool_success == null ? "—" : row.tool_success ? "成功" : "失败" },
      ]} />
      {query.hasNextPage && <div className="load-more"><button className="button ghost" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{query.isFetchingNextPage ? "正在加载…" : "加载更多"}</button></div>}
    </>}</Panel>
    {selected && <Drawer title="事件审计详情" onClose={() => selectEvent()}>{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : (() => {
      const item = detail.data?.item; if (!item) return null;
      return <div className="detail-stack"><div className="detail-hero"><Badge value={item.decision || "none"} />{item.would_decide && <Badge value={item.would_decide} />}<Badge value={item.risk || "none"} /><code>{short(item.event_id, 18)}</code></div>
        <KeyValue items={[["发生时间", formatTime(item.occurred_at)], ["事件类型", item.event_type], ["工具", item.tool_name || "—"], ["Agent", item.agent_id], ["会话", <code>{item.session_key}</code>], ["规则", item.rule_ids.map((value: string) => <code key={value}>{value} </code>)], ["原因", item.reason || "—"], ["策略", <code>{short(item.policy_digest, 24)}</code>], ["数据分类", (item.event?.data_classification || []).join(", ") || "none"], ["审计哈希", <code>{item.event_hash}</code>], ["前序哈希", <code>{item.previous_hash || "genesis"}</code>]]} />
        <div className="inline-actions"><button className="button ghost" onClick={() => navigate(`/policy?event=${item.event_id}`)}>用此脱敏事件模拟策略</button><button className="text-button" onClick={() => navigate(`/sessions?session=${encodeURIComponent(item.session_key)}`)}>查看会话</button></div>
        <h3>归一化事件（已脱敏）</h3><JsonView value={item.event} /><h3>工具结果</h3><JsonView value={item.tool_results} />{item.approval && <><h3>审批</h3><JsonView value={item.approval} /></>}
      </div>;
    })()}</Drawer>}
  </>;
}
