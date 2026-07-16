import { useState } from "react";
import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Drawer, Empty, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

export default function Sessions() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [selected, setSelected] = useState<string | undefined>(() => searchParams.get("session") || undefined);
  const query = useInfiniteQuery({
    queryKey: ["sessions"], initialPageParam: "",
    queryFn: ({ pageParam }) => api<any>(`/sessions?limit=50${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    getNextPageParam: last => last.next_cursor || undefined,
  });
  const detail = useQuery({ queryKey: ["session", selected], queryFn: () => api<any>(`/sessions/${encodeURIComponent(selected!)}`), enabled: !!selected });
  const replay = useMutation({ mutationFn: () => api<any>(`/sessions/${encodeURIComponent(selected!)}/replay`, { method: "POST", body: postBody() }) });
  const rows = query.data?.pages.flatMap(page => page.items) || [];
  const selectSession = (sessionKey?: string) => {
    setSelected(sessionKey); replay.reset(); const next = new URLSearchParams(searchParams);
    if (sessionKey) next.set("session", sessionKey); else next.delete("session"); setSearchParams(next, { replace: true });
  };
  return <>
    <PageHeader title="会话" description="从会话维度查看行为时间线、风险累积和当前策略重放结果。" />
    <Panel>{query.isLoading ? <Loading /> : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} /> : <>
      <DataTable rows={rows} onRow={row => selectSession(row.session_key)} columns={[
        { key: "started_at", label: "开始时间", render: row => formatTime(row.started_at) },
        { key: "last_seen", label: "最近活动", render: row => formatTime(row.last_seen) },
        { key: "session_key", label: "会话", render: row => <code>{short(row.session_key, 20)}</code> },
        { key: "agent_id", label: "Agent" },
        { key: "status", label: "状态", render: row => <Badge value={row.status} /> },
        { key: "event_count", label: "事件" },
        { key: "max_risk", label: "最高风险", render: row => <Badge value={row.max_risk} /> },
        { key: "deny_count", label: "拒绝" },
        { key: "pending_approvals", label: "待审批" },
      ]} />
      {query.hasNextPage && <div className="load-more"><button className="button ghost" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{query.isFetchingNextPage ? "正在加载…" : "加载更多"}</button></div>}
    </>}</Panel>
    {selected && <Drawer title="会话详情" onClose={() => setSelected(undefined)}>{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : (() => {
      const item = detail.data?.item; if (!item) return null;
      return <div className="detail-stack">
        <KeyValue items={[
          ["会话", <code>{item.session_key}</code>],
          ["状态", <Badge value={item.state?.status || "inferred"} />],
          ["累计风险分", item.risk_score],
          ["读/写字节摘要", `${Number(item.io_summary?.read_bytes || 0).toLocaleString()} / ${Number(item.io_summary?.write_bytes || 0).toLocaleString()}`],
          ["工具分布", Object.entries(item.tool_counts || {}).map(([key, value]) => `${key}: ${value}`).join(" · ")],
          ["规则分布", Object.entries(item.rule_counts || {}).map(([key, value]) => `${key}: ${value}`).join(" · ")],
        ]} />
        <div className="inline-actions"><button className="button primary" disabled={replay.isPending} onClick={() => replay.mutate()}>按当前策略重放</button><a className="button ghost" href={`/v1/ui/sessions/${encodeURIComponent(item.session_key)}/export`}>导出脱敏 JSON</a></div>
        {replay.isPending && <Loading label="正在重放…" />}{replay.error && <ErrorState error={replay.error} />}{replay.data && <><h3>重放结果</h3><JsonView value={replay.data.item} /></>}
        <h3>时间线{item.timeline_truncated ? `（显示 ${item.timeline.length}/${item.timeline_total}）` : ""}</h3>
        {item.timeline?.length ? <div className="timeline">{item.timeline.map((entry: any, index: number) => <article key={entry.event?.event_id || index}><span className={`timeline-dot ${entry.risk || "info"}`} /><div><div><strong>{entry.event?.event_type}</strong><Badge value={entry.decision || "none"} />{entry.would_decide && <Badge value={entry.would_decide} />}<Badge value={entry.risk || "none"} /></div><small>{formatTime(entry.event?.occurred_at)} · {entry.event?.tool?.name || "lifecycle"}</small><p>{entry.reason || "无决策原因"}</p></div></article>)}</div> : <Empty />}
      </div>;
    })()}</Drawer>}
  </>;
}
