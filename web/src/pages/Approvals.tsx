import { useEffect, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Drawer, Empty, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

export function Countdown({ expires, serverTime }: { expires: string; serverTime?: string }) {
  const [now, setNow] = useState(() => Date.now());
  const offset = serverTime ? new Date(serverTime).getTime() - Date.now() : 0;
  useEffect(() => { const id = window.setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(id); }, []);
  const seconds = Math.max(0, Math.ceil((new Date(expires).getTime() - (now + offset)) / 1000));
  return <span className={seconds < 10 ? "countdown urgent" : "countdown"}>{seconds > 0 ? `${seconds}s` : "已到期"}</span>;
}

export default function Approvals() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [status, setStatus] = useState(searchParams.get("status") || "pending");
  const [risk, setRisk] = useState(searchParams.get("risk") || "");
  const [selected, setSelected] = useState<string | undefined>(() => searchParams.get("approval") || undefined);
  const [confirmed, setConfirmed] = useState(false);
  const client = useQueryClient();
  const query = useInfiniteQuery({
    queryKey: ["approvals", status, risk], initialPageParam: "",
    queryFn: ({ pageParam }) => api<any>(`/approvals?status=${status}&limit=50${risk ? `&risk=${risk}` : ""}${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    getNextPageParam: last => last.next_cursor || undefined,
    refetchInterval: status === "pending" ? 2_000 : 10_000,
  });
  const detail = useQuery({ queryKey: ["approval", selected], queryFn: () => api<any>(`/approvals/${selected}`), enabled: !!selected });
  const mutation = useMutation({
    mutationFn: (action: "allow-once" | "deny") => api<any>(`/approvals/${selected}/${action}`, { method: "POST", body: postBody() }),
    onSettled: async () => { await client.invalidateQueries({ queryKey: ["approvals"] }); await detail.refetch(); setConfirmed(false); },
  });
  const rows = query.data?.pages.flatMap(page => page.items) || [];
  const serverTime = query.data?.pages[0]?.server_time;
  const selectApproval = (approvalId?: string) => {
    setSelected(approvalId); setConfirmed(false);
    const next = new URLSearchParams(searchParams);
    if (approvalId) next.set("approval", approvalId); else next.delete("approval");
    setSearchParams(next, { replace: true });
  };
  const changeStatus = (value: string) => {
    setStatus(value); setSelected(undefined); setConfirmed(false);
    const next = new URLSearchParams(); next.set("status", value); if (risk) next.set("risk", risk); setSearchParams(next);
  };
  const changeRisk = (value: string) => {
    setRisk(value); const next = new URLSearchParams(); next.set("status", status); if (value) next.set("risk", value); setSearchParams(next);
  };
  return <>
    <PageHeader title="审批中心" description="核对脱敏后的工具、目标与参数绑定，只对当前操作做一次性决定。" actions={<div className="approval-filters"><div className="segmented">{["pending", "allowed_once", "denied", "expired", "consumed", "invalidated_restart"].map(item => <button className={status === item ? "active" : ""} key={item} onClick={() => changeStatus(item)}>{item}</button>)}</div><select aria-label="按风险筛选" value={risk} onChange={e => changeRisk(e.target.value)}><option value="">全部风险</option>{["info", "low", "medium", "high", "critical"].map(item => <option key={item}>{item}</option>)}</select></div>} />
    <div className="notice warning"><strong>没有永久允许</strong><span>GuardAgent 只支持 allow-once 和 deny；审批结果仍需与相同参数摘要、agent、session 和 sender 绑定。</span></div>
    <Panel>{query.isLoading ? <Loading /> : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} /> : rows.length ? <>
      <DataTable rows={rows} onRow={row => selectApproval(row.approval_id)} columns={[
        { key: "approval_id", label: "审批 ID", render: row => <code>{short(row.approval_id, 14)}</code> },
        { key: "risk", label: "风险", render: row => <Badge value={row.risk} /> },
        { key: "status", label: "状态", render: row => <Badge value={row.status} /> },
        { key: "tool", label: "工具 / 目标", render: row => <>{row.display?.tool?.name || "—"}<br /><small>{short(JSON.stringify(row.display?.targets || {}), 38)}</small></> },
        { key: "identity", label: "Agent / Session / Sender", render: row => <>{short(row.display?.agent, 14)}<br /><code>{short(row.display?.session, 14)}</code><br /><small>{short(`${row.display?.channel || "—"}:${row.display?.sender || "—"}`, 24)}</small></> },
        { key: "rules", label: "规则 / 原因", render: row => <>{short((row.rule_ids || []).join(", "), 28)}<br /><small>{short(row.reason, 42)}</small></> },
        { key: "created", label: "创建 / 剩余", render: row => <>{formatTime(row.created_at || row.expires_at)}<br />{row.status === "pending" ? <Countdown expires={row.expires_at} serverTime={serverTime} /> : formatTime(row.expires_at)}</> },
      ]} />
      {query.hasNextPage && <div className="load-more"><button className="button ghost" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{query.isFetchingNextPage ? "正在加载…" : "加载更多"}</button></div>}
    </> : <Empty title="没有符合条件的审批" />}</Panel>
    {selected && <Drawer title="审批详情" onClose={() => selectApproval()}>{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : (() => {
      const item = detail.data?.item; if (!item) return null; const allowed: string[] = item.display?.allowed_decisions || [];
      return <div className="detail-stack"><div className="detail-hero"><Badge value={item.risk} /><Badge value={item.status} /><code>{short(item.approval_id, 18)}</code></div>
        <KeyValue items={[["原因", item.reason], ["规则", item.rule_ids.map((x: string) => <code key={x}>{x} </code>)], ["服务端时间", formatTime(detail.data.server_time)], ["到期", formatTime(item.expires_at)], ["参数摘要", <code>{item.parameter_digest}</code>], ["操作者", item.operator || "尚未处理"]]} />
        <div className="inline-actions"><button className="text-button" onClick={() => navigate(`/events?event=${item.event_id}`)}>查看关联事件</button></div>
        <h3>已脱敏的操作上下文</h3><JsonView value={item.display} />
        {item.status === "pending" && <div className="approval-actions"><label className="confirm-check"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />我已核对工具、目标和参数摘要</label><div>{allowed.includes("deny") && <button className="button danger" disabled={mutation.isPending} onClick={() => { if (window.confirm("确认拒绝这次操作？该决定无法撤销。")) mutation.mutate("deny"); }}>拒绝</button>}{allowed.includes("allow-once") && <button className="button neutral" disabled={!confirmed || mutation.isPending} onClick={() => { if (window.confirm("确认仅允许这一次完全相同的操作？")) mutation.mutate("allow-once"); }}>允许一次</button>}</div>{mutation.error && <ErrorState error={mutation.error} />}</div>}
      </div>;
    })()}</Drawer>}
  </>;
}
