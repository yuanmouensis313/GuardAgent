import { useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Drawer, Empty, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

export default function Sessions() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selected, setSelected] = useState<string | undefined>(() => searchParams.get("session") || undefined);
  const query = useInfiniteQuery({
    queryKey: ["sessions"], initialPageParam: "",
    queryFn: ({ pageParam }) => api<any>(`/sessions?limit=50${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    getNextPageParam: last => last.next_cursor || undefined,
  });
  const detail = useQuery({ queryKey: ["session", selected], queryFn: () => api<any>(`/sessions/${encodeURIComponent(selected!)}`), enabled: !!selected });
  const taskPolicy = useQuery({ queryKey: ["task-policy", selected], queryFn: () => api<any>(`/sessions/${encodeURIComponent(selected!)}/task-policy`), enabled: !!selected });
  const taskGenerations = useQuery({ queryKey: ["task-policy-generations", selected], queryFn: () => api<any>(`/task-policy-generations?session_key=${encodeURIComponent(selected!)}&limit=20`), enabled: !!selected, refetchInterval: 3000 });
  const safetyMemory = useQuery({ queryKey: ["safety-memory", selected], queryFn: () => api<any>(`/sessions/${encodeURIComponent(selected!)}/safety-memory`), enabled: !!selected });
  const replay = useMutation({ mutationFn: () => api<any>(`/sessions/${encodeURIComponent(selected!)}/replay`, { method: "POST", body: postBody() }) });
  const activateTask = useMutation({
    mutationFn: (candidate: any) => api<any>(`/sessions/${encodeURIComponent(selected!)}/task-policy/activate`, {
      method: "POST", body: postBody({ candidate_digest: candidate.policy_digest, expected_active_revision: taskPolicy.data?.item?.active?.revision ?? null }),
    }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["task-policy", selected] }); },
  });
  const rejectTask = useMutation({
    mutationFn: (candidate: any) => api<any>(`/sessions/${encodeURIComponent(selected!)}/task-policy/reject`, {
      method: "POST", body: postBody({ candidate_digest: candidate.policy_digest }),
    }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["task-policy", selected] }); },
  });
  const retryGeneration = useMutation({
    mutationFn: (generationId: string) => api<any>(`/task-policy-generations/${encodeURIComponent(generationId)}/retry`, { method: "POST", body: postBody() }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["task-policy-generations", selected] }); },
  });
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
        <small>重放仅覆盖原本经过策略判定的动作，并使用审计中保存的脱敏规范化证据；生命周期事件不参与重放。</small>
        {replay.isPending && <Loading label="正在重放…" />}{replay.error && <ErrorState error={replay.error} />}{replay.data && <><h3>重放结果</h3><JsonView value={replay.data.item} /></>}
        <h3>会话任务策略 R_task</h3>
        {taskPolicy.isLoading ? <Loading label="正在读取 R_task…" /> : taskPolicy.error ? <ErrorState error={taskPolicy.error} /> : !taskPolicy.data?.item ? <Empty title="此会话尚无 R_task" /> : (() => {
          const view = taskPolicy.data.item; const active = view.active; const candidate = view.candidate;
          return <div className="detail-stack">
            <KeyValue items={[
              ["当前状态", <Badge value={candidate?.status || active?.status || "absent"} />],
              ["活动 revision", active?.revision ?? "—"],
              ["活动摘要", <code>{short(active?.policy_digest, 22)}</code>],
              ["目标", active?.objective?.summary || candidate?.objective?.summary || "—"],
              ["有效期", formatTime(active?.limits?.expires_at || candidate?.limits?.expires_at)],
            ]} />
            {candidate && <Panel title={`待确认 revision ${candidate.revision}`} subtitle={`会话级授权 · digest ${short(candidate.policy_digest, 24)}`}>
              <KeyValue items={[
                ["允许工具", candidate.tools?.allow?.join(", ") || "无"],
                ["读取路径", candidate.files?.read?.join(", ") || "无"],
                ["写入路径", candidate.files?.write?.join(", ") || "无"],
                ["网络读取", candidate.network?.read?.join(", ") || "无"],
                ["网络写入", candidate.network?.write?.join(", ") || "无"],
              ]} />
              <h3>与当前 revision 的权限差异</h3><JsonView value={view.diff} />
              <div className="inline-actions">
                <button className="button primary" disabled={activateTask.isPending || rejectTask.isPending} onClick={() => activateTask.mutate(candidate)}>激活会话策略</button>
                <button className="button danger" disabled={activateTask.isPending || rejectTask.isPending} onClick={() => rejectTask.mutate(candidate)}>拒绝候选</button>
              </div>
              {(activateTask.error || rejectTask.error) && <ErrorState error={activateTask.error || rejectTask.error} />}
            </Panel>}
            <details><summary>历史 revision 与确认记录</summary><JsonView value={{ history: view.history, confirmations: view.confirmations }} /></details>
          </div>;
        })()}
        <h3>Hybrid R_task 生成</h3>
        {taskGenerations.isLoading ? <Loading label="正在读取生成记录…" /> : taskGenerations.error ? <ErrorState error={taskGenerations.error} /> : taskGenerations.data?.items?.length ? <div className="detail-stack">
          {taskGenerations.data.items.map((generation: any) => <Panel key={generation.generation_id} title={`Generation ${short(generation.generation_id, 12)}`} subtitle={`${formatTime(generation.created_at)} · revision ${generation.revision}`}>
            <KeyValue items={[
              ["状态", <Badge value={generation.status} />],
              ["模型", generation.model || "deterministic fallback"],
              ["草案摘要", <code>{short(generation.deterministic_draft_digest, 24)}</code>],
              ["提案摘要", <code>{short(generation.proposal_digest, 24)}</code>],
              ["编译策略", <code>{short(generation.compiled_policy_digest, 24)}</code>],
              ["错误", generation.error_code || "—"],
            ]} />
            {generation.status === "failed" && <div className="inline-actions"><button className="button primary" disabled={retryGeneration.isPending} onClick={() => retryGeneration.mutate(generation.generation_id)}>重试生成</button></div>}
            {(generation.accepted_fields?.length || generation.rejected_fields?.length || generation.uncertainties?.length) && <details><summary>编译明细</summary><JsonView value={{ accepted_fields: generation.accepted_fields, rejected_fields: generation.rejected_fields, uncertainties: generation.uncertainties }} /></details>}
          </Panel>)}
          {retryGeneration.error && <ErrorState error={retryGeneration.error} />}
        </div> : <Empty title="此会话尚无 Hybrid 生成记录" />}
        <h3>结构化安全记忆</h3>
        {safetyMemory.isLoading ? <Loading label="正在构建安全记忆…" /> : safetyMemory.error ? <ErrorState error={safetyMemory.error} /> : <JsonView value={safetyMemory.data?.item || {}} />}
        <h3>时间线{item.timeline_truncated ? `（显示 ${item.timeline.length}/${item.timeline_total}）` : ""}</h3>
        {item.timeline?.length ? <div className="timeline">{item.timeline.map((entry: any, index: number) => <article key={entry.event?.event_id || index}><span className={`timeline-dot ${entry.risk || "info"}`} /><div><div><strong>{entry.event?.event_type}</strong><Badge value={entry.decision || "none"} />{entry.would_decide && <Badge value={entry.would_decide} />}<Badge value={entry.risk || "none"} /></div><small>{formatTime(entry.event?.occurred_at)} · {entry.event?.tool?.name || "lifecycle"}</small><p>{entry.reason || "无决策原因"}</p></div></article>)}</div> : <Empty />}
      </div>;
    })()}</Drawer>}
  </>;
}
