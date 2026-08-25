import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Drawer, Empty, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

export default function Reviews() {
  const client = useQueryClient();
  const [selected, setSelected] = useState<string>();
  const list = useQuery({ queryKey: ["llm-reviews"], queryFn: () => api<any>("/llm-reviews?limit=100"), refetchInterval: 5000 });
  const health = useQuery({ queryKey: ["llm-health"], queryFn: () => api<any>("/llm/health"), refetchInterval: 10_000 });
  const metrics = useQuery({ queryKey: ["llm-metrics"], queryFn: () => api<any>("/llm/metrics"), refetchInterval: 10_000 });
  const detail = useQuery({
    queryKey: ["llm-review", selected],
    queryFn: () => api<any>(`/llm-reviews/${encodeURIComponent(selected!)}`),
    enabled: !!selected,
    refetchInterval: query => ["queued", "running"].includes(query.state.data?.item?.status) ? 1000 : false,
  });
  const retry = useMutation({
    mutationFn: () => api<any>(`/llm-reviews/${encodeURIComponent(selected!)}/retry`, { method: "POST", body: postBody() }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["llm-reviews"] });
      void client.invalidateQueries({ queryKey: ["llm-review", selected] });
    },
  });
  const healthItem = health.data?.item;
  const metricItem = metrics.data?.item;
  return <>
    <PageHeader title="模型审查" description="模型只提供结构化语义信号；最终授权仍由确定性规则、R_task 和融合器决定。" />
    <div className="dashboard-grid lower">
      <Panel title="运行模式"><KeyValue items={[
        ["状态", <Badge value={healthItem?.enabled ? "enabled" : "disabled"} />],
        ["模式", <Badge value={healthItem?.mode || "disabled"} />],
        ["Provider", healthItem?.provider || "—"],
        ["模型", healthItem?.model || "—"],
        ["熔断", <Badge value={healthItem?.circuit_breaker?.open ? "open" : "closed"} />],
      ]} /></Panel>
      <Panel title="审查指标"><KeyValue items={[
        ["任务状态", Object.entries(metricItem?.jobs_by_status || {}).map(([key, value]) => `${key}: ${value}`).join(" · ") || "—"],
        ["结论分布", Object.entries(metricItem?.reviews_by_verdict || {}).map(([key, value]) => `${key}: ${value}`).join(" · ") || "—"],
        ["输入 / 输出 token", `${metricItem?.token_input ?? 0} / ${metricItem?.token_output ?? 0}`],
        ["平均延迟", `${Math.round(metricItem?.average_latency_ms || 0)} ms`],
      ]} /></Panel>
    </div>
    <Panel>{list.isLoading ? <Loading /> : list.error ? <ErrorState error={list.error} /> : list.data?.items?.length ? <DataTable rows={list.data.items} onRow={row => setSelected(row.review_id)} columns={[
      { key: "created_at", label: "创建时间", render: row => formatTime(row.created_at) },
      { key: "subject_type", label: "对象", render: row => <Badge value={row.subject_type} /> },
      { key: "session_key", label: "会话", render: row => <code>{short(row.session_key, 18)}</code> },
      { key: "status", label: "状态", render: row => <Badge value={row.status} /> },
      { key: "verdict", label: "模型建议", render: row => <Badge value={row.verdict || "pending"} /> },
      { key: "risk", label: "风险", render: row => <Badge value={row.risk || "unknown"} /> },
      { key: "confidence", label: "置信度", render: row => row.confidence == null ? "—" : Number(row.confidence).toFixed(2) },
      { key: "latency_ms", label: "延迟", render: row => row.latency_ms == null ? "—" : `${row.latency_ms} ms` },
      { key: "model", label: "模型" },
    ]} /> : <Empty title="尚无模型审查记录" />}</Panel>
    {selected && <Drawer title="模型审查详情" onClose={() => setSelected(undefined)}>{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : (() => {
      const item = detail.data?.item; if (!item) return null;
      return <div className="detail-stack">
        <KeyValue items={[
          ["审查 ID", <code>{item.review_id}</code>],
          ["状态", <Badge value={item.status} />],
          ["结论", <Badge value={item.verdict || "pending"} />],
          ["风险", <Badge value={item.risk || "unknown"} />],
          ["置信度", item.confidence == null ? "—" : Number(item.confidence).toFixed(3)],
          ["输入摘要", <code>{short(item.input_digest, 28)}</code>],
          ["结果摘要", <code>{short(item.result_digest, 28)}</code>],
          ["Prompt 摘要", <code>{short(item.prompt_template_digest, 28)}</code>],
          ["模型", `${item.provider || "—"} / ${item.model || "—"}`],
          ["创建 / 完成", `${formatTime(item.created_at)} / ${formatTime(item.completed_at)}`],
        ]} />
        <p>{item.sanitized_summary || item.last_error_code || "审查尚未产生结论。"}</p>
        {["failed", "timed_out", "invalid", "cancelled"].includes(item.status) && <div className="inline-actions"><button className="button primary" disabled={retry.isPending} onClick={() => retry.mutate()}>重试审查</button></div>}
        {retry.error && <ErrorState error={retry.error} />}
        <h3>威胁与证据</h3><JsonView value={{ threats: item.threats || [], evidence: item.evidence || [], validation_issues: item.validation_issues || [] }} />
        <h3>收窄建议</h3><JsonView value={item.constraints || {}} />
        <small>控制台不展示原始模型输入、原始响应、秘密或认证信息。</small>
      </div>;
    })()}</Drawer>}
  </>;
}
