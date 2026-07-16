import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Drawer, Empty, ErrorState, Loading, PageHeader, Panel } from "../components";

function Checks({ result }: { result: any }) {
  return <div className="checks"><div className="diagnostic-overall"><Badge value={result.overall} /><strong>总体结果：{result.overall}</strong></div>{result.checks?.map((check: any) => <details key={check.name}><summary><Badge value={check.status} /><strong>{check.name}</strong><span>{check.message} · {Number(check.duration_ms || 0).toLocaleString()} ms</span></summary>{check.output && <pre>{check.output}</pre>}</details>)}</div>;
}

export default function Diagnostics() {
  const [jobId, setJobId] = useState<string>();
  const [historical, setHistorical] = useState<any>();
  const start = useMutation({ mutationFn: () => api<any>("/diagnostics/jobs", { method: "POST", body: postBody() }), onSuccess: data => setJobId(data.item.job_id) });
  const job = useQuery({ queryKey: ["diagnostic", jobId], queryFn: () => api<any>(`/diagnostics/jobs/${jobId}`), enabled: !!jobId, refetchInterval: query => ["queued", "running"].includes(query.state.data?.item?.status) ? 1_000 : false });
  const history = useQuery({ queryKey: ["diagnostic-history"], queryFn: () => api<any>("/diagnostics/jobs") });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: () => api<any>("/incidents") });
  const result = job.data?.item?.result;
  useEffect(() => { if (["completed", "failed"].includes(job.data?.item?.status)) void history.refetch(); }, [job.data?.item?.status]);
  return <>
    <PageHeader title="系统诊断" description="运行只读环境检查，诊断不会自动修改 OpenClaw 或操作系统配置。" actions={<button className="button primary" disabled={start.isPending || ["queued", "running"].includes(job.data?.item?.status)} onClick={() => start.mutate()}>运行诊断</button>} />
    {start.error && <ErrorState error={start.error} />}
    {jobId && <Panel title="诊断任务" subtitle={`任务 ${short(jobId, 18)}`}>{job.isLoading ? <Loading /> : job.error ? <ErrorState error={job.error} /> : <><div className="detail-hero"><Badge value={job.data.item.status} /><span>{formatTime(job.data.item.started_at)}</span></div>{["queued", "running"].includes(job.data.item.status) && <Loading label="正在执行 OpenClaw 与安全基线检查…" />}{result && <Checks result={result} />}</>}</Panel>}
    {!jobId && <Panel><Empty title="尚未运行本次诊断" description="检查 OpenClaw、sandbox、exec policy、审批配置、回环绑定和本地状态路径。" /></Panel>}
    <Panel title="最近诊断历史" subtitle="点击记录查看持久化的结构化检查结果">{history.isLoading ? <Loading /> : history.error ? <ErrorState error={history.error} /> : history.data?.items?.length ? <DataTable rows={history.data.items} onRow={setHistorical} columns={[{ key: "started_at", label: "开始时间", render: row => formatTime(row.started_at) }, { key: "status", label: "状态", render: row => <Badge value={row.status} /> }, { key: "overall", label: "总体", render: row => <Badge value={row.result?.overall || "unknown"} /> }, { key: "operator", label: "操作者", render: row => short(row.operator, 22) }]} /> : <Empty title="没有历史诊断" />}</Panel>
    <Panel title="服务事故" subtitle="归一化、认证和审计异常会记录在此">{incidents.isLoading ? <Loading /> : incidents.error ? <ErrorState error={incidents.error} /> : incidents.data?.items?.length ? <DataTable rows={incidents.data.items} columns={[{ key: "created_at", label: "时间", render: row => formatTime(row.created_at) }, { key: "severity", label: "等级", render: row => <Badge value={row.severity} /> }, { key: "category", label: "类别" }, { key: "message", label: "说明" }, { key: "detail", label: "详情", render: row => short(JSON.stringify(row.detail), 44) }]} /> : <Empty title="没有服务事故" />}</Panel>
    {historical && <Drawer title="历史诊断详情" onClose={() => setHistorical(undefined)}><div className="detail-stack"><div className="detail-hero"><Badge value={historical.status} /><span>{formatTime(historical.started_at)}</span></div>{historical.result ? <Checks result={historical.result} /> : <Empty title="该任务没有结构化结果" />}</div></Drawer>}
  </>;
}
