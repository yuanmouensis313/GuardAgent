import { KeyboardEvent, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, formatTime, short } from "../api";
import { Badge, Chart, DataTable, Empty, ErrorState, KeyValue, Loading, Metric, PageHeader, Panel } from "../components";
import type { EChartsCoreOption } from "echarts/core";

export default function Overview() {
  const navigate = useNavigate();
  const [range, setRange] = useState("24h");
  const query = useQuery({ queryKey: ["overview", range], queryFn: () => api<any>(`/overview?range=${range}`) });
  const trendOption = useMemo<EChartsCoreOption>(() => ({
    backgroundColor: "transparent", grid: { left: 42, right: 12, top: 18, bottom: 34 },
    tooltip: { trigger: "axis" }, xAxis: { type: "category", data: (query.data?.metrics.trend || []).map((x: any) => formatTime(x.at)), axisLabel: { color: "#8290a7", hideOverlap: true } },
    yAxis: { type: "value", minInterval: 1, axisLabel: { color: "#8290a7" }, splitLine: { lineStyle: { color: "#243044" } } },
    series: [{ type: "line", smooth: true, symbol: "none", data: (query.data?.metrics.trend || []).map((x: any) => x.count), lineStyle: { color: "#55d6be", width: 3 }, areaStyle: { color: "rgba(85,214,190,.13)" } }]
  }), [query.data]);
  const riskOption = useMemo<EChartsCoreOption>(() => ({
    tooltip: { trigger: "item" }, legend: { bottom: 0, textStyle: { color: "#9aa7ba" } },
    series: [{ type: "pie", radius: ["52%", "74%"], center: ["50%", "43%"], label: { show: false }, data: Object.entries(query.data?.metrics.risks || {}).map(([name, value]) => ({ name, value: Number(value) })) }]
  }), [query.data]);
  const activate = (path: string) => (event: KeyboardEvent<HTMLDivElement>) => { if (event.key === "Enter" || event.key === " ") navigate(path); };

  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const data = query.data; const decisions = data.metrics.decisions || {};
  return <>
    <PageHeader title="安全态势总览" description="查看本地代理行为、策略效果和需要你关注的风险。" actions={<div className="segmented">{["1h", "24h", "7d", "30d"].map(item => <button key={item} className={range === item ? "active" : ""} onClick={() => setRange(item)}>{item}</button>)}</div>} />
    <div className={data.status.mode === "observe" ? "notice observe" : "notice warning"}><strong>{data.status.mode === "observe" ? "Observe 模式" : `${data.status.mode} 模式`}</strong><span>{data.status.mode === "observe" ? "当前记录建议判定但不由 GuardAgent 阻断，请重点关注 would_decide。" : "策略正在参与真实操作控制。"}</span></div>
    <div className="metrics-grid overview-metrics"><Metric label="事件" value={data.metrics.events} note={range} /><Metric label="ALLOW" value={decisions.ALLOW || 0} tone="allow" /><Metric label="DENY" value={decisions.DENY || 0} tone="deny" /><Metric label="REQUIRE_APPROVAL" value={decisions.REQUIRE_APPROVAL || 0} tone="approval" /><Metric label="OBSERVE" value={decisions.OBSERVE || 0} /><Metric label="待审批" value={data.status.pending_approvals} tone="approval" /><Metric label="事故" value={data.status.incidents} tone={data.status.incidents ? "danger" : ""} /></div>
    <Panel title="服务状态"><KeyValue items={[["版本", data.status.version], ["运行状态", <Badge value="online" />], ["策略模式", <Badge value={data.status.mode} />], ["策略 Digest", <code>{data.status.policy_digest}</code>], ["工作区", data.status.workspace], ["数据库完整性", <Badge value={data.status.database_integrity} />]]} /></Panel>
    <div className="dashboard-grid">
      <div className="chart-link" role="link" tabIndex={0} onClick={() => navigate("/events")} onKeyDown={activate("/events")}><Panel title="事件趋势" subtitle="点击进入事件中心；按时间范围自动选择聚合粒度"><Chart option={trendOption} label={`事件趋势：${(data.metrics.trend || []).map((x: any) => `${formatTime(x.at)} ${x.count}条`).join("；") || "无数据"}`} /></Panel></div>
      <div className="chart-link" role="link" tabIndex={0} onClick={() => navigate("/events")} onKeyDown={activate("/events")}><Panel title="风险分布" subtitle="点击进入事件中心；风险与决策相互独立"><Chart option={riskOption} label={`风险分布：${Object.entries(data.metrics.risks || {}).map(([name, value]) => `${name} ${value}条`).join("；") || "无数据"}`} /></Panel></div>
    </div>
    <div className="dashboard-grid lower">
      <Panel title="待审批" subtitle="点击记录查看完整上下文">{data.pending_approvals.length ? <DataTable rows={data.pending_approvals} onRow={row => navigate(`/approvals?approval=${row.approval_id}`)} columns={[{ key: "risk", label: "风险", render: r => <Badge value={r.risk} /> }, { key: "display", label: "工具", render: r => r.display?.tool?.name || "—" }, { key: "expires_at", label: "到期", render: r => formatTime(r.expires_at) }]} /> : <Empty title="没有待审批操作" description="新审批出现时会通过实时通道更新。" />}</Panel>
      <Panel title="高频规则" subtitle="点击规则筛选事件">{data.metrics.top_rules.length ? <DataTable rows={data.metrics.top_rules} onRow={row => navigate(`/events?rule_id=${encodeURIComponent(row.rule_id)}`)} columns={[{ key: "rule_id", label: "规则", render: r => <code>{r.rule_id}</code> }, { key: "total", label: "命中" }, { key: "denied", label: "拒绝" }, { key: "last_seen", label: "最近命中", render: r => formatTime(r.last_seen) }]} /> : <Empty />}</Panel>
    </div>
    <Panel title="最近高危事件">{data.recent_high_risk?.length ? <DataTable rows={data.recent_high_risk} onRow={row => navigate(`/events?event=${row.event_id}`)} columns={[{ key: "occurred_at", label: "时间", render: r => formatTime(r.occurred_at) }, { key: "risk", label: "风险", render: r => <Badge value={r.risk} /> }, { key: "tool_name", label: "工具" }, { key: "reason", label: "原因", render: r => short(r.reason, 72) }]} /> : <Empty title="没有高危事件" />}</Panel>
    {data.recent_incidents.length > 0 && <Panel title="最近服务事故"><DataTable rows={data.recent_incidents} onRow={() => navigate("/diagnostics")} columns={[{ key: "created_at", label: "时间", render: r => formatTime(r.created_at) }, { key: "severity", label: "等级", render: r => <Badge value={r.severity} /> }, { key: "category", label: "类别" }, { key: "message", label: "说明", render: r => short(r.message, 80) }]} /></Panel>}
  </>;
}
