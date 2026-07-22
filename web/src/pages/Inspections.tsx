import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Drawer, Empty, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

export default function Inspections() {
  const client = useQueryClient();
  const [selected, setSelected] = useState<string>();
  const list = useQuery({ queryKey: ["inspections"], queryFn: () => api<any>("/inspections?limit=100") });
  const detail = useQuery({ queryKey: ["inspection", selected], queryFn: () => api<any>(`/inspections/${encodeURIComponent(selected!)}`), enabled: !!selected });
  const refresh = () => { void client.invalidateQueries({ queryKey: ["inspections"] }); void client.invalidateQueries({ queryKey: ["inspection", selected] }); };
  const confirm = useMutation({
    mutationFn: (decision: "approve" | "deny") => api<any>(`/inspections/${encodeURIComponent(selected!)}/confirm`, { method: "POST", body: postBody({ operator: "ui", decision, scope: "allow-this-digest" }) }),
    onSuccess: refresh,
  });
  const invalidate = useMutation({
    mutationFn: () => api<any>(`/inspections/${encodeURIComponent(selected!)}/invalidate`, { method: "POST", body: postBody() }),
    onSuccess: refresh,
  });
  return <>
    <PageHeader title="内容核查" description="Skill/MCP 信任绑定内容摘要、扫描器版本和基础策略；名称相同不能复用旧结论。" />
    <Panel>{list.isLoading ? <Loading /> : list.error ? <ErrorState error={list.error} /> : list.data?.items?.length ? <DataTable rows={list.data.items} onRow={row => setSelected(row.content_digest)} columns={[
      { key: "kind", label: "类型", render: row => <Badge value={row.kind} /> },
      { key: "canonical_name", label: "名称" },
      { key: "content_digest", label: "内容摘要", render: row => <code>{short(row.content_digest, 24)}</code> },
      { key: "decision", label: "结论", render: row => <Badge value={row.decision || "unknown"} /> },
      { key: "risk", label: "风险", render: row => <Badge value={row.risk || "unknown"} /> },
      { key: "inspected_at", label: "扫描时间", render: row => formatTime(row.inspected_at) },
      { key: "scanner_version", label: "扫描器" },
    ]} /> : <Empty title="尚无内容核查记录" />}</Panel>
    {selected && <Drawer title="内容核查详情" onClose={() => setSelected(undefined)}>{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : (() => {
      const item = detail.data?.item; if (!item) return null; const verdict = item.verdict;
      return <div className="detail-stack">
        <KeyValue items={[
          ["类型 / 名称", `${item.kind} / ${item.canonical_name}`],
          ["内容摘要", <code>{item.content_digest}</code>],
          ["结论", <Badge value={verdict?.decision || "unknown"} />],
          ["风险", <Badge value={verdict?.risk || "unknown"} />],
          ["状态", <Badge value={verdict?.status || "unknown"} />],
          ["扫描器", verdict?.scanner_version],
          ["策略摘要", <code>{short(verdict?.inspection_policy_digest, 24)}</code>],
          ["到期", formatTime(verdict?.expires_at)],
        ]} />
        <div className="inline-actions">
          {verdict?.decision === "REQUIRE_APPROVAL" && <button className="button primary" disabled={confirm.isPending} onClick={() => confirm.mutate("approve")}>允许此摘要</button>}
          <button className="button danger" disabled={confirm.isPending} onClick={() => confirm.mutate("deny")}>拒绝</button>
          <button className="button ghost" disabled={invalidate.isPending} onClick={() => invalidate.mutate()}>使结论失效</button>
        </div>
        {(confirm.error || invalidate.error) && <ErrorState error={confirm.error || invalidate.error} />}
        <h3>Findings（不含原始证据）</h3><JsonView value={verdict?.findings || []} />
        <h3>能力清单</h3><JsonView value={verdict?.capability_manifest || {}} />
        <h3>文件清单与确认记录</h3><JsonView value={{ manifest: item.manifest, confirmations: item.confirmations }} />
      </div>;
    })()}</Drawer>}
  </>;
}
