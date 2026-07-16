import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { ErrorState, KeyValue, Loading, PageHeader, Panel } from "../components";

export default function Settings() {
  const query = useQuery({ queryKey: ["settings"], queryFn: () => api<any>("/settings") });
  return <>
    <PageHeader title="设置" description="只读展示当前运行配置。修改环境变量后需要重启 GuardAgent。" />
    <div className="notice observe"><strong>只读配置</strong><span>此页面不会返回 bearer token，也不允许浏览任意文件或修改安全路径。</span></div>
    <Panel title="运行配置">{query.isLoading ? <Loading /> : query.error ? <ErrorState error={query.error} /> : <KeyValue items={Object.entries(query.data.item).map(([key, value]) => [key, <span key={key}>{typeof value === "number" ? value.toLocaleString() : String(value)}<small className="setting-source">{query.data.sources?.[key] || "derived"} · 修改后需重启</small></span>])} />}</Panel>
  </>;
}
