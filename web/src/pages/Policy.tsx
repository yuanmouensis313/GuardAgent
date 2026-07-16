import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import CodeMirror, { EditorView } from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import { api, ApiError, formatTime, postBody, short } from "../api";
import { Badge, DataTable, Empty, ErrorState, JsonView, KeyValue, Loading, PageHeader, Panel } from "../components";

const sampleEvent = {
  schema_version: "1.0", event_type: "tool.before", source: "guardctl", agent_id: "main", session_key: "ui-simulation",
  origin: { channel: "local", sender_id: "local-operator", is_local_operator: true },
  tool: { name: "exec", kind: "shell", input_kind: "powershell" }, params: { command: "git push origin main" },
};
const cspNonce = document.querySelector<HTMLMetaElement>('meta[name="guard-csp-nonce"]')?.content || "";
type CheckState = "pending" | "pass" | "fail";
const pendingChecks = (): { validate: CheckState; diff: CheckState; regression: CheckState } => ({ validate: "pending", diff: "pending", regression: "pending" });

export default function Policy() {
  const client = useQueryClient();
  const [searchParams] = useSearchParams();
  const auditEventId = searchParams.get("event") || "";
  const current = useQuery({ queryKey: ["policy"], queryFn: () => api<any>("/policy") });
  const revisions = useQuery({ queryKey: ["policy-revisions"], queryFn: () => api<any>("/policy/revisions") });
  const diagnostics = useQuery({ queryKey: ["diagnostic-history"], queryFn: () => api<any>("/diagnostics/jobs") });
  const auditEvent = useQuery({ queryKey: ["policy-audit-event", auditEventId], queryFn: () => api<any>(`/events/${auditEventId}`), enabled: !!auditEventId });
  const [text, setText] = useState("");
  const [eventText, setEventText] = useState(JSON.stringify(sampleEvent, null, 2));
  const [sessionKey, setSessionKey] = useState("");
  const [builder, setBuilder] = useState({ event_type: "tool.before", tool: "exec", session: "ui-simulation", channel: "local", sender: "local-operator", params: '{"command":"git status"}' });
  const [result, setResult] = useState<{ title: string; value: any; error?: unknown }>();
  const [busy, setBusy] = useState("");
  const [comment, setComment] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [checks, setChecks] = useState(pendingChecks);

  useEffect(() => { if (current.data?.item.text && !text) setText(current.data.item.text); }, [current.data, text]);
  useEffect(() => { if (auditEvent.data?.item.event) setEventText(JSON.stringify(auditEvent.data.item.event, null, 2)); }, [auditEvent.data]);

  const updateText = (value: string) => { setText(value); setChecks(pendingChecks()); };
  const run = async (title: string, path: string, payload: Record<string, unknown>) => {
    setBusy(title); setResult(undefined);
    try {
      const value = await api<any>(path, { method: "POST", body: postBody(payload) });
      setResult({ title, value: value.item });
      if (path === "/policy/validate") setChecks(state => ({ ...state, validate: value.item.valid === true ? "pass" : "fail" }));
      if (path === "/policy/diff") setChecks(state => ({ ...state, diff: "pass" }));
      if (path === "/policy/regression" && !payload.session_key) setChecks(state => ({ ...state, regression: value.item.passed === true ? "pass" : "fail" }));
      return value;
    } catch (error) { setResult({ title, value: null, error }); throw error; }
    finally { setBusy(""); }
  };
  const publish = async () => {
    try {
      await run("发布结果", "/policy/publish", { policy: text, expected_digest: current.data.item.digest, comment, confirmation: confirmation || undefined });
      await client.invalidateQueries({ queryKey: ["policy"] });
      await client.invalidateQueries({ queryKey: ["policy-revisions"] });
      await client.invalidateQueries({ queryKey: ["overview"] });
      setComment(""); setConfirmation(""); setChecks(pendingChecks());
    } catch { /* displayed below */ }
  };
  const restore = async (revisionId: string) => {
    if (!window.confirm("将校验并恢复该策略版本，是否继续？")) return;
    setBusy("回滚策略");
    try {
      const value = await api<any>(`/policy/revisions/${revisionId}/restore`, { method: "POST", body: postBody({ expected_digest: current.data.item.digest, confirmation: "ENFORCE" }) });
      setResult({ title: "回滚策略", value: value.item });
      setText(""); await client.invalidateQueries({ queryKey: ["policy"] }); await client.invalidateQueries({ queryKey: ["policy-revisions"] });
    } catch (error) { setResult({ title: "回滚策略", value: null, error }); } finally { setBusy(""); }
  };
  const buildEvent = () => {
    try {
      const params = JSON.parse(builder.params);
      setEventText(JSON.stringify({ schema_version: "1.0", event_type: builder.event_type, source: "guardctl", agent_id: "main", session_key: builder.session, origin: { channel: builder.channel, sender_id: builder.sender, is_local_operator: true }, tool: { name: builder.tool, kind: builder.tool === "exec" ? "shell" : "tool" }, params }, null, 2));
    } catch { setResult({ title: "构造测试事件", value: null, error: new ApiError(422, { code: "JSON_INVALID", message: "参数字段不是有效 JSON" }) }); }
  };
  const simulate = () => {
    try { void run("模拟结果", "/policy/simulate", { policy: text, event: JSON.parse(eventText) }).catch(() => {}); }
    catch { setResult({ title: "模拟结果", value: null, error: new ApiError(422, { code: "JSON_INVALID", message: "测试事件不是有效 JSON" }) }); }
  };

  if (current.isLoading) return <Loading />;
  if (current.error) return <ErrorState error={current.error} onRetry={() => void current.refetch()} />;
  const info = current.data.item;
  const dirty = text !== info.text;
  const candidateEnforce = /\bmode\s*:\s*["']?enforce\b/i.test(text) && info.mode !== "enforce";
  const checksPassed = checks.validate === "pass" && checks.diff === "pass" && checks.regression === "pass";
  return <>
    <PageHeader title="策略工作台" description="候选策略必须完成校验、差异审阅和 fixtures 回归，才能原子发布。" actions={<div className="policy-state"><Badge value={info.mode} /><code>{short(info.digest, 20)}</code>{dirty && <span>有未发布修改</span>}</div>} />
    <div className="notice danger"><strong>安全边界</strong><span>前端门槛只改善操作流程；发布时后端仍会重新校验、检查 digest 并在失败时恢复旧策略。</span></div>
    <div className="policy-layout">
      <Panel title="YAML 策略" subtitle={info.source}><CodeMirror value={text} height="620px" extensions={[yaml(), ...(cspNonce ? [EditorView.cspNonce.of(cspNonce)] : [])]} onChange={updateText} basicSetup={{ foldGutter: true, lineNumbers: true, highlightActiveLine: true }} theme="dark" /></Panel>
      <div className="policy-side">
        <Panel title="当前摘要"><KeyValue items={[["模式", <Badge value={info.summary.mode} />], ["规则", info.summary.rules], ["默认决策", info.summary.default_decision], ["允许域名", info.summary.allow_domains.length], ["拒绝域名", info.summary.deny_domains.length], ["预算", <code>{JSON.stringify(info.summary.budgets)}</code>], ["修改时间", formatTime(info.modified_at)]]} /></Panel>
        <Panel title="发布前检查"><div className="button-stack"><button className="button ghost" disabled={!!busy} onClick={() => void run("校验结果", "/policy/validate", { policy: text }).catch(() => {})}>1. 校验策略</button><button className="button ghost" disabled={!!busy} onClick={() => void run("安全影响差异", "/policy/diff", { policy: text }).catch(() => {})}>2. 查看安全差异</button><button className="button ghost" disabled={!!busy} onClick={() => void run("Fixtures 回归", "/policy/regression", { policy: text }).catch(() => {})}>3. 运行 Fixtures 回归</button></div>
          <div className="check-gates"><span><Badge value={checks.validate} />校验</span><span><Badge value={checks.diff} />差异</span><span><Badge value={checks.regression} />回归</span></div>
          {candidateEnforce && <div className="enforce-gate"><strong>最近诊断</strong>{diagnostics.data?.items?.[0] ? <span><Badge value={diagnostics.data.items[0].result?.overall || diagnostics.data.items[0].status} /> {formatTime(diagnostics.data.items[0].completed_at || diagnostics.data.items[0].started_at)}</span> : <span className="danger-text">尚无诊断记录，建议先到“系统诊断”运行 doctor。</span>}</div>}
          <label>发布备注<input value={comment} onChange={event => setComment(event.target.value)} placeholder="说明本次策略变更" /></label>{candidateEnforce && <label>输入 ENFORCE 确认真实拦截<input value={confirmation} onChange={event => setConfirmation(event.target.value)} /></label>}
          <button className="button primary full" disabled={!dirty || !checksPassed || !!busy || candidateEnforce && confirmation !== "ENFORCE"} onClick={() => void publish()}>{busy === "发布结果" ? "正在发布…" : "发布候选策略"}</button>
        </Panel>
      </div>
    </div>
    {busy && busy !== "发布结果" && <Loading label={`${busy}执行中…`} />}{result && <Panel title={result.title}>{result.error ? <ErrorState error={result.error} /> : <JsonView value={result.value} />}</Panel>}
    <Panel title="单事件模拟" subtitle={auditEventId ? `已载入脱敏审计事件 ${short(auditEventId, 18)}` : "可用内置表单构造事件，或从事件详情跳转后载入脱敏审计事件"}>
      {auditEvent.error && <ErrorState error={auditEvent.error} />}
      <div className="event-builder"><input aria-label="事件类型" value={builder.event_type} onChange={event => setBuilder({ ...builder, event_type: event.target.value })} placeholder="事件类型" /><input aria-label="工具" value={builder.tool} onChange={event => setBuilder({ ...builder, tool: event.target.value })} placeholder="工具" /><input aria-label="会话" value={builder.session} onChange={event => setBuilder({ ...builder, session: event.target.value })} placeholder="会话" /><input aria-label="来源频道" value={builder.channel} onChange={event => setBuilder({ ...builder, channel: event.target.value })} placeholder="频道" /><input aria-label="发送者" value={builder.sender} onChange={event => setBuilder({ ...builder, sender: event.target.value })} placeholder="发送者" /><input aria-label="参数 JSON" value={builder.params} onChange={event => setBuilder({ ...builder, params: event.target.value })} placeholder="参数 JSON" /><button className="button ghost" onClick={buildEvent}>生成事件 JSON</button></div>
      <textarea className="code-input" value={eventText} onChange={event => setEventText(event.target.value)} /><button className="button ghost" disabled={!!busy} onClick={simulate}>模拟候选策略</button>
    </Panel>
    <Panel title="候选策略会话重放" subtitle="使用未发布策略重放已有会话，不修改历史记录"><div className="inline-form"><input value={sessionKey} onChange={event => setSessionKey(event.target.value)} placeholder="完整 session key" /><button className="button ghost" disabled={!sessionKey || !!busy} onClick={() => void run("候选会话重放", "/policy/regression", { policy: text, session_key: sessionKey }).catch(() => {})}>按候选策略重放</button></div></Panel>
    <Panel title="策略历史" subtitle="现有 policy_versions 仅用于审计；下列 revision 可恢复原始 YAML">{revisions.isLoading ? <Loading /> : revisions.data?.items?.length ? <DataTable rows={revisions.data.items} columns={[{ key: "created_at", label: "时间", render: row => formatTime(row.created_at) }, { key: "mode", label: "模式", render: row => <Badge value={row.mode} /> }, { key: "digest", label: "Digest", render: row => <code>{short(row.digest, 20)}</code> }, { key: "operator", label: "操作者", render: row => short(row.operator, 20) }, { key: "comment", label: "备注" }, { key: "restore", label: "操作", render: row => <button className="text-button" disabled={!!busy} onClick={event => { event.stopPropagation(); void restore(row.revision_id); }}>恢复</button> }]} /> : <Empty title="尚无可恢复的 UI 发布版本" />}</Panel>
  </>;
}
