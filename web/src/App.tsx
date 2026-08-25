import { lazy, Suspense, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, consumeBootstrap, postBody, restoreSession, SessionInfo, setCsrf, short } from "./api";
import { Badge, ErrorState, Loading } from "./components";
const Overview = lazy(() => import("./pages/Overview"));
const Approvals = lazy(() => import("./pages/Approvals"));
const Events = lazy(() => import("./pages/Events"));
const Sessions = lazy(() => import("./pages/Sessions"));
const Sanitization = lazy(() => import("./pages/Sanitization"));
const Inspections = lazy(() => import("./pages/Inspections"));
const Reviews = lazy(() => import("./pages/Reviews"));
const Policy = lazy(() => import("./pages/Policy"));
const Diagnostics = lazy(() => import("./pages/Diagnostics"));
const Settings = lazy(() => import("./pages/Settings"));

const nav = [
  ["/overview", "总览", "⌂"], ["/approvals", "审批中心", "!"], ["/events", "事件中心", "◎"],
  ["/sessions", "会话", "⋮"], ["/reviews", "模型审查", "※"], ["/inspections", "内容核查", "⌕"], ["/sanitization", "脱敏观测", "◇"], ["/policy", "策略", "{}"], ["/diagnostics", "系统诊断", "+"], ["/settings", "设置", "·"]
] as const;

function Shell({ session, onLogout }: { session: SessionInfo; onLogout: () => void }) {
  const client = useQueryClient();
  const navigate = useNavigate();
  const [theme, setTheme] = useState<"system" | "dark" | "light">(() => (localStorage.getItem("guard-theme") as "system" | "dark" | "light") || "system");
  const statusQuery = useQuery({ queryKey: ["overview", "24h"], queryFn: () => api<any>("/overview?range=24h"), refetchInterval: 10_000 });
  const state = statusQuery.data?.status;

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const apply = () => { document.documentElement.dataset.theme = theme === "system" ? media.matches ? "light" : "dark" : theme; };
    apply();
    media.addEventListener("change", apply);
    localStorage.setItem("guard-theme", theme);
    return () => media.removeEventListener("change", apply);
  }, [theme]);

  useEffect(() => {
    const stream = new EventSource("/v1/ui/stream", { withCredentials: true });
    const refresh = () => {
      void client.invalidateQueries({ queryKey: ["overview"] });
      void client.invalidateQueries({ queryKey: ["approvals"] });
      void client.invalidateQueries({ queryKey: ["events"] });
      void client.invalidateQueries({ queryKey: ["sessions"] });
      void client.invalidateQueries({ queryKey: ["task-policy"] });
      void client.invalidateQueries({ queryKey: ["sanitization"] });
      void client.invalidateQueries({ queryKey: ["inspections"] });
      void client.invalidateQueries({ queryKey: ["llm-reviews"] });
      void client.invalidateQueries({ queryKey: ["task-policy-generations"] });
    };
    ["approval.created", "approval.resolved", "approval.expired", "event.recorded", "decision.recorded", "policy.reloaded", "task_policy.candidate", "task_policy.activated", "task_policy.rejected", "task_policy.closed", "task_policy.generation_queued", "task_policy.hybrid_candidate", "llm_review.queued", "sanitization.recorded", "inspection.updated", "incident.created", "diagnostic.completed"].forEach(name => stream.addEventListener(name, refresh));
    return () => stream.close();
  }, [client]);

  return <div className="app-shell">
    <aside className="sidebar">
      <button className="brand" onClick={() => navigate("/overview")}><span className="brand-mark">G</span><span><strong>GuardAgent</strong><small>LOCAL CONTROL</small></span></button>
      <nav>{nav.map(([path, label, icon]) => <NavLink key={path} to={path}><span>{icon}</span>{label}{path === "/approvals" && state?.pending_approvals > 0 && <b>{state.pending_approvals}</b>}</NavLink>)}</nav>
      <div className="sidebar-foot"><div className="operator"><span className="online-dot" /><div><small>本地操作者</small><code>{short(session.operator, 18)}</code></div></div><button className="text-button" onClick={onLogout}>安全退出</button></div>
    </aside>
    <main className="main">
      <div className="topbar"><div className="mode-status"><span className={statusQuery.isError ? "danger" : "healthy"}>{statusQuery.isError ? "○ 服务离线" : "● 服务在线"}</span><Badge value={state?.mode || "connecting"} /><span className={state?.database_integrity === "ok" ? "healthy" : "danger"}>{state?.database_integrity === "ok" ? "✓ 审计库正常" : "! 审计库异常"}</span><span>待审批 {state?.pending_approvals ?? "—"}</span><code>{short(state?.policy_digest)}</code></div><div className="topbar-actions"><button className="theme-button" aria-label={`当前主题：${theme}，点击切换`} onClick={() => setTheme(theme === "system" ? "dark" : theme === "dark" ? "light" : "system")}>{theme === "system" ? "◐ 自动" : theme === "dark" ? "☾ 深色" : "☀ 浅色"}</button><div className="local-only">仅限本机 · {state?.version || "0.1.0"}</div></div></div>
      <div className="content"><Suspense fallback={<Loading />}><Routes>
        <Route path="/overview" element={<Overview />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/events" element={<Events />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/reviews" element={<Reviews />} />
        <Route path="/sanitization" element={<Sanitization />} />
        <Route path="/inspections" element={<Inspections />} />
        <Route path="/policy" element={<Policy />} />
        <Route path="/diagnostics" element={<Diagnostics />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes></Suspense></div>
    </main>
  </div>;
}

function LoginGuide({ error, retry }: { error?: unknown; retry: () => void }) {
  return <main className="login-screen"><div className="login-card"><div className="login-logo">G</div><p className="eyebrow">GuardAgent Local Console</p><h1>安全控制台尚未解锁</h1><p>为避免浏览器接触长期 bearer token，请在本机终端运行以下命令，系统会创建一次性登录链接。</p><code className="command">guardctl ui</code>{error ? <ErrorState error={error} onRetry={retry} /> : null}<p className="login-note">会话只在本机有效，30 分钟无操作后自动失效。</p></div></main>;
}

export default function App() {
  const client = useQueryClient();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();

  const connect = async () => {
    setLoading(true); setError(undefined);
    try {
      const params = new URLSearchParams(window.location.hash.split("?")[1] || "");
      const code = params.get("code");
      const result = code ? await consumeBootstrap(code) : await restoreSession();
      if (code) window.history.replaceState(null, "", "/ui/");
      setSession(result);
    } catch (cause) {
      setSession(null); setCsrf(""); setError(cause);
    } finally { setLoading(false); }
  };

  useEffect(() => { void connect(); }, []);
  useEffect(() => {
    const expire = () => { setCsrf(""); client.clear(); setSession(null); setError(new Error("UI 会话已过期，请重新运行 guardctl ui。")); };
    window.addEventListener("guard-session-expired", expire);
    return () => window.removeEventListener("guard-session-expired", expire);
  }, [client]);
  if (loading) return <main className="login-screen"><Loading label="正在建立安全会话…" /></main>;
  if (!session) return <LoginGuide error={error} retry={() => void connect()} />;
  const logout = async () => {
    try { await api("/auth/session", { method: "DELETE", body: postBody() }); } finally { setCsrf(""); setSession(null); }
  };
  return <Shell session={session} onLogout={() => void logout()} />;
}
