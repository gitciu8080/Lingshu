/* 灵枢情报视图：导航栏 / 仪表板 / 资产管理 / 威胁建模 / 资产测绘。
   数据源：/api/dashboard 与 /api/session/{id}/intel；图表全部内联 SVG。 */
import { useEffect, useMemo, useState } from "react";
import { Activity, ChevronLeft, ChevronRight, Crosshair, Database, FileText, Gauge, LayoutDashboard, LogOut, Menu, Moon, Network, Radar, Search, Settings, ShieldAlert, Sparkles, Sun, Target, TrendingUp, UserCog, Wrench } from "lucide-react";
import { api, Session } from "./api";
import lightLogo from "./logo2.png";
import darkLogo from "./logored.png";

export type IntelView =
  | "console" | "dashboard" | "assets" | "threats" | "mapping" | "reports"
  | "agent_settings" | "settings" | "tooling" | "knowledge";

/* ── 导航栏 ── */

const NAV_ITEMS: { id: IntelView; label: string; icon: typeof Gauge }[] = [
  { id: "dashboard", label: "仪表板", icon: LayoutDashboard },
  { id: "console", label: "控制台", icon: Crosshair },
  { id: "assets", label: "资产管理", icon: Database },
  { id: "threats", label: "威胁建模", icon: ShieldAlert },
  { id: "mapping", label: "资产测绘", icon: Network },
  { id: "reports", label: "发现与报告", icon: FileText },
  { id: "agent_settings", label: "Agent 设置", icon: UserCog },
  { id: "settings", label: "用户与系统设置", icon: Settings },
  { id: "tooling", label: "系统工具状态", icon: Wrench },
  { id: "knowledge", label: "本地知识库", icon: Database },
];

export function NavRail({ view, onChange, onLogout, theme, onToggleTheme,
}: {
  view: IntelView; onChange: (v: IntelView) => void;
  onLogout: () => void;
  theme: string; onToggleTheme: () => void;
}) {
  const [open, setOpen] = useState(() =>
    typeof window === "undefined" ? true : window.innerWidth > 760);
  const isMobile = () => window.innerWidth <= 760;
  const pick = (id: IntelView) => {
    onChange(id);
    if (isMobile()) setOpen(false);
  };
  return (
    <>
      <button className="nav-mobile-toggle" onClick={() => setOpen(true)}
        aria-label="打开导航菜单">
        <Menu size={18} />
      </button>
      {open && <button className="nav-scrim" aria-label="关闭导航菜单"
        onClick={() => setOpen(false)} />}
      <aside className={`nav-rail ${open ? "open" : ""}`}>
      <div className="nav-rail-head">
        <div className="brand nav-brand">
          <span className="brand-logo nav-mark">
            <img className="theme-logo-light" src={lightLogo} alt="灵枢" />
            <img className="theme-logo-dark" src={darkLogo} alt="灵枢" />
          </span>
          <div className="nav-label">
            <b>灵枢</b>
            <small>Lingshu Console</small>
          </div>
        </div>
        <button
          className="nav-collapse"
          onClick={() => setOpen(!open)}
          aria-label={open ? "收起导航" : "展开导航"}
        >
          {open ? <ChevronLeft size={14} /> : <ChevronRight size={14} />}
        </button>
      </div>
      <nav>
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={view === item.id ? "active" : ""}
            onClick={() => pick(item.id)}
            title={item.label}
          >
            <item.icon size={16} />
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </nav>
      <footer className="nav-footer">
        <button onClick={onToggleTheme} title="切换显示样式">
          {theme === "light" ? <Moon size={16} /> : theme === "dark" ? (
            <Sparkles size={16} />) : (<Sun size={16} />)}
          <span className="nav-label">主题切换</span>
        </button>
        <button className="nav-logout" onClick={onLogout} title="退出登录">
          <LogOut size={16} />
          <span className="nav-label">退出登录</span>
        </button>
      </footer>
      </aside>
    </>
  );
}

function SessionListPanel({ sessions, activeId, onSelect }: {
  sessions: Session[]; activeId: string; onSelect: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const shown = sessions.filter((s) =>
    !search || `${s.title || ""} ${s.target || ""}`.toLowerCase()
      .includes(search.toLowerCase()));
  return (
    <aside className="session-list-panel">
      <div className="session-search">
        <Search size={14} />
        <input value={search} onChange={(e) => setSearch(e.target.value)}
          placeholder="搜索目标或会话" />
      </div>
      <div className="session-list">
        {shown.length ? shown.map((s) => (
          <button key={s.id}
            className={`session-row ${s.id === activeId ? "selected" : ""}`}
            onClick={() => onSelect(s.id)}>
            <i className={s.status === "completed" ? "success"
              : s.status === "failed" ? "fail"
              : s.status === "running" || s.status === "active" ? "live" : ""} />
            <div>
              <b>{(s.title || s.id).slice(0, 30)}</b>
              <small>{String(s.target || "—").slice(-26)}</small>
            </div>
          </button>
        )) : <p className="session-count">无匹配任务</p>}
      </div>
    </aside>
  );
}

/* ── 情报数据加载 ── */

export type SessionIntel = {
  session_id: string; target: string; goal: string; mission_mode: string;
  phase: string; success: boolean | null; flag: string | null;
  assets: { id: string; host: string; port: number | null; service: string;
            source: string; confidence: number; first_seen: string;
            last_seen: string; evidence_ids: string[] }[];
  attack_chain: { objective?: string; report?: string; service?: string;
                  cve?: string; timestamp?: string }[];
  hypotheses: { id?: string; statement?: string; status?: string;
                confidence?: number }[];
  findings: { source?: string; report?: string }[];
  iocs: { id: string; content: string }[];
  verdicts: { id: string; content: string }[];
  evidence_records: { id: string; source: string; kind: string;
    summary: string; category: string; confidence: number;
    created_at: string;
    verification?: { status?: string } | null }[];
};

function useSessionIntel(sessionId: string) {
  const [intel, setIntel] = useState<SessionIntel | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!sessionId) { setIntel(null); return; }
    let cancelled = false;
    setLoading(true);
    api.sessionIntel(sessionId)
      .then((data) => { if (!cancelled) setIntel(data); })
      .catch(() => { if (!cancelled) setIntel(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [sessionId]);
  return { intel, loading };
}

function ViewHeader({ title, sub, extra }: {
  title: string; sub: string; extra?: React.ReactNode;
}) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        <small>{sub}</small>
      </div>
      {extra && <div className="page-head-extra">{extra}</div>}
    </header>
  );
}

function EmptyHint({ text }: { text: string }) {
  return <div className="page-empty"><ShieldAlert size={30} /><p>{text}</p></div>;
}

/* ── 仪表板 ── */

type DashboardData = {
  total: number;
  by_status: Record<string, number>;
  by_mode: Record<string, number>;
  by_mission: Record<string, number>;
  recent: { id: string; title: string; target: string; status: string;
            created_at: string; run_mode: string;
            phase?: string; success?: boolean | null }[];
  assets_total: number; mlps_verdicts: number;
  success_rate: number | null;
  token_usage: { total_tokens?: number | null; calls?: number | null };
};

function Donut({ data }: {
  data: { label: string; value: number; color: string }[];
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;
  const radius = 52, stroke = 16, cx = 64, cy = 64;
  let offset = 0;
  return (
    <svg viewBox="0 0 128 128" className="chart-donut">
      {total > 0 && data.map((d) => {
        const frac = d.value / total;
        const dash = frac * 2 * Math.PI * radius;
        const el = (
          <circle key={d.label} cx={cx} cy={cy} r={radius} fill="none"
            stroke={d.color} strokeWidth={d.value ? stroke : 0}
            strokeDasharray={`${dash} ${2 * Math.PI * radius - dash}`}
            strokeDashoffset={-offset * 2 * Math.PI * radius}
            transform={`rotate(-90 ${cx} ${cy})`}>
            <title>{`${d.label}: ${d.value}`}</title>
          </circle>
        );
        offset += frac;
        return el;
      })}
      <text x={cx} y={cy + 5} textAnchor="middle" className="donut-total">
        {total}
      </text>
    </svg>
  );
}

function BarRow({ label, value, max, color }: {
  label: string; value: number; max: number; color: string;
}) {
  return (
    <div className="chart-bar-row">
      <span className="chart-bar-label">{label}</span>
      <div className="chart-bar-track">
        <div className="chart-bar-fill" style={{
          width: `${max ? Math.max(4, (value / max) * 100) : 4}%`,
          background: color,
        }} />
      </div>
      <b>{value}</b>
    </div>
  );
}

const MODE_LABELS: Record<string, string> = {
  ctf: "CTF 夺旗", incident_response: "应急响应",
  authorized_pentest: "授权渗透", hybrid_taskbook: "混合任务书",
  mlps: "等保测评", auto: "自动判定",
};
const STATUS_COLORS: Record<string, string> = {
  completed: "var(--orchestrator)", failed: "var(--attack)",
  running: "var(--recon)", active: "var(--recon)",
  cancelled: "var(--dim)", pending: "var(--dim)",
};

export function DashboardView({ onOpenSession }: { onOpenSession: (id: string) => void }) {
  const [data, setData] = useState<DashboardData | null>(null);
  useEffect(() => {
    api.dashboard().then(setData).catch(() => setData(null));
  }, []);
  if (!data) return <EmptyHint text="仪表板加载中…" />;
  const statusData = Object.entries(data.by_status).map(([label, value]) => ({
    label, value, color: STATUS_COLORS[label] || "var(--dim)",
  }));
  const modeEntries = Object.entries(data.by_mission);
  const modeMax = Math.max(1, ...modeEntries.map(([, v]) => v));
  const stats = [
    { label: "任务总数", value: data.total, icon: Activity },
    { label: "完成 / 成功率", value: `${data.by_status.completed || 0} / ${data.success_rate ?? "—"}%`, icon: TrendingUp },
    { label: "资产台账", value: data.assets_total, icon: Database },
    { label: "等保判定", value: data.mlps_verdicts, icon: ShieldAlert },
    { label: "Token 用量(30d)", value: data.token_usage.total_tokens ?? "—", icon: Gauge },
  ];
  return (
    <>
      <ViewHeader title="仪表板" sub="OPERATIONS DASHBOARD / 全局运行态势" />
      <div className="dash-stats">
        {stats.map((s) => (
          <article key={s.label} className="dash-stat">
            <s.icon size={16} />
            <b>{s.value}</b>
            <span>{s.label}</span>
          </article>
        ))}
      </div>
      <div className="dash-grid">
        <section className="dash-card">
          <header>任务状态分布</header>
          <div className="dash-donut-wrap">
            <Donut data={statusData} />
            <ul>
              {statusData.map((d) => (
                <li key={d.label}>
                  <i style={{ background: d.color }} />
                  {d.label}: <b>{d.value}</b>
                </li>
              ))}
            </ul>
          </div>
        </section>
        <section className="dash-card">
          <header>任务模式分布</header>
          {modeEntries.length
            ? modeEntries.map(([mode, value]) => (
                <BarRow key={mode} label={MODE_LABELS[mode] || mode}
                  value={value} max={modeMax} color="var(--recon)" />
              ))
            : <p className="mini muted">暂无数据</p>}
        </section>
        <section className="dash-card dash-wide">
          <header>近期任务（点击进入控制台）</header>
          <table className="dash-table">
            <thead><tr><th>任务</th><th>目标</th><th>模式</th><th>状态</th><th>时间</th></tr></thead>
            <tbody>
              {data.recent.map((s) => (
                <tr key={s.id} onClick={() => onOpenSession(s.id)}>
                  <td className="ellip">{(s.title || s.id).slice(0, 30)}</td>
                  <td className="ellip">{String(s.target || "—").slice(-30)}</td>
                  <td>{s.run_mode === "fast" ? "⚡ FAST" : "STD"}</td>
                  <td>{s.status}</td>
                  <td className="mini">{String(s.created_at || "").slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </>
  );
}

/* ── 资产管理 ── */

type AssetFilter = "all" | "host:port" | "host-only" | "domain";

export function AssetsView({ sessions, activeId, onSelect }: {
  sessions: Session[]; activeId: string; onSelect: (id: string) => void;
}) {
  const { intel, loading } = useSessionIntel(activeId);
  const [filter, setFilter] = useState<AssetFilter>("all");
  const [search, setSearch] = useState("");
  const assets = useMemo(() => {
    const all = intel?.assets || [];
    return all.filter((a) => {
      if (filter === "host:port" && a.port == null) return false;
      if (filter === "host-only" && a.port != null) return false;
      if (filter === "domain" && !/[a-z]/i.test(a.host)) return false;
      if (search && !`${a.host} ${a.service}`.toLowerCase().includes(search.toLowerCase()))
        return false;
      return true;
    });
  }, [intel, filter, search]);
  const tabs: { id: AssetFilter; label: string }[] = [
    { id: "all", label: `全部 ${intel?.assets.length || 0}` },
    { id: "host:port", label: `主机:端口 ${intel?.assets.filter((a) => a.port != null).length || 0}` },
    { id: "host-only", label: `仅主机 ${intel?.assets.filter((a) => a.port == null).length || 0}` },
    { id: "domain", label: `域名 ${intel?.assets.filter((a) => /[a-z]/i.test(a.host)).length || 0}` },
  ];
  return (
    <>
      <ViewHeader
        title="资产管理" sub="ASSET INVENTORY / 按任务台账查看测绘与侦察发现"
      />
      <div className="intel-layout">
      <SessionListPanel sessions={sessions} activeId={activeId} onSelect={onSelect} />
      <div className="intel-content">
      {!activeId ? <EmptyHint text="选择一个任务查看其资产台账" /> : loading ? (
        <EmptyHint text="加载中…" />
      ) : !intel ? (
        <EmptyHint text="该任务暂无情报数据（任务仍在执行或数据不可用）" />
      ) : (
        <>
          <div className="asset-tabs">
            {tabs.map((t) => (
              <button key={t.id} className={filter === t.id ? "active" : ""}
                onClick={() => setFilter(t.id)}>{t.label}</button>
            ))}
            <input className="asset-search" placeholder="搜索资产 / 服务…"
              value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {assets.length ? (
            <table className="asset-table">
              <thead><tr>
                <th>资产</th><th>端口</th><th>服务</th><th>来源</th>
                <th>置信度</th><th>首次发现</th><th>最近活动</th><th>证据</th>
              </tr></thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.id}>
                    <td><b>{a.host}</b></td>
                    <td>{a.port ?? "—"}</td>
                    <td>{a.service || "—"}</td>
                    <td className="mini">{a.source || "—"}</td>
                    <td>{Math.round((a.confidence || 0) * 100)}%</td>
                    <td className="mini">{String(a.first_seen || "").slice(5, 16)}</td>
                    <td className="mini">{String(a.last_seen || "").slice(5, 16)}</td>
                    <td>{a.evidence_ids?.length || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <EmptyHint text="该筛选下无资产（先在控制台跑一轮测绘/侦察）" />}
        </>
      )}
      </div>
      </div>
    </>
  );
}

/* ── 威胁建模（思维导图 SVG）── */

export function ThreatsView({ sessions, activeId, onSelect }: {
  sessions: Session[]; activeId: string; onSelect: (id: string) => void;
}) {
  const { intel, loading } = useSessionIntel(activeId);
  const graph = useMemo(() => {
    if (!intel) return null;
    const chain = intel.attack_chain || [];
    const chainNodes = chain.slice(-8).map((step, index) => ({
      id: `c${index}`, label: String(step.objective || "攻击步骤").slice(0, 22),
      sub: [step.service, step.cve].filter(Boolean).join(" · ") || "攻击步骤",
      kind: "chain" as const,
    }));
    const threats = (intel.hypotheses || []).slice(-6).map((h, index) => ({
      id: `h${index}`,
      label: String(h.statement || "假设").slice(0, 26),
      sub: String(h.status || "active"),
      kind: h.status === "rejected" ? ("rejected" as const) : ("threat" as const),
    }));
    const rootX = 130, rootY = 240;
    const chainX = 380;
    const chainStep = 78;
    const threatX = 380;
    const threatStep = 64;
    const chainYs = chainNodes.map((_, index) =>
      60 + index * chainStep + (240 - chainNodes.length * chainStep) / 2);
    const threatCount = threats.length;
    const threatYs = threats.map((_, index) =>
      (chainNodes.length ? 240 : 140) + (index - (threatCount - 1) / 2) * threatStep);
    const nodes = [
      { id: "root", x: rootX, y: rootY, label: "攻击目标", sub: intel.target.slice(-30), kind: "root" as const },
      ...chainNodes.map((node, index) => ({ ...node, x: chainX, y: chainYs[index] })),
      ...threats.map((node, index) => ({ ...node, x: threatX + 260, y: threatYs[index] })),
    ];
    const edges = [
      ...chainNodes.map((_, index) => ({
        from: "root", to: `c${index}`,
        color: index === chainNodes.length - 1 ? "var(--attack)" : "var(--recon)",
      })),
      ...threats.map((_, index) => ({
        from: "root", to: `h${index}`,
        color: threats[index].kind === "rejected" ? "var(--dim)" : "var(--brain)",
      })),
    ];
    const height = Math.max(420, 60 + Math.max(chainNodes.length * chainStep,
      threatCount * threatStep) + 60);
    return { nodes, edges, width: 980, height };
  }, [intel]);

  return (
    <>
      <ViewHeader
        title="威胁建模" sub="THREAT MODEL / 攻击链与假设的思维导图视图"
      />
      <div className="intel-layout">
      <SessionListPanel sessions={sessions} activeId={activeId} onSelect={onSelect} />
      <div className="intel-content">
            {!activeId ? <EmptyHint text="选择一个任务查看威胁建模" /> : loading ? (
        <EmptyHint text="加载中…" />
      ) : !intel ? (
        <EmptyHint text="该任务暂无威胁数据" />
      ) : (
        <>
                    <div className="threat-chips">
            <span className="chip">攻击链 {intel.attack_chain.length}</span>
            <span className="chip">假设 {intel.hypotheses.length}</span>
            <span className="chip">发现 {intel.findings.length}</span>
            <span className="chip">IOC {intel.iocs.length}</span>
            {intel.flag && <span className="chip ok">FLAG ✓</span>}
          </div>
          <div className="graph-canvas">
            {graph && graph.nodes.length > 1 ? (
              <svg viewBox={`0 0 ${graph.width} ${graph.height}`} className="graph-svg">
                {graph.edges.map((edge, index) => {
                  const from = graph.nodes.find((n) => n.id === edge.from);
                  const to = graph.nodes.find((n) => n.id === edge.to);
                  if (!from || !to) return null;
                  const x1 = from.x + 110, y1 = from.y;
                  const x2 = to.x - 8, y2 = to.y;
                  return <path key={index}
                    d={`M ${x1} ${y1} C ${x1 + 70} ${y1}, ${x2 - 70} ${y2}, ${x2} ${y2}`}
                    fill="none" stroke={edge.color} strokeWidth={1.6} opacity={0.75} />;
                })}
                {graph.nodes.map((node) => (
                  <g key={node.id} transform={`translate(${node.x - 110}, ${node.y - 26})`}
                    className={`graph-node ${node.kind}`}>
                    <rect width={220} height={52} rx={7} />
                    <text x={12} y={22}>{node.label}</text>
                    <text x={12} y={40} className="node-sub">{node.sub}</text>
                  </g>
                ))}
              </svg>
            ) : <EmptyHint text="攻击链与假设尚未产生（先在控制台推进任务）" />}
          </div>
          {!!intel.iocs.length && (
            <div className="ioc-strip">
              <b>IOC：</b>
              {intel.iocs.slice(0, 12).map((ioc) => (
                <code key={ioc.id}>{ioc.content.replace("IOC[", "").replace("]: ", " ↦ ")}</code>
              ))}
            </div>
          )}
        </>
      )}
      </div>
      </div>
    </>
  );
}

/* ── 发现与报告 ── */

function downloadBlob(name: string, response: Response): Promise<void> {
  return response.blob().then((blob) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
  });
}

export function ReportsView({ sessions, activeId, onSelect }: {
  sessions: Session[]; activeId: string; onSelect: (id: string) => void;
}) {
  const { intel, loading } = useSessionIntel(activeId);
  const [summary, setSummary] = useState("");
  const [artifacts, setArtifacts] = useState<
    { path: string; size: number; modified_at: string }[]
  >([]);
  const [reportAvailable, setReportAvailable] = useState(false);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    setSummary(""); setArtifacts([]); setReportAvailable(false); setNotice("");
    if (!activeId) return;
    api.reportMarkdown(activeId)
      .then((text) => setSummary(typeof text === "string" ? text : ""))
      .catch(() => setSummary(""));
    api.artifacts(activeId)
      .then((r) => setArtifacts(r.artifacts || []))
      .catch(() => setArtifacts([]));
    fetch(`/api/session/${encodeURIComponent(activeId)}`,
      { headers: { Authorization: `Bearer ${localStorage.getItem("lingshu-token") || ""}` } })
      .then((r) => r.json())
      .then((d) => setReportAvailable(!!d.report_available))
      .catch(() => setReportAvailable(false));
  }, [activeId]);

  const download = async (kind: "pdf" | "markdown" | "jsonl") => {
    if (!activeId) return;
    setNotice("下载中…");
    try {
      const response = kind === "pdf"
        ? await fetch(`/api/session/${encodeURIComponent(activeId)}/report`,
            { headers: { Authorization: `Bearer ${localStorage.getItem("lingshu-token") || ""}` } })
        : await fetch(
            `/api/session/${encodeURIComponent(activeId)}/${kind === "markdown" ? "report/markdown" : "jsonl"}`,
            { headers: { Authorization: `Bearer ${localStorage.getItem("lingshu-token") || ""}` } });
      if (!response.ok) throw new Error(`下载失败 (${response.status})`);
      const names = { pdf: "report.pdf", markdown: "report.md", jsonl: "session.jsonl" };
      await downloadBlob(`${activeId.slice(0, 8)}-${names[kind]}`, response);
      setNotice("已下载");
    } catch (err) { setNotice(String(err)); }
  };

  const records = intel?.evidence_records || [];
  const verdictColor: Record<string, string> = {
    verified: "ok", failed: "err", unverified: "",
  };

  return (
    <>
      <ViewHeader
        title="发现与报告" sub="FINDINGS & REPORTS / 报告交付、证据记录与任务产物"
      />
      <div className="intel-layout">
      <SessionListPanel sessions={sessions} activeId={activeId} onSelect={onSelect} />
      <div className="intel-content">
                <div className="report-actions">
            <button className="danger-button" disabled={!reportAvailable}
              onClick={() => download("pdf")}>下载 PDF 报告</button>
            <button className="quiet-button" onClick={() => download("markdown")}>下载 Markdown</button>
            <button className="quiet-button" onClick={() => download("jsonl")}>下载会话 JSONL</button>
            {notice && <span className="mini">{notice}</span>}
          </div>
      {!activeId ? <EmptyHint text="选择一个任务查看报告与证据" /> : loading ? (
        <EmptyHint text="加载中…" />
      ) : (
        <>
          <div className="reports-grid">
            <section className="report-card">
              <header>测评报告正文 {summary ? "" : "（暂无，任务收尾后生成）"}</header>
              <div className="report-body">
                {summary
                  ? summary.split("\n").map((line, index) => (
                      <p key={index} className={line.startsWith("#") ? "report-h" : ""}>{line}</p>
                    ))
                  : <p className="mini muted">任务收尾后 Summary 智能体生成报告，此处可在线查看与下载。</p>}
              </div>
            </section>
            <section className="report-card">
              <header>证据记录 <span>{records.length}</span></header>
              <div className="evidence-records">
                {records.length ? records.slice().reverse().map((item) => (
                  <details key={item.id} className="evidence-line">
                    <summary>
                      <b>{item.id}</b>
                      <span>{item.source}</span>
                      <i className={item.kind === "attack_report" ? "attack" : ""}>{item.kind}</i>
                      {item.verification?.status && (
                        <em className={verdictColor[item.verification.status] || ""}>
                          {item.verification.status}
                        </em>
                      )}
                    </summary>
                    <p>{item.summary.slice(0, 600)}</p>
                    <small>{item.category || "—"} · 置信度 {Math.round((item.confidence || 0) * 100)}% · {String(item.created_at || "").slice(0, 19)}</small>
                  </details>
                )) : <p className="mini muted">暂无证据记录。</p>}
              </div>
            </section>
            <section className="report-card">
              <header>任务产物 <span>{artifacts.length}</span></header>
              <div className="artifact-records">
                {artifacts.length ? artifacts.slice().reverse().map((item) => (
                  <button key={item.path} className="artifact-row" onClick={() => {
                    api.artifactFile(activeId, item.path);
                  }} title={`下载 ${item.path}`}>
                    <b>{item.path.split("/").pop()}</b>
                    <small>{item.path}</small>
                    <em>{Math.max(1, Math.round(item.size / 1024))} KB</em>
                  </button>
                )) : <p className="mini muted">暂无产物文件；工具输出与截图落盘后在此显示。</p>}
              </div>
            </section>
          </div>
        </>
      )}
      </div>
      </div>
    </>
  );
}

/* ── 资产测绘（拓扑图 SVG）── */

function groupKey(host: string): string {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  const parts = host.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : host;
}

export function MappingView({ sessions, activeId, onSelect }: {
  sessions: Session[]; activeId: string; onSelect: (id: string) => void;
}) {
  const { intel, loading } = useSessionIntel(activeId);
  const [layout, setLayout] = useState<"grouped" | "tree">("grouped");
  const graph = useMemo(() => {
    if (!intel || !intel.assets.length) return null;
    const groups = new Map<string, typeof intel.assets>();
    for (const asset of intel.assets) {
      const key = groupKey(asset.host);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(asset);
    }
    const rootX = 70, rootY = 200;
    const groupX = 330;
    const nodes: { id: string; x: number; y: number; label: string;
                   sub: string; kind: string }[] = [
      { id: "root", x: rootX, y: rootY, label: "攻击目标",
        sub: intel.target.slice(-26), kind: "root" },
    ];
    const edges: { from: string; to: string; color: string }[] = [];
    const groupEntries = [...groups.entries()];
    if (layout === "tree") {
      // 层次分组：目标 → 各资产（拍平）
      const step = Math.min(58, 420 / Math.max(1, intel.assets.length));
      const startY = 200 - ((intel.assets.length - 1) * step) / 2;
      intel.assets.slice(0, 14).forEach((asset, index) => {
        nodes.push({ id: `a${index}`, x: 380, y: startY + index * step,
          label: asset.host, sub: asset.service || (asset.port ? `:${asset.port}` : ""),
          kind: "asset" });
        edges.push({ from: "root", to: `a${index}`, color: "var(--recon)" });
      });
    } else {
      // 成组思维导图：目标 → 分组 → 资产
      const groupStep = Math.max(120, 520 / Math.max(1, groupEntries.length));
      groupEntries.forEach(([key, items], gIndex) => {
        const gY = 60 + gIndex * groupStep + groupStep / 2;
        nodes.push({ id: `g${gIndex}`, x: groupX, y: gY, label: key,
          sub: `${items.length} 项资产`, kind: "group" });
        edges.push({ from: "root", to: `g${gIndex}`, color: "var(--orchestrator)" });
        items.slice(0, 6).forEach((asset, aIndex) => {
          const aY = gY + (aIndex - (Math.min(items.length, 6) - 1) / 2) * 44;
          nodes.push({ id: `g${gIndex}a${aIndex}`, x: 660, y: aY,
            label: asset.host,
            sub: asset.service || (asset.port ? `:${asset.port}` : ""),
            kind: "asset" });
          edges.push({ from: `g${gIndex}`, to: `g${gIndex}a${aIndex}`,
            color: "var(--line)" });
        });
      });
    }
    const height = Math.max(440, 80 + Math.max(
      groupEntries.length * 130, intel.assets.length * 46));
    return { nodes, edges, width: 1020, height };
  }, [intel, layout]);

  return (
    <>
      <ViewHeader
        title="资产测绘" sub="ASSET MAPPING / 测绘发现的关系拓扑"
      />
      <div className="intel-layout">
      <SessionListPanel sessions={sessions} activeId={activeId} onSelect={onSelect} />
      <div className="intel-content">
            {!activeId ? <EmptyHint text="选择一个任务查看资产拓扑" /> : loading ? (
        <EmptyHint text="加载中…" />
      ) : !graph ? (
        <EmptyHint text="暂无测绘资产（先在控制台执行测绘/侦察，或接入外部测绘引擎）" />
      ) : (
        <>
                    <div className="map-toolbar">
            <select value={layout} onChange={(e) => setLayout(e.target.value as typeof layout)}>
              <option value="grouped">成组思维导图</option>
              <option value="tree">层次分组</option>
            </select>
            <span className="chip">布局适应画布 · 节点 {graph.nodes.length}</span>
          </div>
          <div className="graph-canvas tall">
            <svg viewBox={`0 0 ${graph.width} ${graph.height}`} className="graph-svg">
              {graph.edges.map((edge, index) => {
                const from = graph.nodes.find((n) => n.id === edge.from);
                const to = graph.nodes.find((n) => n.id === edge.to);
                if (!from || !to) return null;
                const x1 = from.x + 130, y1 = from.y;
                const x2 = to.x - 6, y2 = to.y;
                return <path key={index}
                  d={`M ${x1} ${y1} C ${x1 + 80} ${y1}, ${x2 - 80} ${y2}, ${x2} ${y2}`}
                  fill="none" stroke={edge.color} strokeWidth={1.6} opacity={0.8} />;
              })}
              {graph.nodes.map((node) => (
                <g key={node.id} transform={`translate(${node.x}, ${node.y - 24})`}
                  className={`graph-node ${node.kind}`}>
                  <rect width={190} height={48} rx={7} />
                  <text x={12} y={21}>{node.label.slice(0, 26)}</text>
                  <text x={12} y={38} className="node-sub">{node.sub.slice(0, 30)}</text>
                </g>
              ))}
            </svg>
          </div>
        </>
      )}
      </div>
      </div>
    </>
  );
}
