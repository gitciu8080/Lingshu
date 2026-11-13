import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  ArrowDown, ArrowUp, Bot, BrainCircuit, CalendarDays, CheckCircle2, Coins, Globe, KeyRound, LogOut,
  Plus, RotateCcw, Search, ShieldAlert, Trash2, UserCog, Wrench,
} from "lucide-react";
import { toast } from "sonner";
import {
  AgentModelBindingRole,
  api,
  auth,
  ManagedProvider,
  ModelProviderOption,
  PlatformUsageSummary,
  ProviderCatalogEntry,
  UsageGroupRow,
  UserProfile,
  UserUsageSummary,
} from "./api";
import { ProviderWizardDialog } from "./ProviderWizard";

// 用户设置页（/settings）：个人版管理台，复用 superadmin 页面的视觉体系。
// Tab1 大模型供应商（私有池）；Tab2 Agent 模型分工；Tab3 用量统计；Tab4 账号安全。
type Tab = "providers" | "usage" | "intel" | "account";

const TITLES: Record<Tab, [string, string]> = {
  intel: ["资产测绘引擎", "INTEL SEARCH / FOFA·Hunter·Shodan·ZoomEye API Key"],
  providers: ["大模型供应商管理", "MY LLM PROVIDERS / 私有供应商、模型列表与凭据"],
  usage: ["Token 用量统计", "TOKEN USAGE / 模型推理消耗的输入与输出 Token"],
  account: ["账号安全", "ACCOUNT SECURITY / 登录名、邮箱与密码"],
};

const DAY_OPTIONS = [
  { value: 7, label: "近 7 天" },
  { value: 30, label: "近 30 天" },
  { value: 90, label: "近 90 天" },
  { value: 0, label: "全部" },
];

export function formatTokens(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(value);
}

// ── 用量展示共享组件（用户页与超管页复用） ──
export function UsageStatCards({ calls, inputTokens, outputTokens, totalTokens }: {
  calls: number; inputTokens: number; outputTokens: number; totalTokens: number;
}) {
  return (
    <section className="superadmin-stats">
      <article><span>TOTAL_TOKENS</span><b>{formatTokens(totalTokens)}</b><i /></article>
      <article><span>INPUT_TOKENS</span><b>{formatTokens(inputTokens)}</b><i /></article>
      <article><span>OUTPUT_TOKENS</span><b>{formatTokens(outputTokens)}</b><i /></article>
      <article className="danger"><span>MODEL_CALLS</span><b>{calls}</b><i /></article>
    </section>
  );
}

export function UsageGroupTable({ title, note, rows, keyHeader, totalTokens }: {
  title: string;
  note: string;
  rows: UsageGroupRow[];
  keyHeader: string;
  totalTokens: number;
}) {
  return (
    <section className="superadmin-database">
      <header>
        <div><h2>{title}</h2><em>{note}</em></div>
      </header>
      <div className="superadmin-table-wrap">
        <table className="superadmin-table">
          <thead>
            <tr><th>{keyHeader}</th><th>调用次数</th><th>输入 TOKEN</th><th>输出 TOKEN</th><th>合计</th><th>占比</th></tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const rowTotal = row.input_tokens + row.output_tokens;
              const percent = totalTokens > 0 ? Math.round((rowTotal / totalTokens) * 100) : 0;
              return (
                <tr key={row.key}>
                  <td><code>{row.key}</code></td>
                  <td>{row.calls}</td>
                  <td>{row.input_tokens.toLocaleString()}</td>
                  <td>{row.output_tokens.toLocaleString()}</td>
                  <td><b>{rowTotal.toLocaleString()}</b></td>
                  <td style={{ minWidth: 110 }}>
                    <span style={{ fontSize: 11 }}>{percent}%</span>
                    <span style={{ display: "block", height: 3, background: "#242424", marginTop: 4 }}>
                      <span style={{ display: "block", height: 3, width: `${percent}%`, background: "var(--sa-accent, var(--accent))" }} />
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!rows.length && <p className="empty-note">该时间范围内暂无用量记录</p>}
      </div>
      <footer><span>LLM INFERENCE ONLY</span><span>ROWS {rows.length}</span></footer>
    </section>
  );
}

export function UsageDayPicker({ days, onChange }: { days: number; onChange: (days: number) => void }) {
  return (
    <div className="superadmin-toolbar">
      <select value={days} onChange={(e) => onChange(Number(e.target.value))}>
        {DAY_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </div>
  );
}

function UsageDashStats({ calls, inputTokens, outputTokens, totalTokens }: {
  calls: number; inputTokens: number; outputTokens: number; totalTokens: number;
}) {
  return (
    <div className="dash-stats">
      <article className="dash-stat"><Coins size={16} /><b>{formatTokens(totalTokens)}</b><span>总 Token</span></article>
      <article className="dash-stat"><ArrowDown size={16} /><b>{formatTokens(inputTokens)}</b><span>输入 Token</span></article>
      <article className="dash-stat"><ArrowUp size={16} /><b>{formatTokens(outputTokens)}</b><span>输出 Token</span></article>
      <article className="dash-stat"><BrainCircuit size={16} /><b>{calls}</b><span>模型调用</span></article>
    </div>
  );
}

function UsageGroupCard({ title, note, rows, keyHeader, totalTokens }: {
  title: string;
  note: string;
  rows: UsageGroupRow[];
  keyHeader: string;
  totalTokens: number;
}) {
  return (
    <section className="dash-card dash-wide">
      <header>{title}
        <span className="dash-note">{note}</span>
        <span className="card-actions db-count">{rows.length} 行</span>
      </header>
      <table className="dash-table plain">
        <thead>
          <tr><th>{keyHeader}</th><th>调用次数</th><th>输入 TOKEN</th><th>输出 TOKEN</th><th>合计</th><th>占比</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const rowTotal = row.input_tokens + row.output_tokens;
            const percent = totalTokens > 0 ? Math.round((rowTotal / totalTokens) * 100) : 0;
            return (
              <tr key={row.key}>
                <td><code>{row.key}</code></td>
                <td>{row.calls}</td>
                <td>{row.input_tokens.toLocaleString()}</td>
                <td>{row.output_tokens.toLocaleString()}</td>
                <td><b>{rowTotal.toLocaleString()}</b></td>
                <td style={{ minWidth: 110 }}>
                  <span style={{ fontSize: 11 }}>{percent}%</span>
                  <span style={{ display: "block", height: 3, background: "var(--line2)", marginTop: 4 }}>
                    <span style={{ display: "block", height: 3, width: `${percent}%`, background: "var(--accent)" }} />
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {!rows.length && <p className="empty-note">该时间范围内暂无用量记录</p>}
    </section>
  );
}

const INTEL_PLATFORMS: { id: string; label: string; needsEmail: boolean; hint: string }[] = [
  { id: "fofa", label: "FOFA", needsEmail: true, hint: 'email + key；查询如 title="登录"' },
  { id: "hunter", label: "Hunter 奇安信", needsEmail: false, hint: "api-key；每日免费配额" },
  { id: "shodan", label: "Shodan", needsEmail: false, hint: "api-key；按 credit 计费" },
  { id: "zoomeye", label: "ZoomEye", needsEmail: false, hint: "API-KEY（国际版）" },
];

function IntelCard() {
  const [state, setState] = useState<Record<string, { configured: boolean; email: string; hint: string; source: string }>>({});
  const [drafts, setDrafts] = useState<Record<string, { key: string; email: string }>>({});
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");

  const load = () => {
    api.intelKeys().then((r) => setState(r.keys.platforms || {})).catch(() => setState({}));
  };
  useEffect(load, []);

  const save = async (platform: string) => {
    const draft = drafts[platform];
    if (!draft?.key?.trim()) { setNotice("请输入 API Key"); return; }
    setBusy(platform);
    try {
      await api.setIntelKey(platform, draft.key.trim(), draft.email?.trim() || "");
      setNotice(`${platform} 已保存`);
      setDrafts((d) => ({ ...d, [platform]: { key: "", email: draft.email || "" } }));
      load();
    } catch (e) { setNotice(String(e)); }
    setBusy("");
  };
  const remove = async (platform: string) => {
    setBusy(platform);
    try { await api.deleteIntelKey(platform); setNotice(`${platform} 已删除`); load(); }
    catch (e) { setNotice(String(e)); }
    setBusy("");
  };
  const test = async (platform: string) => {
    setBusy(platform); setNotice(`${platform} 测试中…`);
    try {
      const r = await api.testIntelKey(platform);
      setNotice(`${platform}: ${r.ok ? "✅ 可用" : "❌ " + (r.error || "不可用")}`);
    } catch (e) { setNotice(String(e)); }
    setBusy("");
  };

  return (
    <section className="dash-card dash-wide intel-card">
      <header>资产测绘引擎 API Key
        <span className="dash-note">FOFA / Hunter / Shodan / ZoomEye；key 加密存储，仅测绘查询使用（结果属情报，测试目标仍需授权审批）</span>
      </header>
      <div style={{ display: "grid", gap: 14, padding: "2px 0" }}>
        {notice && <p className="mini" style={{ margin: 0 }}>{notice}</p>}
        {INTEL_PLATFORMS.map((p) => {
          const st = state[p.id] || { configured: false, email: "", hint: "", source: "" };
          const draft = drafts[p.id] || { key: "", email: "" };
          return (
            <div key={p.id} style={{ border: "1px solid var(--line)", borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <b>{p.label}</b>
                {st.configured
                  ? <span className="mini ok">已配置 {st.email ? `(${st.email})` : st.hint} {st.source === "platform" ? "· 平台池" : ""}</span>
                  : <span className="mini muted">未配置 · {p.hint}</span>}
                <span style={{ flex: 1 }} />
                {st.configured && <button className="quiet-button" disabled={busy === p.id} onClick={() => remove(p.id)}>删除</button>}
                <button className="quiet-button" disabled={busy === p.id || !st.configured} onClick={() => test(p.id)}>测试连接</button>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: p.needsEmail ? "1fr 1fr auto" : "1fr auto", gap: 8, marginTop: 8 }}>
                {p.needsEmail && (
                  <input placeholder="email" value={draft.email || ""} onChange={(e) => setDrafts((d) => ({ ...d, [p.id]: { ...draft, email: e.target.value } }))} />
                )}
                <input type="password" placeholder={st.configured ? "输入新 key 覆盖" : "API Key"}
                  value={draft.key || ""} onChange={(e) => setDrafts((d) => ({ ...d, [p.id]: { ...draft, key: e.target.value } }))} />
                <button className="danger-button" disabled={busy === p.id || !draft.key?.trim()} onClick={() => save(p.id)}>
                  {busy === p.id ? "保存中…" : "保存"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function AgentSettingsView() {
  const [roles, setRoles] = useState<AgentModelBindingRole[]>([]);
  const [options, setOptions] = useState<ModelProviderOption[]>([]);
  const [draftBindings, setDraftBindings] = useState<
    Record<string, { provider: string; model: string; thinking_intensity: string }>
  >({});
  const [savingBindings, setSavingBindings] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [bindingsResult, optionsResult] = await Promise.all([
        api.agentModelBindings(),
        api.modelProviders(),
      ]);
      setRoles(bindingsResult.roles);
      setOptions(optionsResult.providers);
      setDraftBindings(Object.fromEntries(
        bindingsResult.roles
          .filter((role) => role.provider)
          .map((role) => [role.role, {
            provider: role.provider,
            model: role.model,
            thinking_intensity: role.thinking_intensity || "",
          }]),
      ));
    } catch (error) {
      toast.error(String(error));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void load(); }, []);

  const setBinding = (
    role: string,
    patch: Partial<{ provider: string; model: string; thinking_intensity: string }>,
  ) => {
    setDraftBindings((old) => {
      const current = old[role] || { provider: "", model: "", thinking_intensity: "" };
      const next = { ...current, ...patch };
      if (patch.provider !== undefined && patch.provider !== current.provider) {
        const models = options.find((option) => option.id === patch.provider)?.models || [];
        next.model = models[0] || "";
      }
      return { ...old, [role]: next };
    });
  };

  const saveBindings = async () => {
    setSavingBindings(true);
    try {
      const payload: Record<string, { provider: string; model: string; thinking_intensity: string | null } | null> = {};
      for (const role of roles) {
        const draft = draftBindings[role.role];
        payload[role.role] = draft && draft.provider && draft.model
          ? { provider: draft.provider, model: draft.model, thinking_intensity: draft.thinking_intensity || null }
          : null;
      }
      await api.saveAgentModelBindings(payload);
      toast.success("Agent 模型分工已保存");
      void load();
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSavingBindings(false);
    }
  };

  const boundCount = Object.values(draftBindings).filter((item) => item.provider && item.model).length;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Agent 模型分工</h1>
          <small>AGENT MODEL BINDINGS / 每个 Agent 角色使用的模型与思考强度</small>
        </div>
        <div className="page-head-extra">
          <button className="quiet-button" disabled={savingBindings || !options.length}
            onClick={() => void saveBindings()}>
            {savingBindings ? "保存中…" : "保存分工"}
          </button>
        </div>
      </header>
      <div className="dash-stats">
        <article className="dash-stat"><Bot size={16} /><b>{roles.length}</b><span>Agent 角色</span></article>
        <article className="dash-stat"><CheckCircle2 size={16} /><b>{boundCount}</b><span>已绑定</span></article>
        <article className="dash-stat"><BrainCircuit size={16} /><b>{options.reduce((sum, option) => sum + (option.models?.length || 0), 0)}</b><span>可用模型</span></article>
        <article className="dash-stat"><ShieldAlert size={16} /><b>{roles.length - boundCount}</b><span>跟随主模型</span></article>
      </div>
      <section className="dash-card dash-wide">
        <header>角色绑定
          <span className="dash-note">未绑定的角色跟随任务创建时选择的主模型；绑定失效自动回退主模型</span>
          <span className="card-actions db-count">{roles.length} 角色</span>
        </header>
        <table className="dash-table plain">
          <thead><tr><th>Agent 角色</th><th>供应商</th><th>模型</th><th>思考强度</th></tr></thead>
          <tbody>
            {roles.map((role) => {
              const draft = draftBindings[role.role] || { provider: "", model: "", thinking_intensity: "" };
              const models = options.find((option) => option.id === draft.provider)?.models || [];
              return (
                <tr key={role.role}>
                  <td>
                    <div className="cell-main">
                      <b>{role.label}</b>
                      <small>{role.role}</small>
                    </div>
                  </td>
                  <td>
                    <select value={draft.provider} onChange={(e) => setBinding(role.role, { provider: e.target.value })}>
                      <option value="">跟随主模型</option>
                      {options.map((option) => (
                        <option key={option.id} value={option.id}>
                          {option.label}{option.owner === "platform" ? "（平台）" : ""}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select value={draft.model} disabled={!draft.provider} onChange={(e) => setBinding(role.role, { model: e.target.value })}>
                      <option value="">{draft.provider ? "（默认模型）" : "—"}</option>
                      {models.map((name) => <option key={name} value={name}>{name}</option>)}
                    </select>
                  </td>
                  <td>
                    <select
                      value={draft.thinking_intensity}
                      disabled={!draft.provider}
                      onChange={(e) => setBinding(role.role, { thinking_intensity: e.target.value })}
                    >
                      <option value="">跟随主模型</option>
                      <option value="off">off（无思考）</option>
                      <option value="low">low</option>
                      <option value="medium">medium</option>
                      <option value="high">high</option>
                    </select>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!options.length && !loading && (
          <p className="empty-note">请先在「用户与系统设置 → 大模型供应商」添加至少一个可用的供应商配置</p>
        )}
      </section>
    </>
  );
}

export default function UserSettingsPage() {
  const [tab, setTab] = useState<Tab>("providers");
  const [loading, setLoading] = useState(true);
  const [providers, setProviders] = useState<ManagedProvider[]>([]);
  const [catalog, setCatalog] = useState<ProviderCatalogEntry[]>([]);
  const [options, setOptions] = useState<ModelProviderOption[]>([]);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [search, setSearch] = useState("");
  const [editor, setEditor] = useState<ManagedProvider | null | undefined>(undefined);

  // ── 用量统计 ──
  const [usage, setUsage] = useState<UserUsageSummary | null>(null);
  const [usageDays, setUsageDays] = useState(30);

  // ── 账号表单 ──
  const [draftProfile, setDraftProfile] = useState({ username: "", email: "" });
  const [savingProfile, setSavingProfile] = useState(false);
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [providersResult, profileResult] = await Promise.all([
        api.myLLMProviders(),
        api.profile(),
      ]);
      setProviders(providersResult.providers);
      setProfile(profileResult);
      setDraftProfile({ username: profileResult.username, email: profileResult.email || "" });
      if (!catalog.length) {
        const catalogResult = await api.userProviderCatalog();
        setCatalog(catalogResult.providers);
      }
      const optionsResult = await api.modelProviders();
      setOptions(optionsResult.providers);
    } catch (error) {
      toast.error(String(error));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!auth.get()) { window.location.replace("/"); return; }
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 用量 Tab 激活或时间窗变化时按需拉取
  useEffect(() => {
    if (tab !== "usage") return;
    api.myTokenUsage(usageDays)
      .then(setUsage)
      .catch((error) => toast.error(String(error)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, usageDays]);

  const visibleProviders = useMemo(
    () => providers.filter((item) =>
      `${item.name} ${item.provider} ${item.base_url} ${item.models.map((m) => m.name).join(" ")}`
        .toLowerCase().includes(search.toLowerCase())),
    [providers, search],
  );

  const removeProvider = async (item: ManagedProvider) => {
    if (!window.confirm(`确定删除供应商配置「${item.name}」？其 ${item.models.length} 个模型与加密密钥都会一并删除；绑定它的 Agent 分工将自动回退主模型。`)) return;
    try { await api.myDeleteLLMProvider(item.id); toast.success("供应商配置已删除"); void load(); }
    catch (error) { toast.error(String(error)); }
  };


  const submitProfile = async (event: FormEvent) => {
    event.preventDefault();
    setSavingProfile(true);
    try {
      const result = await api.updateProfile(draftProfile);
      toast.success(result.message || "资料已更新");
      void load();
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSavingProfile(false);
    }
  };

  const submitPassword = async (event: FormEvent) => {
    event.preventDefault();
    if (newPassword !== confirmPassword) { toast.error("两次输入的新密码不一致"); return; }
    setChangingPassword(true);
    try {
      const result = await api.changePassword({ old_password: oldPassword, new_password: newPassword });
      toast.success(result.message || "密码已修改，请重新登录");
      setTimeout(() => { auth.clear(); window.location.replace("/"); }, 1200);
    } catch (error) {
      toast.error(String(error));
    } finally {
      setChangingPassword(false);
    }
  };

  const enabledCount = providers.filter((item) => item.enabled).length;

  return (
    <div className="settings-view">
      <header className="page-head">
        <div>
          <h1>{TITLES[tab][0]}</h1>
          <small>{TITLES[tab][1]}</small>
        </div>
        <div className="page-head-extra">
          <button className="quiet-button" onClick={() => void load()} disabled={loading}>
            {loading ? "同步中…" : "同步数据"}
          </button>
        </div>
      </header>
      <nav className="asset-tabs settings-tabs">
        <button className={tab === "providers" ? "active" : ""} onClick={() => { setTab("providers"); setSearch(""); }}>大模型供应商</button>
        <button className={tab === "usage" ? "active" : ""} onClick={() => { setTab("usage"); }}>Token 用量</button>
        <button className={tab === "intel" ? "active" : ""} onClick={() => { setTab("intel"); }}>资产测绘引擎</button>
        <button className={tab === "account" ? "active" : ""} onClick={() => { setTab("account"); }}>账号安全</button>
      </nav>

        {tab === "providers" && (
          <>
            <div className="dash-stats">
              <article className="dash-stat"><Bot size={16} /><b>{providers.length}</b><span>供应商配置</span></article>
              <article className="dash-stat"><CheckCircle2 size={16} /><b>{enabledCount}</b><span>已启用</span></article>
              <article className="dash-stat"><BrainCircuit size={16} /><b>{providers.reduce((sum, item) => sum + item.models.length, 0)}</b><span>模型总数</span></article>
              <article className="dash-stat"><Wrench size={16} /><b>{providers.filter((item) => item.enabled_tools.length).length}</b><span>原生工具接入</span></article>
            </div>
            <section className="dash-card dash-wide">
              <header>私有供应商池
                <span className="dash-note">仅自己可见可用；平台池由超级管理员维护</span>
                <span className="card-actions">
                  <label className="dash-search"><Search size={13} />
                    <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="搜索名称 / 供应商 / 模型…" />
                  </label>
                  <button className="danger-button compact add-model" onClick={() => setEditor(null)}>
                    <Plus size={14} /> 添加供应商
                  </button>
                </span>
              </header>
              <div className="dash-scroll">
                <table className="dash-table plain model-config-table">
                  <thead><tr><th>状态</th><th>配置 / PROVIDER</th><th>API 地址</th><th>模型</th><th>原生工具</th><th>API Key</th><th>归属</th><th>操作</th></tr></thead>
                  <tbody>
                    {visibleProviders.map((item) => (
                      <tr key={item.id}>
                        <td><span className={item.enabled ? "endpoint-state enabled" : "endpoint-state"}><i />{item.enabled ? "启用" : "停用"}</span></td>
                        <td>
                          <div className="cell-main"><b>{item.name}</b><small>{item.provider} · {item.api_style}</small></div>
                        </td>
                        <td><code className="endpoint-url">{item.base_url}</code></td>
                        <td>
                          <div className="model-chips">
                            {item.models.map((m) => (
                              <span key={m.name} className={`model-chip ${m.enabled ? "" : "off"}`} title={m.enabled ? "" : "已停用"}>
                                {m.name}{m.vision ? " · 多模态" : ""}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td><small className="tool-stack">{item.enabled_tools.length ? item.enabled_tools.join("、") : "—"}</small></td>
                        <td>
                          {item.api_key_status === "invalid"
                            ? <code className="key-invalid" title="加密密钥已丢失或轮换，请修改该配置并重新填写 API Key">密钥失效</code>
                            : <code>{item.api_key_masked}</code>}
                        </td>
                        <td><span className="role-badge">{item.owner === "platform" ? "平台" : "我的"}</span></td>
                        <td className="user-actions">
                          <button className="quiet-button" onClick={() => setEditor(item)}>修改</button>
                          <button className="danger-button compact" onClick={() => void removeProvider(item)}>
                            <Trash2 size={13} /> 删除
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!loading && !visibleProviders.length && (
                  <p className="empty-note">尚无供应商配置，请点击「添加供应商」接入你自己的大模型 API</p>
                )}
              </div>
            </section>
          </>
        )}

        {tab === "usage" && (
          <>
            {usage ? (
              <>
                <UsageDashStats
                  calls={usage.calls}
                  inputTokens={usage.input_tokens}
                  outputTokens={usage.output_tokens}
                  totalTokens={usage.input_tokens + usage.output_tokens}
                />
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <UsageDayPicker days={usageDays} onChange={setUsageDays} />
                </div>
                <UsageGroupCard title="按模型" note="按模型名分解的消耗" rows={usage.by_model}
                  keyHeader="模型" totalTokens={usage.input_tokens + usage.output_tokens} />
                <UsageGroupCard title="按供应商" note="按供应商配置分解的消耗" rows={usage.by_provider}
                  keyHeader="供应商配置" totalTokens={usage.input_tokens + usage.output_tokens} />
                <UsageGroupCard title="按会话" note="消耗最高的会话（Top 10）" rows={usage.by_session}
                  keyHeader="会话" totalTokens={usage.input_tokens + usage.output_tokens} />
              </>
            ) : (
              <p className="empty-note">加载用量数据…</p>
            )}
          </>
        )}

        {tab === "intel" && <IntelCard />}

        {tab === "account" && profile && (
          <>
            <div className="dash-stats">
              <article className="dash-stat"><UserCog size={16} /><b className="ellip">{profile.username}</b><span>登录名</span></article>
              <article className="dash-stat"><ShieldAlert size={16} /><b style={{ fontSize: 15 }}>{profile.role}</b><span>角色</span></article>
              <article className="dash-stat"><CalendarDays size={16} /><b style={{ fontSize: 13 }}>{(profile.created_at || "--").slice(0, 10)}</b><span>创建时间</span></article>
              <article className="dash-stat"><KeyRound size={16} /><b style={{ fontSize: 13 }}>{profile.last_login ? profile.last_login.slice(0, 10) : "从未登录"}</b><span>最近登录</span></article>
            </div>
            <section className="dash-card dash-wide">
              <header>登录资料
                <span className="dash-note">登录名与联系方式；用户名全局唯一</span>
              </header>
              <form onSubmit={submitProfile} className="dash-form">
                <label>登录名
                  <input value={draftProfile.username} minLength={2} maxLength={32} required
                    onChange={(e) => setDraftProfile((old) => ({ ...old, username: e.target.value }))} />
                </label>
                <label>邮箱（可选）
                  <input type="email" value={draftProfile.email} maxLength={120}
                    onChange={(e) => setDraftProfile((old) => ({ ...old, email: e.target.value }))} />
                </label>
                <button type="submit" className="danger-button" disabled={savingProfile}>
                  {savingProfile ? "保存中…" : "保存资料"}
                </button>
              </form>
            </section>
            <section className="dash-card dash-wide">
              <header>修改密码
                <span className="dash-note">修改成功后所有登录状态失效，需使用新密码重新登录</span>
              </header>
              <form onSubmit={submitPassword} className="dash-form">
                <label>当前密码
                  <input type="password" value={oldPassword} required autoComplete="current-password"
                    onChange={(e) => setOldPassword(e.target.value)} />
                </label>
                <label>新密码（至少 8 位，含大小写字母与数字）
                  <input type="password" value={newPassword} minLength={8} required autoComplete="new-password"
                    onChange={(e) => setNewPassword(e.target.value)} />
                </label>
                <label>确认新密码
                  <input type="password" value={confirmPassword} minLength={8} required autoComplete="new-password"
                    onChange={(e) => setConfirmPassword(e.target.value)} />
                </label>
                <button type="submit" className="danger-button" disabled={changingPassword}>
                  <KeyRound size={14} />{changingPassword ? "修改中…" : "修改密码"}
                </button>
              </form>
            </section>
          </>
        )}

      {editor !== undefined && (
        <ProviderWizardDialog
          editing={editor}
          catalog={catalog}
          scope="user"
          onClose={() => setEditor(undefined)}
          onSaved={() => void load()}
        />
      )}
    </div>
  );
}
