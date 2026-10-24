import { FormEvent, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Download, LoaderCircle, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  api, LLMProviderInput, ManagedProvider, ManagedProviderModel,
  ProviderCatalogEntry, ProviderModelSettings,
} from "./api";

// 添加供应商向导：选择供应商 → 填写凭据 → 模型列表 → 每模型超参数 → 工具与启用
const WIZARD_STEPS = ["选择供应商", "填写凭据", "模型列表", "模型超参数", "工具与启用"];

export function defaultModelSettings(spec: ProviderCatalogEntry | null): ProviderModelSettings {
  const overrides = (spec?.default_settings || {}) as Partial<ProviderModelSettings>;
  return {
    temperature: 0.7,
    top_p: 0.95,
    top_k: null,
    max_tokens: 0,
    max_retries: 3,
    context_size: 128000,
    timeout_seconds: 600,
    thinking_enabled: true,
    thinking_budget: 0,
    ...overrides,
  };
}

function toolsAvailableFor(spec: ProviderCatalogEntry | null, apiStyle: string): string[] {
  if (!spec) return [];
  return Object.entries(spec.native_tools)
    .filter(([, meta]) =>
      apiStyle === "responses" ? meta.wire === "responses" : meta.wire !== "responses")
    .map(([key]) => key);
}

type WizardModel = ManagedProviderModel & { _new?: boolean; _origName?: string };

// scope：superadmin=超管平台池（/api/superadmin/*）；user=用户私有池（/api/my/*）
export type ProviderScope = "superadmin" | "user";

function scopeApi(scope: ProviderScope) {
  return scope === "user" ? {
    create: api.myCreateLLMProvider,
    update: api.myUpdateLLMProvider,
    probeSaved: api.myProbeModelsSaved,
    probe: api.myProbeModels,
    addModel: api.myAddProviderModel,
    updateModel: api.myUpdateProviderModel,
    deleteModel: api.myDeleteProviderModel,
  } : {
    create: api.createLLMProvider,
    update: api.updateLLMProvider,
    probeSaved: api.probeModelsSaved,
    probe: api.probeModels,
    addModel: api.addProviderModel,
    updateModel: api.updateProviderModel,
    deleteModel: api.deleteProviderModel,
  };
}

export function ProviderWizardDialog({ editing, catalog, scope = "superadmin", onClose, onSaved }: {
  editing: ManagedProvider | null;
  catalog: ProviderCatalogEntry[];
  scope?: ProviderScope;
  onClose: () => void;
  onSaved: () => void;
}) {
  const endpoints = scopeApi(scope);
  const [step, setStep] = useState(editing ? 2 : 1);
  const [spec, setSpec] = useState<ProviderCatalogEntry | null>(
    () => catalog.find((item) => item.key === editing?.provider) || null);
  const [draft, setDraft] = useState(() => editing ? {
    name: editing.name,
    api_style: editing.api_style,
    base_url: editing.base_url,
    gateway_mode: editing.gateway_mode,
    enabled_tools: [...(editing.enabled_tools || [])],
    api_key: "",
    clear_api_key: false,
    enabled: editing.enabled,
  } : {
    name: "",
    api_style: "chat_completions",
    base_url: "",
    gateway_mode: "base_url",
    enabled_tools: [] as string[],
    api_key: "",
    clear_api_key: false,
    enabled: true,
  });
  const [models, setModels] = useState<WizardModel[]>(() =>
    editing
      ? editing.models.map((m) => ({ ...m, settings: { ...m.settings }, _origName: m.name }))
      : []);
  const [fetched, setFetched] = useState<string[]>([]);
  const [probing, setProbing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [manualName, setManualName] = useState("");

  const change = <K extends keyof typeof draft>(key: K, value: (typeof draft)[K]) =>
    setDraft((old) => ({ ...old, [key]: value }));
  const availableTools = toolsAvailableFor(spec, draft.api_style);
  const gatewayStyle = draft.api_style === "chat_completions" || draft.api_style === "responses";

  const chooseProvider = (entry: ProviderCatalogEntry) => {
    setSpec(entry);
    setDraft((old) => ({
      ...old,
      api_style: entry.default_api_style,
      base_url: entry.default_base_url,
      enabled_tools: [],
    }));
    setFetched([]);
  };

  const changeApiStyle = (apiStyle: string) =>
    setDraft((old) => ({
      ...old,
      api_style: apiStyle,
      enabled_tools: old.enabled_tools.filter((t) => toolsAvailableFor(spec, apiStyle).includes(t)),
    }));

  const addModel = (rawName: string) => {
    const name = rawName.trim();
    if (!name) return;
    if (models.some((m) => m.name === name)) {
      toast.error(`模型 ${name} 已在列表中`);
      return;
    }
    setModels((old) => [
      ...old,
      { name, enabled: true, vision: false, settings: defaultModelSettings(spec), _new: true },
    ]);
    setFetched((old) => old.filter((m) => m !== name));
    setManualName("");
  };

  const removeModel = (index: number) =>
    setModels((old) => old.filter((_, i) => i !== index));

  const patchModel = (index: number, patch: Partial<WizardModel>) =>
    setModels((old) => old.map((m, i) => (i === index ? { ...m, ...patch } : m)));

  const patchModelSettings = (index: number, patch: Partial<ProviderModelSettings>) =>
    setModels((old) => old.map((m, i) =>
      i === index ? { ...m, settings: { ...m.settings, ...patch } } : m));

  const probe = async () => {
    if (!spec) return;
    setProbing(true);
    try {
      // 编辑已有配置且密钥健康时优先用服务端保存的凭据拉取
      const useSaved = editing && editing.api_key_status !== "invalid" && !draft.api_key.trim();
      const result = useSaved
        ? await endpoints.probeSaved(editing.id)
        : await endpoints.probe({
            provider: spec.key,
            base_url: draft.base_url.trim(),
            api_key: draft.api_key.trim(),
          });
      const known = new Set(models.map((m) => m.name));
      setFetched(result.models.filter((m) => !known.has(m)));
      toast.success(`已从 ${result.endpoint} 拉取到 ${result.models.length} 个模型`);
    } catch (error) {
      toast.error(String(error));
    } finally {
      setProbing(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!spec) { setStep(1); return; }
    if (draft.name.trim().length < 2) {
      toast.error("配置名称至少 2 个字符");
      setStep(2);
      return;
    }
    if (!models.some((m) => m.enabled)) {
      toast.error("请至少启用一个模型");
      setStep(3);
      return;
    }
    setSaving(true);
    try {
      const payload: LLMProviderInput = {
        name: draft.name.trim(),
        provider: spec.key,
        api_style: draft.api_style,
        base_url: draft.base_url.trim(),
        gateway_mode: draft.gateway_mode,
        enabled_tools: draft.enabled_tools,
        enabled: draft.enabled,
        models: models.map(({ _new: _n, _origName: _o, ...m }) => m),
      };
      if (draft.api_key.trim()) payload.api_key = draft.api_key.trim();
      if (draft.clear_api_key) payload.clear_api_key = true;
      if (editing) {
        await endpoints.update(editing.id, payload);
        const currentNames = new Set(models.map((m) => m.name));
        for (const m of models) {
          if (m._new) {
            const { _new: _n, _origName: _o, ...clean } = m;
            await endpoints.addModel(editing.id, clean);
            continue;
          }
          const original = editing.models.find((x) => x.name === m._origName);
          if (
            !original ||
            original.name !== m.name ||
            original.enabled !== m.enabled ||
            original.vision !== m.vision ||
            JSON.stringify(original.settings) !== JSON.stringify(m.settings)
          ) {
            await endpoints.updateModel(editing.id, {
              model: m._origName || m.name,
              name: m.name,
              enabled: m.enabled,
              vision: m.vision,
              settings: m.settings,
            });
          }
        }
        for (const m of editing.models) {
          if (!currentNames.has(m.name)) {
            await endpoints.deleteModel(editing.id, m.name);
          }
        }
      } else {
        await endpoints.create(payload);
      }
      toast.success(editing ? "供应商配置已更新" : "供应商配置已创建");
      onSaved();
      onClose();
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay model-config-overlay" />
        <Dialog.Content className="modal model-config-modal">
          <Dialog.Title>{editing ? "修改" : "添加"}大模型供应商</Dialog.Title>
          <Dialog.Description>
            {spec?.docs_url ? (
              <a href={spec.docs_url} target="_blank" rel="noreferrer">
                {spec.label} 官方文档 ↗
              </a>
            ) : "按步骤完成：供应商 → 凭据 → 模型列表 → 超参数 → 工具。"}
            {" "}密钥加密保存，编辑时留空不会替换。
          </Dialog.Description>
          <ol className="wizard-steps">
            {WIZARD_STEPS.map((label, index) => (
              <li key={label} className={index + 1 === step ? "active" : index + 1 < step ? "done" : ""}>
                <i>{index + 1 < step ? "✓" : index + 1}</i> {label}
              </li>
            ))}
          </ol>
          <form onSubmit={submit} className="model-config-form">
            {step === 1 && (
              <fieldset className="model-form-section">
                <legend><i>01</i> 选择供应商</legend>
                <div className="provider-cards">
                  {catalog.map((entry) => (
                    <button
                      type="button"
                      key={entry.key}
                      className={`provider-card ${spec?.key === entry.key ? "selected" : ""}`}
                      onClick={() => chooseProvider(entry)}
                    >
                      <b>{entry.label}</b>
                      <small>{entry.key} · {entry.api_styles.join(" / ")}</small>
                      <small>
                        {Object.keys(entry.native_tools).length
                          ? `内置工具: ${Object.keys(entry.native_tools).join("、")}`
                          : "无内置服务端工具"}
                      </small>
                    </button>
                  ))}
                </div>
              </fieldset>
            )}
            {step === 2 && spec && (
              <fieldset className="model-form-section">
                <legend><i>02</i> 填写凭据（{spec.label}）</legend>
                <div className="model-form-grid">
                  <label>配置名称<small>仅用于管理后台识别</small>
                    <input value={draft.name} onChange={(e) => change("name", e.target.value)} required /></label>
                  <label>API 协议
                    <small>切换协议会按 wire 格式重新过滤可启用的内置工具</small>
                    <select value={draft.api_style} onChange={(e) => changeApiStyle(e.target.value)}
                      disabled={spec.api_styles.length === 1}>
                      {spec.api_styles.map((style) => <option key={style} value={style}>{style}</option>)}
                    </select></label>
                </div>
                <label>Base URL<small>OpenAI 兼容网关地址；Gemini 使用官方端点无需填写</small>
                  <input value={draft.base_url} onChange={(e) => change("base_url", e.target.value)}
                    placeholder={spec.default_base_url || "https://…"} required={gatewayStyle} /></label>
                {gatewayStyle && (
                  <label>网关端点模式<small>仅平台把完整资源端点注册为网关时选择完整端点</small>
                    <select value={draft.gateway_mode} onChange={(e) => change("gateway_mode", e.target.value)}>
                      <option value="base_url">标准 Base URL（请求 API 资源路径）</option>
                      <option value="full_endpoint">完整资源端点网关（请求网关根路径）</option>
                    </select></label>
                )}
                {editing?.api_key_status === "invalid" && (
                  <p className="field-help key-invalid-hint">
                    ⚠ 该配置的加密密钥已丢失或被轮换，运行时已被停用。请重新填写下方 API Key 并保存即可修复。
                  </p>
                )}
                <label>API Key<small>{editing?.has_api_key ? `当前 ${editing.api_key_masked}；留空则保持不变` : "将使用 Fernet 加密后保存"}</small>
                  <input type="password" value={draft.api_key} onChange={(e) => change("api_key", e.target.value)}
                    placeholder={editing?.has_api_key ? "留空保持现有密钥" : "sk-…"}
                    autoComplete="new-password" disabled={!!draft.clear_api_key}
                    required={editing?.api_key_status === "invalid"} /></label>
                {editing?.has_api_key && (
                  <label className="inline-danger">
                    <input type="checkbox" checked={draft.clear_api_key}
                      onChange={(e) => change("clear_api_key", e.target.checked)} /> 删除已保存 API Key
                  </label>
                )}
              </fieldset>
            )}
            {step === 3 && spec && (
              <fieldset className="model-form-section">
                <legend><i>03</i> 模型列表</legend>
                <div className="model-probe-row">
                  <button type="button" className="quiet-button" onClick={() => void probe()} disabled={probing}>
                    {probing ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />}
                    访问 {spec.models_probe === "ollama" ? "/api/tags" : spec.models_probe === "gemini" ? "/v1beta/models" : spec.models_probe === "anthropic" ? "/v1/models" : "/models"} 拉取
                  </button>
                  <label className="manual-add">
                    <input value={manualName} onChange={(e) => setManualName(e.target.value)}
                      placeholder="或手动输入模型名称，如 qwen3-max"
                      onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addModel(manualName); } }} />
                    <button type="button" className="quiet-button" onClick={() => addModel(manualName)}>
                      <Plus size={14} /> 添加
                    </button>
                  </label>
                </div>
                {!!fetched.length && (
                  <div className="model-chips">
                    {fetched.map((name) => (
                      <button type="button" key={name} className="model-chip addable" onClick={() => addModel(name)}>
                        <Plus size={11} /> {name}
                      </button>
                    ))}
                  </div>
                )}
                <div className="wizard-model-list">
                  {models.map((m, index) => (
                    <div key={`${m.name}-${index}`} className={`wizard-model-row ${m.enabled ? "" : "off"}`}>
                      <label className="inline-toggle">
                        <input type="checkbox" checked={m.enabled} onChange={(e) => patchModel(index, { enabled: e.target.checked })} />
                        <code>{m.name}</code>
                      </label>
                      <button type="button" className="danger-button compact" onClick={() => removeModel(index)}>
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))}
                  {!models.length && <p className="empty-note">尚未添加模型：拉取或手动输入均可</p>}
                </div>
              </fieldset>
            )}
            {step === 4 && spec && (
              <fieldset className="model-form-section">
                <legend><i>04</i> 每个模型的超参数</legend>
                {models.map((m, index) => (
                  <details key={`${m.name}-${index}`} className="model-advanced" open={models.length <= 3}>
                    <summary>{m.name}{m.vision ? " · 多模态" : ""}{m.enabled ? "" : "（停用）"}</summary>
                    <div className="model-form-grid three">
                      {spec.params.temperature && <label>Temperature<small>0 稳定 · 2 发散</small>
                        <input type="number" min={0} max={2} step={0.05} value={m.settings.temperature}
                          onChange={(e) => patchModelSettings(index, { temperature: Number(e.target.value) })} /></label>}
                      {spec.params.top_p && <label>Top P<small>核采样范围</small>
                        <input type="number" min={0.01} max={1} step={0.01} value={m.settings.top_p}
                          onChange={(e) => patchModelSettings(index, { top_p: Number(e.target.value) })} /></label>}
                      {spec.params.top_k && <label>Top K<small>留空使用默认</small>
                        <input type="number" min={1} max={128} value={m.settings.top_k ?? ""}
                          onChange={(e) => patchModelSettings(index, { top_k: e.target.value === "" ? null : Number(e.target.value) })} /></label>}
                      {spec.params.max_tokens && <label>Max Tokens<small>0 使用服务端默认值</small>
                        <input type="number" min={0} max={1048576} value={m.settings.max_tokens}
                          onChange={(e) => patchModelSettings(index, { max_tokens: Number(e.target.value) })} /></label>}
                      <label>Context Size
                        <input type="number" min={1024} max={10485760} value={m.settings.context_size}
                          onChange={(e) => patchModelSettings(index, { context_size: Number(e.target.value) })} /></label>
                      <label>Timeout / 秒
                        <input type="number" min={1} max={3600} value={m.settings.timeout_seconds}
                          onChange={(e) => patchModelSettings(index, { timeout_seconds: Number(e.target.value) })} /></label>
                      <label>Max Retries
                        <input type="number" min={0} max={10} value={m.settings.max_retries}
                          onChange={(e) => patchModelSettings(index, { max_retries: Number(e.target.value) })} /></label>
                      {spec.params.thinking_budget && <label>Thinking Budget<small>0 使用默认</small>
                        <input type="number" min={0} max={1048576} value={m.settings.thinking_budget}
                          onChange={(e) => patchModelSettings(index, { thinking_budget: Number(e.target.value) })} /></label>}
                    </div>
                    <label className="inline-toggle">
                      <input type="checkbox" checked={m.settings.thinking_enabled}
                        onChange={(e) => patchModelSettings(index, { thinking_enabled: e.target.checked })} />
                      <span><b>启用推理能力</b><small>思考强度仍由任务发起时的思考级别决定</small></span>
                    </label>
                    <label className="inline-toggle">
                      <input type="checkbox" checked={m.vision}
                        onChange={(e) => patchModel(index, { vision: e.target.checked })} />
                      <span><b>多模态（视觉）模型</b><small>任务开启视觉输入时优先选择该模型</small></span>
                    </label>
                    <label className="inline-toggle">
                      <input type="checkbox" checked={m.enabled}
                        onChange={(e) => patchModel(index, { enabled: e.target.checked })} />
                      <span><b>在任务创建页可选</b><small>停用后不出现在模型下拉中</small></span>
                    </label>
                  </details>
                ))}
                {!models.length && <p className="empty-note">请先在上一步添加模型</p>}
              </fieldset>
            )}
            {step === 5 && spec && (
              <fieldset className="model-form-section">
                <legend><i>05</i> 供应商内置工具与启用</legend>
                {availableTools.length ? Object.entries(spec.native_tools).filter(([key]) => availableTools.includes(key)).map(([key, meta]) => (
                  <label key={key} className="inline-toggle">
                    <input type="checkbox" checked={draft.enabled_tools.includes(key)}
                      onChange={(e) => change("enabled_tools",
                        e.target.checked ? [...draft.enabled_tools, key] : draft.enabled_tools.filter((t) => t !== key))} />
                    <span><b>{meta.label}</b><small>{meta.description}</small></span>
                  </label>
                )) : <p className="field-help">该供应商在当前协议下没有可启用的服务端内置工具。</p>}
                <label className="inline-toggle">
                  <input type="checkbox" checked={draft.enabled} onChange={(e) => change("enabled", e.target.checked)} />
                  <span><b>启用此供应商</b><small>停用后任务创建页不可选择</small></span>
                </label>
                <section className="model-policy">
                  <b>灵枢运行策略</b>
                  <span>Streaming ON</span><span>TOOLS STATE-GUARDED</span>
                  <small>为保证实时消息与状态机顺序，流式与权限参数由系统锁定。</small>
                </section>
              </fieldset>
            )}
            <div className="modal-actions">
              {step > 1 && <button type="button" className="quiet-button" onClick={() => setStep((s) => s - 1)}>上一步</button>}
              {step < 5 && (
                <button type="button" className="danger-button"
                  disabled={(step === 1 && !spec) || (step === 3 && !models.length)}
                  onClick={() => setStep((s) => s + 1)}>
                  下一步
                </button>
              )}
              {step === 5 && <button className="danger-button" disabled={saving}>{saving ? "保存中…" : "保存配置"}</button>}
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
