export type Session = {
  id: string;
  target?: string;
  goal?: string;
  title?: string;
  phase?: string;
  is_live?: boolean;
  success?: boolean | null;
  created_at?: string;
  status?: string;
  provider?: string;
  model?: string;
  model_level?: string;
  model_name?: string;
  thinking_intensity?: string;
  target_info?: { run_mode?: string } & Record<string, unknown>;
};
export type Event = Record<string, unknown> & {
  seq?: number;
  event_type?: string;
  type?: string;
  content?: string;
  agent_name?: string;
  agent?: string;
  payload?: Record<string, unknown>;
  delta?: string;
  full_text?: string;
  message?: string;
  reason?: string;
  block_id?: string;
  reply_id?: string;
  tool_call_id?: string;
  tool_name?: string;
  full_args?: string;
};
export type SystemUser = {
  id: number;
  username: string;
  email?: string;
  role: string;
  created_at?: string;
  last_login?: string | null;
};
export type ModelApiConfig = {
  id: number;
  name: string;
  category: "llm" | "embedding";
  provider: string;
  api_style: "chat_completions" | "responses" | "embeddings";
  base_url: string;
  gateway_mode: "base_url" | "full_endpoint";
  native_tools: string[];
  has_api_key: boolean;
  api_key_masked: string;
  api_key_status?: "ok" | "invalid" | "unset";
  model_low: string;
  model_min: string;
  model_max: string;
  model_name: string;
  vision_model?: string;
  dimensions: number;
  pass_dimensions: boolean;
  enabled: boolean;
  settings: {
    temperature: number;
    top_p: number;
    max_tokens: number;
    max_retries: number;
    context_size: number;
    timeout_seconds: number;
    thinking_enabled: boolean;
  };
  created_at?: string;
  updated_at?: string;
};
export type ModelApiConfigInput = Omit<
  ModelApiConfig,
  "id" | "has_api_key" | "api_key_masked" | "created_at" | "updated_at"
> & { api_key?: string; clear_api_key?: boolean };
export type ModelProviderOption = {
  id: string;
  label: string;
  provider?: string;
  api_style: string;
  builtin: boolean;
  models?: string[];
  models_detail?: { name: string; vision: boolean }[];
  vision_model?: string;
  owner?: "platform" | "mine";
};

// ── v2 供应商管理（core/providers.py 目录驱动） ──
export type ProviderModelSettings = {
  temperature: number;
  top_p: number;
  top_k: number | null;
  max_tokens: number;
  max_retries: number;
  context_size: number;
  timeout_seconds: number;
  thinking_enabled: boolean;
  thinking_budget: number;
};
export type ManagedProviderModel = {
  name: string;
  enabled: boolean;
  vision: boolean;
  settings: ProviderModelSettings;
};
export type ProviderCatalogEntry = {
  key: string;
  label: string;
  driver: string;
  api_styles: string[];
  default_api_style: string;
  default_base_url: string;
  models_endpoint: string | null;
  models_probe: string;
  params: {
    temperature: boolean;
    top_p: boolean;
    top_k: boolean;
    max_tokens: boolean;
    thinking_budget: boolean;
    reasoning_efforts: string[];
  };
  native_tools: Record<string, { label: string; description: string; wire: string }>;
  default_models: string[];
  default_settings: Record<string, unknown>;
  docs_url: string;
};
export type ManagedProvider = {
  id: number;
  name: string;
  provider: string;
  api_style: string;
  base_url: string;
  gateway_mode: string;
  enabled_tools: string[];
  has_api_key: boolean;
  api_key_masked: string;
  api_key_status?: "ok" | "invalid" | "unset";
  enabled: boolean;
  models: ManagedProviderModel[];
  enabled_models?: string[];
  owner?: "platform" | "mine";
  owner_id?: number | null;
  created_at?: string;
  updated_at?: string;
};
export type LLMProviderInput = {
  name: string;
  provider: string;
  api_style: string;
  base_url: string;
  gateway_mode: string;
  enabled_tools: string[];
  api_key?: string;
  clear_api_key?: boolean;
  enabled: boolean;
  models: ManagedProviderModel[];
};
export type AgentModelBindingInputType = {
  provider: string;
  model: string;
  thinking_intensity: string | null;
};
export type AgentModelBindingRole = AgentModelBindingInputType & {
  role: string;
  label: string;
};
export type UserProfile = {
  id: number;
  username: string;
  email: string;
  role: string;
  created_at?: string;
  last_login?: string;
};
export type UsageGroupRow = {
  key: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
};
export type UserUsageSummary = {
  user_id: number;
  days: number;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  by_provider: UsageGroupRow[];
  by_model: UsageGroupRow[];
  by_session: UsageGroupRow[];
};
export type PlatformUsageSummary = {
  days: number;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  by_user: (UsageGroupRow & { user_id: number })[];
  by_provider: UsageGroupRow[];
  by_model: UsageGroupRow[];
};
export type ToolStatus = {
  id: string;
  category?: string;
  kind?: string;
  status?: string;
  command?: string;
  roles?: string[];
  risk?: string;
  approval_required?: boolean;
  description?: string;
  usage_hint?: string;
  alternatives?: string[];
  version?: string;
  error?: string;
};
export type PythonPackageStatus = {
  name: string;
  version: string;
  required?: string;
  status: "matched" | "untracked" | "missing" | "version_mismatch";
};
export type PythonEnvironmentStatus = {
  interpreter: string;
  package_count: number;
  requirements_count: number;
  counts: Record<string, number>;
  packages: PythonPackageStatus[];
  ignored_requirement_lines?: string[];
};
export type ToolingCatalog = {
  tools: ToolStatus[];
  counts: Record<string, number>;
  environment?: { python?: PythonEnvironmentStatus };
};
const base = import.meta.env.VITE_API_BASE_URL || "";
let token = localStorage.getItem("lingshu_token") || "";
export const auth = {
  get: () => token,
  set: (value: string) => {
    token = value;
    localStorage.setItem("lingshu_token", value);
  },
  clear: () => {
    token = "";
    localStorage.removeItem("lingshu_token");
  },
};
async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  const response = await fetch(base + url, { ...options, headers });
  const data = await response.json().catch(() => null);
  if (!response.ok)
    throw new Error(data?.detail || `请求失败 (${response.status})`);
  return data as T;
}
export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  register: (username: string, password: string, email = "", invite_code = "") =>
    request("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password, email, invite_code }),
    }),
  version: () => request<{ branch: string; commit: string }>("/api/version"),
  me: () => request<{ id: number; username: string; role: string; onboarded?: boolean }>("/auth/me"),
  markOnboarded: () => request<{ message: string }>("/auth/onboarded", { method: "PUT" }),
  superadminUsers: () => request<{ users: SystemUser[] }>("/api/superadmin/users"),
  resetUserPassword: (userId: number, password: string) =>
    request<{ message: string }>(`/api/superadmin/users/${encodeURIComponent(String(userId))}/password`, {
      method: "PUT",
      body: JSON.stringify({ password }),
    }),
  deleteUser: (userId: number) =>
    request<{ message: string }>(`/api/superadmin/users/${encodeURIComponent(String(userId))}`, {
      method: "DELETE",
    }),
  modelConfigs: (category?: "llm" | "embedding") =>
    request<{ configs: ModelApiConfig[] }>(
      `/api/superadmin/model-configs${category ? `?category=${category}` : ""}`,
    ),
  modelProviders: () =>
    request<{ providers: ModelProviderOption[] }>("/api/model-providers"),
  createModelConfig: (data: ModelApiConfigInput) =>
    request<{ config: ModelApiConfig; rag_status?: Record<string, unknown> }>(
      "/api/superadmin/model-configs",
      { method: "POST", body: JSON.stringify(data) },
    ),
  updateModelConfig: (id: number, data: ModelApiConfigInput) =>
    request<{ config: ModelApiConfig; rag_status?: Record<string, unknown> }>(
      `/api/superadmin/model-configs/${encodeURIComponent(String(id))}`,
      { method: "PUT", body: JSON.stringify(data) },
    ),
  deleteModelConfig: (id: number) =>
    request<{ message: string; rag_status?: Record<string, unknown> }>(
      `/api/superadmin/model-configs/${encodeURIComponent(String(id))}`,
      { method: "DELETE" },
    ),
  // ── v2 供应商管理 ──
  providerCatalog: () =>
    request<{ providers: ProviderCatalogEntry[] }>(
      "/api/superadmin/providers/catalog",
    ),
  llmProviders: () =>
    request<{ providers: ManagedProvider[] }>("/api/superadmin/model-providers"),
  createLLMProvider: (data: LLMProviderInput) =>
    request<{ provider: ManagedProvider }>("/api/superadmin/model-providers", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateLLMProvider: (id: number, data: LLMProviderInput) =>
    request<{ provider: ManagedProvider }>(
      `/api/superadmin/model-providers/${encodeURIComponent(String(id))}`,
      { method: "PUT", body: JSON.stringify(data) },
    ),
  deleteLLMProvider: (id: number) =>
    request<{ message: string }>(
      `/api/superadmin/model-providers/${encodeURIComponent(String(id))}`,
      { method: "DELETE" },
    ),
  probeModels: (data: { provider: string; base_url: string; api_key: string }) =>
    request<{ models: string[]; endpoint: string }>(
      "/api/superadmin/model-providers/probe-models",
      { method: "POST", body: JSON.stringify(data) },
    ),
  probeModelsSaved: (id: number) =>
    request<{ models: string[]; endpoint: string }>(
      `/api/superadmin/model-providers/${encodeURIComponent(String(id))}/probe-models`,
      { method: "POST" },
    ),
  addProviderModel: (
    id: number,
    model: { name: string; enabled?: boolean; vision?: boolean; settings?: Partial<ProviderModelSettings> },
  ) =>
    request<{ model: ManagedProviderModel }>(
      `/api/superadmin/model-providers/${encodeURIComponent(String(id))}/models`,
      { method: "POST", body: JSON.stringify(model) },
    ),
  updateProviderModel: (
    id: number,
    payload: { model: string } & Partial<ManagedProviderModel>,
  ) =>
    request<{ model: ManagedProviderModel }>(
      `/api/superadmin/model-providers/${encodeURIComponent(String(id))}/models`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  deleteProviderModel: (id: number, model: string) =>
    request<{ message: string }>(
      `/api/superadmin/model-providers/${encodeURIComponent(String(id))}/models?model=${encodeURIComponent(model)}`,
      { method: "DELETE" },
    ),
  // ── 用户级模型管理（每用户私有供应商池 + Agent 模型分工）──
  userProviderCatalog: () =>
    request<{ providers: ProviderCatalogEntry[] }>("/api/providers/catalog"),
  myLLMProviders: () =>
    request<{ providers: ManagedProvider[] }>("/api/my/model-providers"),
  myCreateLLMProvider: (data: LLMProviderInput) =>
    request<{ provider: ManagedProvider }>("/api/my/model-providers", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  myUpdateLLMProvider: (id: number, data: LLMProviderInput) =>
    request<{ provider: ManagedProvider }>(
      `/api/my/model-providers/${encodeURIComponent(String(id))}`,
      { method: "PUT", body: JSON.stringify(data) },
    ),
  myDeleteLLMProvider: (id: number) =>
    request<{ message: string }>(
      `/api/my/model-providers/${encodeURIComponent(String(id))}`,
      { method: "DELETE" },
    ),
  myProbeModels: (data: { provider: string; base_url: string; api_key: string }) =>
    request<{ models: string[]; endpoint: string }>(
      "/api/my/model-providers/probe-models",
      { method: "POST", body: JSON.stringify(data) },
    ),
  myProbeModelsSaved: (id: number) =>
    request<{ models: string[]; endpoint: string }>(
      `/api/my/model-providers/${encodeURIComponent(String(id))}/probe-models`,
      { method: "POST" },
    ),
  myAddProviderModel: (
    id: number,
    model: { name: string; enabled?: boolean; vision?: boolean; settings?: Partial<ProviderModelSettings> },
  ) =>
    request<{ model: ManagedProviderModel }>(
      `/api/my/model-providers/${encodeURIComponent(String(id))}/models`,
      { method: "POST", body: JSON.stringify(model) },
    ),
  myUpdateProviderModel: (
    id: number,
    payload: { model: string } & Partial<ManagedProviderModel>,
  ) =>
    request<{ model: ManagedProviderModel }>(
      `/api/my/model-providers/${encodeURIComponent(String(id))}/models`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  myDeleteProviderModel: (id: number, model: string) =>
    request<{ message: string }>(
      `/api/my/model-providers/${encodeURIComponent(String(id))}/models?model=${encodeURIComponent(model)}`,
      { method: "DELETE" },
    ),
  agentModelBindings: () =>
    request<{ roles: AgentModelBindingRole[]; intensities: string[] }>(
      "/api/agent-model-bindings",
    ),
  saveAgentModelBindings: (
    bindings: Record<string, AgentModelBindingInputType | null>,
  ) =>
    request<{ bindings: Record<string, AgentModelBindingInputType> }>(
      "/api/agent-model-bindings",
      { method: "PUT", body: JSON.stringify({ bindings }) },
    ),
  // ── 账号自助设置 ──
  profile: () =>
    request<UserProfile>("/auth/profile"),
  updateProfile: (data: { username: string; email: string }) =>
    request<{ profile: UserProfile; message: string }>("/auth/profile", {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  changePassword: (data: { old_password: string; new_password: string }) =>
    request<{ message: string }>("/auth/password", {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  // ── Token 用量统计 ──
  myTokenUsage: (days = 30) =>
    request<UserUsageSummary>(`/api/my/token-usage?days=${encodeURIComponent(String(days))}`),
  superadminTokenUsage: (days = 30) =>
    request<PlatformUsageSummary>(`/api/superadmin/token-usage?days=${encodeURIComponent(String(days))}`),
  sessions: async (offset = 0, limit = 30) => {
    const data = await request<{ sessions?: unknown; has_more?: unknown; next_offset?: unknown }>(
      `/api/sessions?limit=${encodeURIComponent(String(limit))}&offset=${encodeURIComponent(String(offset))}`,
    );
    const sessions = Array.isArray(data?.sessions)
      ? data.sessions.filter(
          (item): item is Session =>
            !!item && typeof item === "object" && typeof item.id === "string",
        )
      : [];
    return {
      sessions,
      hasMore: data?.has_more === true,
      nextOffset: Number(data?.next_offset || offset + sessions.length),
    };
  },
  session: (id: string) =>
    request<Session & Record<string, unknown>>(
      `/api/session/${encodeURIComponent(id)}`,
    ),
  messages: async (
    id: string,
    options: { beforeSeq?: number; afterSeq?: number; limit?: number } = {},
  ) => {
    const params = new URLSearchParams();
    params.set("limit", String(options.limit || 200));
    if (options.beforeSeq !== undefined)
      params.set("before_seq", String(options.beforeSeq));
    if (options.afterSeq !== undefined)
      params.set("after_seq", String(options.afterSeq));
    const data = await request<{
      messages?: unknown;
      snapshots?: unknown;
      has_more?: unknown;
      oldest_seq?: unknown;
      newest_seq?: unknown;
    }>(
      `/api/session/${encodeURIComponent(id)}/messages?${params.toString()}`,
    );
    const messages = Array.isArray(data?.messages)
      ? data.messages.map((item) =>
          item && typeof item === "object"
            ? (item as Event)
            : ({ event_type: "message", content: String(item ?? "") } as Event),
        )
      : [];
    const snapshots = Array.isArray(data?.snapshots)
      ? data.snapshots.flatMap((item): Event[] => {
          if (!item || typeof item !== "object") return [];
          const snapshot = item as Record<string, unknown>;
          const streamType = String(snapshot.stream_type || "text");
          return [
            {
              ...snapshot,
              event_type: `${streamType}_stream`,
              agent_name: String(snapshot.agent_name || "system"),
              content: String(snapshot.content || ""),
              _streamKey: String(
                snapshot.block_id ||
                  snapshot.reply_id ||
                  `${snapshot.agent_name || "system"}:${streamType}`,
              ),
              _family: streamType,
            },
          ];
        })
      : [];
    return {
      messages,
      snapshots,
      hasMore: data?.has_more === true,
      oldestSeq: Number(data?.oldest_seq || 0),
      newestSeq: Number(data?.newest_seq || 0),
    };
  },
  create: (data: Record<string, string | boolean>) =>
    request<{ session_id: string }>("/api/session/start", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  send: (id: string, content: string) =>
    request(`/api/session/${encodeURIComponent(id)}/message`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),
  approvalDecision: (
    id: string,
    decision: "批准" | "补充侦察" | "拒绝",
    selection: { selected_plan_id: string; priority_order: string[] },
  ) =>
    request(`/api/session/${encodeURIComponent(id)}/message`, {
      method: "POST",
      body: JSON.stringify({ content: decision, approval_selection: selection }),
    }),
  cancel: (id: string) =>
    request(`/api/session/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
    }),
  remove: (id: string) =>
    request(`/api/session/${encodeURIComponent(id)}`, { method: "DELETE" }),
  approval: (id: string) =>
    request<{ pending: boolean; event?: Record<string, unknown> }>(
      `/api/session/${encodeURIComponent(id)}/pending_approval`,
    ),
  upload: (files: File[]) => {
    const body = new FormData();
    files.forEach((file) => body.append("files", file));
    return request<{
      files: { filename: string; path: string; size: number }[];
      path: string;
      target: string;
      count: number;
      total_size: number;
    }>(
      "/api/mission/upload",
      { method: "POST", body },
    );
  },
  report: async (id: string) => {
    const response = await fetch(
      base + `/api/session/${encodeURIComponent(id)}/report`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} },
    );
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      throw new Error(data?.detail || `报告下载失败 (${response.status})`);
    }
    return response.blob();
  },
  reportMarkdown: async (id: string) => {
    const response = await fetch(
      base + `/api/session/${encodeURIComponent(id)}/report/markdown`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} },
    );
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      throw new Error(data?.detail || `Markdown 报告下载失败 (${response.status})`);
    }
    return response.blob();
  },
  jsonl: async (id: string) => {
    const response = await fetch(
      base + `/api/session/${encodeURIComponent(id)}/jsonl`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} },
    );
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      throw new Error(data?.detail || `JSONL 导出失败 (${response.status})`);
    }
    return response.blob();
  },
  knowledgeStatus: () =>
    request<Record<string, unknown>>("/api/knowledge/status"),
  toolingCatalog: (refresh = false) =>
    request<ToolingCatalog>(
      `/api/tooling/catalog${refresh ? "?refresh=true" : ""}`,
    ),
  knowledgeSearch: (query: string) =>
    request<{ results: { score: number; source: string; snippet: string }[] }>(
      "/api/knowledge/search",
      { method: "POST", body: JSON.stringify({ query }) },
    ),
  reindex: () =>
    request<Record<string, unknown>>("/api/knowledge/reindex", {
      method: "POST",
    }),
};
export async function* stream(
  id: string,
  signal: AbortSignal,
  afterSeq = 0,
): AsyncGenerator<Event> {
  let cursor = afterSeq;
  let retryDelay = 400;
  while (!signal.aborted) {
    try {
      const response = await fetch(
        base + `/api/session/${encodeURIComponent(id)}/stream?after_seq=${cursor}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "text/event-stream",
          },
          signal,
        },
      );
      // 任务正常结束后活跃流端点会返回 404，此时不再无意义重连。
      if (response.status === 404) return;
      if (!response.ok || !response.body)
        throw new Error(`实时连接失败 (${response.status})`);
      retryDelay = 400;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (!signal.aborted) {
        const { done, value } = await reader.read();
        buf += decoder.decode(value || new Uint8Array(), { stream: !done });
        const frames = buf.split(/\r?\n\r?\n/);
        buf = frames.pop() || "";
        for (const frame of frames) {
          const raw = frame
            .split(/\r?\n/)
            .filter((x) => x.startsWith("data:"))
            .map((x) => x.slice(5).trim())
            .join("\n");
          if (!raw) continue;
          try {
            const parsed = JSON.parse(raw);
            const event: Event = parsed && typeof parsed === "object"
              ? parsed
              : { event_type: "message", content: String(parsed ?? "") };
            cursor = Math.max(cursor, Number(event.seq || 0));
            yield event;
            const kind = String(event.type || event.event_type || "");
            if (["mission_end", "mission_cancelled", "session_deleted"].includes(kind)) {
              await reader.cancel().catch(() => undefined);
              return;
            }
          } catch {}
        }
        if (done) break;
      }
    } catch (error) {
      if (signal.aborted) return;
      console.warn("实时连接中断，准备续传", error);
    }
    if (signal.aborted) return;
    await abortableDelay(retryDelay, signal);
    retryDelay = Math.min(retryDelay * 2, 5000);
  }
}

async function abortableDelay(milliseconds: number, signal: AbortSignal) {
  await new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const timer = window.setTimeout(done, milliseconds);
    function done() {
      window.clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });
}

export async function* accountStream(signal: AbortSignal): AsyncGenerator<Event> {
  let retryDelay = 500;
  while (!signal.aborted) {
    try {
      const response = await fetch(base + "/api/agent-service/account/stream", {
        headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" },
        signal,
      });
      if (!response.ok || !response.body)
        throw new Error(`账户实时连接失败 (${response.status})`);
      retryDelay = 500;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!signal.aborted) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
        const frames = buffer.split(/\r?\n\r?\n/);
        buffer = frames.pop() || "";
        for (const frame of frames) {
          const raw = frame.split(/\r?\n/)
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).trim()).join("\n");
          if (!raw) continue;
          try { yield JSON.parse(raw) as Event; } catch {}
        }
        if (done) break;
      }
    } catch (error) {
      if (signal.aborted) return;
      console.warn("账户实时连接中断，准备重连", error);
    }
    await abortableDelay(retryDelay, signal);
    retryDelay = Math.min(retryDelay * 2, 5000);
  }
}
