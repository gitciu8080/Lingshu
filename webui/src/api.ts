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
  model_low: string;
  model_min: string;
  model_max: string;
  model_name: string;
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
  api_style: string;
  builtin: boolean;
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
  me: () => request<{ id: number; username: string; role: string }>("/auth/me"),
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
  create: (data: Record<string, string>) =>
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
  jsonl: async (id: string, prefix = "") => {
    const query = prefix ? `?prefix=${encodeURIComponent(prefix)}` : "";
    const response = await fetch(
      base + `/api/session/${encodeURIComponent(id)}/jsonl${query}`,
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
