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
  if (options.body) headers.set("Content-Type", "application/json");
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
  register: (username: string, password: string, email = "") =>
    request("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password, email }),
    }),
  sessions: async () => {
    const data = await request<{ sessions?: unknown }>(
      "/api/sessions?limit=200",
    );
    const sessions = Array.isArray(data?.sessions)
      ? data.sessions.filter(
          (item): item is Session =>
            !!item && typeof item === "object" && typeof item.id === "string",
        )
      : [];
    return { sessions };
  },
  session: (id: string) =>
    request<Session & Record<string, unknown>>(
      `/api/session/${encodeURIComponent(id)}`,
    ),
  messages: async (id: string, after = 0) => {
    const data = await request<{ messages?: unknown; snapshots?: unknown }>(
      `/api/session/${encodeURIComponent(id)}/messages?after_seq=${after}&limit=5000`,
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
    return { messages, snapshots };
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
  cancel: (id: string) =>
    request(`/api/session/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
    }),
  remove: (id: string) =>
    request(`/api/session/${encodeURIComponent(id)}`, { method: "DELETE" }),
  approval: (id: string) =>
    request(`/api/session/${encodeURIComponent(id)}/pending_approval`),
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
  const response = await fetch(
    base +
      `/api/session/${encodeURIComponent(id)}/stream?after_seq=${afterSeq}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "text/event-stream",
      },
      signal,
    },
  );
  if (!response.ok || !response.body) throw new Error("实时连接失败");
  const reader = response.body.getReader(),
    decoder = new TextDecoder();
  let buf = "";
  while (true) {
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
      if (raw)
        try {
          const parsed = JSON.parse(raw);
          yield parsed && typeof parsed === "object"
            ? parsed
            : { event_type: "message", content: String(parsed ?? "") };
        } catch {}
    }
    if (done) break;
  }
}
