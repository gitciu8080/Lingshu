import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Bot,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  ClipboardList,
  Crosshair,
  Database,
  FlaskConical,
  LogOut,
  Moon,
  Network,
  Plus,
  Search,
  Send,
  ShieldAlert,
  RotateCcw,
  Square,
  Sun,
  Swords,
  Terminal,
  Trash2,
  X,
} from "lucide-react";
import { toast } from "sonner";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, auth, Event, Session, stream } from "./api";
import lightLogo from "./logo2.png";
import darkLogo from "./logored.png";

type Mission = Record<string, unknown> & {
  plan_items?: PlanItem[];
  findings?: unknown[];
  flag?: string;
  goal?: string;
  phase?: string;
  exploitation_approved?: boolean;
};
type PlanItem = {
  id: string;
  content: string;
  phase: string;
  status: string;
  evidence?: string;
  expert?: string;
  origin?: string;
};
const AGENTS: Record<
  string,
  {
    label: string;
    expert: string;
    icon: typeof Bot;
    tone: string;
    role: string;
  }
> = {
  Brain: {
    label: "战略总参谋",
    expert: "Sophia - 战略规划专家",
    icon: BrainCircuit,
    tone: "brain",
    role: "战略规划",
  },
  Recon: { label: "网络侦察", expert: "Ethan - 网络侦察专家", icon: Network, tone: "recon", role: "情报采集" },
  ArtifactTriage: {
    label: "文件研判",
    expert: "Iris - 文件分析专家",
    icon: FlaskConical,
    tone: "analysis",
    role: "静态分析",
  },
  Analysis: {
    label: "漏洞研判",
    expert: "Nora - 漏洞研判专家",
    icon: FlaskConical,
    tone: "analysis",
    role: "证据分析",
  },
  Attack: { label: "验证专家", expert: "Mike - WEB渗透专家", icon: Swords, tone: "attack", role: "授权验证" },
  Orchestrator: {
    label: "行动指挥",
    expert: "Alex - 行动指挥专家",
    icon: Crosshair,
    tone: "orchestrator",
    role: "阶段调度",
  },
  Reserve: {
    label: "逆向专家",
    expert: "Ryan - 逆向程序专家",
    icon: Terminal,
    tone: "analysis",
    role: "二进制分析",
  },
  system: {
    label: "系统",
    expert: "系统事件",
    icon: ShieldAlert,
    tone: "system",
    role: "任务事件",
  },
  user: { label: "操作员", expert: "授权操作员", icon: Bot, tone: "user", role: "人工指令" },
};

const EXPERT_HINTS: [RegExp, keyof typeof AGENTS][] = [
  [/Sophia|战略规划/, "Brain"],
  [/Alex|行动指挥/, "Orchestrator"],
  [/Ethan|网络侦察/, "Recon"],
  [/Iris|文件分析|数字取证/, "ArtifactTriage"],
  [/Nora|漏洞研判/, "Analysis"],
  [/Mike|Victor|Alice|Morgan|Taylor|Olivia|Ada|渗透专家|利用专家|安全验证/, "Attack"],
  [/Ryan|逆向程序|逆向利用/, "Reserve"],
];
function safeEvent(value: unknown): Event {
  return value && typeof value === "object"
    ? (value as Event)
    : {
        event_type: "message",
        agent_name: "system",
        content: String(value ?? ""),
      };
}
function payloadOf(event: Event): Record<string, unknown> {
  if (event.payload && typeof event.payload === "object") return event.payload;
  if (typeof event.content === "string" && event.content.trim().startsWith("{"))
    try {
      const value = JSON.parse(event.content);
      return value && typeof value === "object" ? value : {};
    } catch {}
  return {};
}
function dataOf(event: Event): Record<string, unknown> {
  return { ...event, ...payloadOf(event) };
}
function kindOf(event: Event) {
  return String(event.event_type || event.type || "message");
}
function agentOf(value: unknown) {
  const event = safeEvent(value),
    raw =
      event.agent_name ||
      event.agent ||
      (event.event_type === "user_message" ? "user" : "system"),
    name = String(raw || "system");
  const direct = AGENTS[name];
  if (direct) return { name, agentKey: name, ...direct };
  const expertKey = EXPERT_HINTS.find(([pattern]) => pattern.test(name))?.[1];
  if (expertKey) return { name, agentKey: expertKey, ...AGENTS[expertKey] };
  const key = Object.keys(AGENTS).find((item) =>
    name.toLowerCase().includes(item.toLowerCase()),
  );
  return key
    ? { name, agentKey: key, ...AGENTS[key] }
    : { name, agentKey: name, label: name, expert: name, icon: Bot, tone: "system", role: "智能体" };
}
function eventText(value: unknown) {
  const event = safeEvent(value);
  const data = dataOf(event);
  if (
    typeof event.content === "string" &&
    !event.content.trim().startsWith("{")
  )
    return event.content;
  return String(
    data.full_text ||
      data.delta ||
      data.message ||
      data.reason ||
      event.content ||
      "",
  );
}

const TOOL_LABELS: Record<string, string> = {
  scoped_shell: "执行受限命令",
  dispatch_recon: "调度侦察智能体",
  dispatch_attack: "调度验证智能体",
  analysis: "漏洞研判",
  cve_search: "检索 CVE 情报",
  request_exploitation_approval: "请求人工审批",
  view_mission_state: "查看任务状态",
  complete_mission: "结束任务",
  AddPlan: "添加计划",
  UpdatePlan: "更新计划",
  DeletePlan: "删除计划",
  ListPlan: "查看计划",
};

function findLastEventIndex(
  list: Event[],
  predicate: (event: Event) => boolean,
) {
  for (let index = list.length - 1; index >= 0; index -= 1) {
    if (predicate(list[index])) return index;
  }
  return -1;
}

function mergeEvent(list: Event[], value: Event): Event[] {
  const event = safeEvent(value);
  const kind = kindOf(event);
  const data = dataOf(event);
  const agent = String(event.agent_name || event.agent || "system");
  const family =
    kind === "stream_snapshot"
      ? String(data.stream_type || "text")
      : kind.startsWith("thinking_")
        ? "thinking"
        : "text";
  const streamKey = String(
    data.block_id || data.reply_id || `${agent}:${family}`,
  );

  if (["plan_updated", "target_info"].includes(kind)) return list;

  if (kind === "stream_snapshot") {
    const index = findLastEventIndex(
      list,
      (item) =>
        item._streamKey === streamKey ||
        (item._family === family && agentOf(item).name === agent),
    );
    const snapshot: Event = {
      ...event,
      event_type: `${family}_stream`,
      content: String(data.full_text || data.content || ""),
      _streamKey: streamKey,
      _family: family,
    };
    if (index < 0) return snapshot.content ? [...list, snapshot] : list;
    const next = [...list];
    next[index] = { ...next[index], ...snapshot };
    return next;
  }

  if (["text_start", "thinking_start"].includes(kind)) {
    return [
      ...list,
      { ...event, content: "", _streamKey: streamKey, _family: family },
    ];
  }

  if (["text_delta", "thinking_delta", "text_end", "thinking_end"].includes(kind)) {
    const index = findLastEventIndex(
      list,
      (item) =>
        item._streamKey === streamKey ||
        (item._family === family && agentOf(item).name === agent),
    );
    const isEnd = kind.endsWith("_end");
    const full = String(data.full_text || "");
    const delta = String(data.delta || "");
    if (index >= 0) {
      const previous = list[index];
      const content = isEnd
        ? full || String(previous.content || "")
        : String(previous.content || "") + delta;
      const next = [...list];
      next[index] = {
        ...previous,
        ...event,
        event_type: isEnd ? kind : `${family}_stream`,
        content,
        _streamKey: streamKey,
        _family: family,
      };
      return next;
    }
    const content = full || delta || eventText(event);
    return content
      ? [
          ...list,
          {
            ...event,
            event_type: isEnd ? kind : `${family}_stream`,
            content,
            _streamKey: streamKey,
            _family: family,
          },
        ]
      : list;
  }

  if (kind.startsWith("tool_call")) {
    const id = String(data.tool_call_id || data.reply_id || "");
    const index = id
      ? findLastEventIndex(
          list,
          (item) => String(dataOf(item).tool_call_id || "") === id,
        )
      : -1;
    if (kind === "tool_call_delta" && index < 0) return list;
    const previous = index >= 0 ? list[index] : undefined;
    const previousData = previous ? dataOf(previous) : {};
    const fullArgs = String(
      data.full_args ||
        (String(previousData.full_args || "") + String(data.delta || "")),
    );
    const merged: Event = {
      ...(previous || {}),
      ...event,
      event_type: kind === "tool_call_start" ? kind : "tool_call_end",
      tool_call_id: id,
      tool_name: String(data.tool_name || previousData.tool_name || ""),
      full_args: fullArgs,
    };
    if (index >= 0) {
      const next = [...list];
      next[index] = merged;
      return next;
    }
    return [...list, merged];
  }

  const text = eventText(event);
  const previous = list.at(-1);
  if (
    text &&
    previous &&
    eventText(previous) === text &&
    agentOf(previous).name === agent
  )
    return list;
  return [...list, event];
}

function normalizeEvents(values: Event[]) {
  return values.reduce<Event[]>((result, event) => mergeEvent(result, event), []);
}

function MarkdownContent({ children }: { children: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        a: ({ children: label, ...props }) => (
          <a {...props} target="_blank" rel="noreferrer">
            {label}
          </a>
        ),
      }}
    >
      {children}
    </ReactMarkdown>
  );
}

function systemNoticeText(event: Event) {
  const kind = kindOf(event);
  const data = dataOf(event);
  if (kind === "approval_required") return "⚠️ 等待人工审批…";
  if (kind === "approval_resolved")
    return data.approved === true
      ? "✅ 审批已通过，进入攻击阶段"
      : "❌ 审批已拒绝";
  if (kind === "phase_change")
    return `阶段切换 → ${phaseLabel(String(data.phase || event.content || ""))}`;
  if (kind === "mission_start") return `🚀 ${eventText(event)}`;
  if (kind === "mission_end") return `🏁 ${eventText(event)}`;
  if (kind === "mission_cancelled") return `⏹ ${eventText(event)}`;
  if (kind === "error") return `❌ ${eventText(event)}`;
  if (kind === "flag_found")
    return `🚩 FLAG 已找到：${String(data.flag || eventText(event))}`;
  const text = eventText(event);
  return text.trim().startsWith("{") ? "任务状态已更新" : text;
}
function phaseLabel(phase?: string) {
  return (
    (
      {
        planning: "规划",
        recon: "侦察",
        analysis: "研判",
        exploitation: "利用验证",
        post_exploitation: "后渗透",
        completed: "已完成",
        failed: "失败",
      } as Record<string, string>
    )[phase || ""] ||
    phase ||
    "--"
  );
}

function Login({ onReady }: { onReady: () => void }) {
  const [user, setUser] = useState(""),
    [password, setPassword] = useState(""),
    [register, setRegister] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      if (register) await api.register(user, password);
      const r = await api.login(user, password);
      auth.set(r.access_token);
      onReady();
    } catch (err) {
      toast.error(String(err));
    }
  };
  return (
    <main className="login-page">
      <form className="login-card" onSubmit={submit}>
        <div className="login-mark">
          <img className="theme-logo-light" src={lightLogo} alt="灵枢" />
          <img className="theme-logo-dark" src={darkLogo} alt="灵枢" />
          <i />
        </div>
        <h1>
          灵枢 <small>Lingshu</small>
        </h1>
        <p className="kicker">MULTI-AGENT SECURITY CONSOLE</p>
        <div className="login-tabs">
          <button
            type="button"
            className={!register ? "active" : ""}
            onClick={() => setRegister(false)}
          >
            登录
          </button>
          <button
            type="button"
            className={register ? "active" : ""}
            onClick={() => setRegister(true)}
          >
            注册
          </button>
        </div>
        <label>
          用户名
          <input
            value={user}
            onChange={(e) => setUser(e.target.value)}
            required
            placeholder="请输入用户名"
          />
        </label>
        <label>
          密码
          <input
            value={password}
            type="password"
            onChange={(e) => setPassword(e.target.value)}
            required
            placeholder="请输入密码"
          />
        </label>
        <button className="danger-button">
          {register ? "创建账户" : "进入控制台"} <span>→</span>
        </button>
        <footer>授权安全测试 · 全程审计 · v2.0</footer>
      </form>
    </main>
  );
}

function NewMission({ onCreated }: { onCreated: (id: string) => void }) {
  const [open, setOpen] = useState(false),
    [target, setTarget] = useState(""),
    [goal, setGoal] = useState("获取 Flag"),
    [provider, setProvider] = useState("deepseek"),
    [model, setModel] = useState("Min");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.create({ target, goal, provider, model });
      setOpen(false);
      onCreated(r.session_id);
    } catch (err) {
      toast.error(String(err));
    }
  };
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button className="new-mission">
          <Plus size={15} />
          新建测试任务
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="modal">
          <Dialog.Title>创建授权测试任务</Dialog.Title>
          <p>所有攻击类操作都将在利用前要求人工批准。</p>
          <form onSubmit={submit}>
            <label>
              授权目标
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
                placeholder="IP / 主机名 / 文件路径"
              />
            </label>
            <label>
              任务目标
              <input value={goal} onChange={(e) => setGoal(e.target.value)} />
            </label>
            <div className="select-row">
              <label>
                模型提供商
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                >
                  <option value="deepseek">DeepSeek</option>
                  <option value="qwen">Qwen</option>
                </select>
              </label>
              <label>
                思考级别
                <select
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                >
                  {["Low", "Min", "Max"].map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="modal-actions">
              <Dialog.Close className="quiet-button">取消</Dialog.Close>
              <button className="danger-button">启动任务</button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function AgentCard({ event: value }: { event: Event }) {
  const event = safeEvent(value),
    info = agentOf(event),
    Icon = info.icon,
    text = eventText(event),
    kind = kindOf(event),
    data = dataOf(event),
    displayName = info.name.includes(" - ") ? info.name : info.expert;
  if (kind === "expert_joined") {
    const expertName = String(
      data.expert_name || data.agent || "安全专家",
    );
    const expertInfo = agentOf({ agent_name: expertName });
    const ExpertIcon = expertInfo.icon;
    return (
      <div className="expert-join-row">
        <div className={`expert-join-card ${expertInfo.tone}`}>
          <span className="expert-icon">
            <ExpertIcon size={18} />
          </span>
          <span className="expert-join-label">专家加入</span>
          <span className="expert-join-name">{expertName}</span>
          <span className="expert-join-state">已加入当前任务</span>
        </div>
      </div>
    );
  }
  if (
    ((String(event.agent_name || event.agent || "system").toLowerCase() ===
      "system") &&
      !kind.includes("tool_call")) ||
    [
      "approval_required",
      "approval_resolved",
      "phase_change",
      "mission_start",
      "mission_end",
      "mission_cancelled",
      "error",
      "flag_found",
    ].includes(kind)
  )
    return (
      <div className={kind === "phase_change" ? "phase-divider" : "system-notice"}>
        <span>{systemNoticeText(event) || "任务状态已更新"}</span>
      </div>
    );
  if (kind.includes("thinking"))
    return (
      <details className={`agent-card thinking ${info.tone}`}>
        <summary>
          <span className="agent-avatar">
            <Icon size={15} />
          </span>
          <b>{displayName}</b>
          <i>{info.agentKey} · 推理过程</i>
          <ChevronDown size={15} />
        </summary>
        <div className="thinking-body">
          <MarkdownContent>{text || "正在推理…"}</MarkdownContent>
        </div>
      </details>
    );
  if (kind.includes("tool_call")) {
    const toolName = String(data.tool_name || "执行工具");
    return (
      <div className="system-notice tool-notice">
        <span>
          🔧 [{displayName}] 调用工具：{TOOL_LABELS[toolName] || toolName}
        </span>
      </div>
    );
  }
  return (
    <article
      className={`agent-card ${info.tone} ${info.tone === "user" ? "operator" : ""}`}
    >
      <header>
        <span className="agent-avatar">
          <Icon size={15} />
        </span>
        <div>
          <b>{displayName}</b>
          <small>
            {info.agentKey} · {info.role}
          </small>
        </div>
        <i>{kind.replaceAll("_", " ")}</i>
      </header>
      <div className="agent-body">
        <MarkdownContent>
          {text || (kind === "text_start" ? "正在输出…" : "任务状态已更新")}
        </MarkdownContent>
      </div>
    </article>
  );
}

function PlanPanel({ mission, phase }: { mission: Mission; phase?: string }) {
  const items = mission.plan_items || [];
  return (
    <section className="side-section">
      <div className="side-title">
        <ClipboardList size={15} />
        作战计划 <span>{items.length}</span>
      </div>
      {items.length ? (
        items.map((item) => (
          <article
            className={`plan-line ${item.status} ${item.phase === phase ? "active" : ""}`}
            key={item.id}
          >
            <span>
              {item.status === "completed" ? (
                <CheckCircle2 size={14} />
              ) : (
                <CircleDot size={14} />
              )}
            </span>
            <div>
              <b>{item.content}</b>
              <small>
                {phaseLabel(item.phase)} ·{" "}
                {item.expert || item.origin || "待分配"}
              </small>
              {item.evidence && <em>{item.evidence}</em>}
            </div>
          </article>
        ))
      ) : (
        <p className="empty-note">Brain 制定计划后将在此处显示。</p>
      )}
    </section>
  );
}

function Knowledge({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [status, setStatus] = useState<Record<string, unknown>>({}),
    [query, setQuery] = useState(""),
    [results, setResults] = useState<
      { score: number; source: string; snippet: string }[]
    >([]);
  const load = () =>
    api
      .knowledgeStatus()
      .then(setStatus)
      .catch((err) => setStatus({ error: String(err) }));
  useEffect(() => {
    if (open) void load();
  }, [open]);
  return (
    <Dialog.Root open={open} onOpenChange={(v) => !v && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="knowledge-drawer">
          <header>
            <div>
              <Database size={18} />
              <b>本地知识库</b>
            </div>
            <button onClick={onClose}>
              <X size={18} />
            </button>
          </header>
          <div className="rag-health">
            <span className={status.available === true ? "ok" : "off"} />
            <div>
              <b>{status.available === true ? "索引在线" : "索引不可用"}</b>
              <small>.RAG · {String(status.documents ?? 0)} 个文档</small>
            </div>
          </div>
          {Boolean(status.error) && (
            <p className="error-note">{String(status.error)}</p>
          )}
          <div className="knowledge-search">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="检索 Writeup 或技术线索"
            />
            <button
              onClick={async () => {
                try {
                  setResults((await api.knowledgeSearch(query)).results);
                } catch (err) {
                  toast.error(String(err));
                }
              }}
            >
              <Search size={17} />
            </button>
          </div>
          <button
            className="quiet-button full"
            onClick={async () => {
              try {
                setStatus(await api.reindex());
                toast.success("知识库索引已同步");
              } catch (err) {
                toast.error(String(err));
              }
            }}
          >
            同步 .RAG 文档
          </button>
          <div className="hits">
            {results.map((r, i) => (
              <article key={i}>
                <header>
                  <b>{r.source}</b>
                  <span>{r.score.toFixed(3)}</span>
                </header>
                <p>{r.snippet}</p>
              </article>
            ))}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export default function App() {
  const [ready, setReady] = useState(!!auth.get()),
    [dark, setDark] = useState(
      localStorage.getItem("lingshu_theme") !== "light",
    ),
    [sessions, setSessions] = useState<Session[]>([]),
    [active, setActive] = useState(""),
    [events, setEvents] = useState<Event[]>([]),
    [detail, setDetail] = useState<Mission>({}),
    [text, setText] = useState(""),
    [search, setSearch] = useState(""),
    [knowledge, setKnowledge] = useState(false);
  const feedRef = useRef<HTMLElement>(null);
  const autoScroll = useRef(true);
  const current = useMemo(
    () => sessions.find((s) => s.id === active),
    [sessions, active],
  );
  const phase = String(detail.phase || current?.phase || "");
  const isLive = current?.is_live === true;
  const load = async () => {
    try {
      const list = (await api.sessions()).sessions;
      setSessions(list);
      if (!active && list[0]) setActive(list[0].id);
    } catch {
      auth.clear();
      setReady(false);
    }
  };
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("lingshu_theme", dark ? "dark" : "light");
  }, [dark]);
  useEffect(() => {
    if (ready) void load();
  }, [ready]);
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    autoScroll.current = true;
    setEvents([]);
    setDetail({});
    api
      .session(active)
      .then((r) =>
        setDetail({ ...r, ...((r.mission_state as Mission) || {}) }),
      )
      .catch(() => {});
    (async () => {
      let afterSeq = 0;
      try {
        const history = await api.messages(active);
        if (controller.signal.aborted) return;
        const historyEvents = history.messages || [];
        afterSeq = historyEvents.reduce(
          (maximum, event) => Math.max(maximum, Number(event.seq || 0)),
          0,
        );
        setEvents(
          normalizeEvents([...historyEvents, ...(history.snapshots || [])]),
        );
      } catch (err) {
        if (!controller.signal.aborted) toast.error(String(err));
      }
      try {
        for await (const event of stream(
          active,
          controller.signal,
          afterSeq,
        )) {
          setEvents((currentEvents) => mergeEvent(currentEvents, event));
          const payload = dataOf(event);
          const eventKind = kindOf(event);
          if (
            ["mission_end", "mission_cancelled", "session_deleted"].includes(
              eventKind,
            )
          )
            setSessions((currentSessions) =>
              currentSessions.map((session) =>
                session.id === active
                  ? {
                      ...session,
                      is_live: false,
                      success:
                        eventKind === "mission_end"
                          ? payload.status === "completed" ||
                            payload.success === true
                          : session.success,
                    }
                  : session,
              ),
            );
          if (
            event.type === "plan_updated" ||
            event.event_type === "plan_updated"
          )
            setDetail((v) => ({
              ...v,
              plan_items: (payload.items as PlanItem[]) || v.plan_items,
              phase: String(payload.phase || v.phase || ""),
            }));
          if (
            event.type === "target_info" ||
            event.event_type === "target_info"
          )
            setDetail((v) => ({ ...v, ...payload }));
        }
      } catch (err) {
        if (
          !controller.signal.aborted &&
          !String(err).includes("会话不存在或已结束")
        )
          console.warn("实时连接已结束", err);
      }
    })();
    return () => controller.abort();
  }, [active]);
  useEffect(() => {
    const feed = feedRef.current;
    if (!feed || !autoScroll.current) return;
    feed.scrollTop = feed.scrollHeight;
  }, [events]);
  if (!ready) return <Login onReady={() => setReady(true)} />;
  const filtered = sessions.filter((s) =>
    `${s.title || ""} ${s.target || ""}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const send = async () => {
    if (!active || !text.trim()) return;
    try {
      await api.send(active, text);
      setEvents((currentEvents) =>
        mergeEvent(currentEvents, {
          event_type: "user_message",
          agent_name: "user",
          content: text,
        }),
      );
      setText("");
    } catch (err) {
      toast.error(String(err));
    }
  };
  const rerun = async () => {
    if (!active) return;
    try {
      const source = await api.session(active);
      const result = await api.create({
        target: String(source.target || detail.target || ""),
        goal: String(source.goal || detail.goal || "获取 Flag"),
        provider: String(source.provider || detail.provider || "deepseek"),
        model: String(source.model || detail.model || "Min"),
        source_session_id: active,
      });
      setActive(result.session_id);
      await load();
      toast.success("已基于当前会话启动再次攻击");
    } catch (err) {
      toast.error(`再次攻击失败：${String(err)}`);
    }
  };
  return (
    <div className="console-shell">
      <div className="scanlines" />
      <div className="top-rail">
        <span>LINGSHU / AUTHORIZED SECURITY OPERATIONS</span>
        <span className="online">
          <i />
          SYSTEM ONLINE
        </span>
      </div>
      <div className="app-frame">
        <aside className="session-sidebar">
            <header>
              <div className="brand">
                <span className="brand-logo">
                  <img className="theme-logo-light" src={lightLogo} alt="灵枢" />
                  <img className="theme-logo-dark" src={darkLogo} alt="灵枢" />
                </span>
                <div>
                  <b>灵枢</b>
                  <small>Lingshu Console</small>
                </div>
                <button onClick={() => setDark(!dark)} title="切换主题">
                  {dark ? <Sun size={15} /> : <Moon size={15} />}
                </button>
              </div>
              <NewMission
                onCreated={(id) => {
                  setActive(id);
                  void load();
                }}
              />
            </header>
            <div className="session-search">
              <Search size={14} />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="搜索目标或会话"
              />
            </div>
            <div className="session-list">
              <p className="session-count">
                <span>任务会话</span>
                <i aria-hidden="true" />
                <b>{filtered.length}</b>
              </p>
              {filtered.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setActive(s.id)}
                  className={`session-row ${active === s.id ? "selected" : ""}`}
                >
                  <i
                    className={
                      s.is_live
                        ? "live"
                        : s.success === true
                          ? "success"
                          : s.success === false
                            ? "fail"
                            : ""
                    }
                  />
                  <div>
                    <b>{s.title || s.target || s.id.slice(0, 8)}</b>
                    <small>
                      {phaseLabel(s.phase)} · {s.target || "等待任务信息"}
                    </small>
                  </div>
                </button>
              ))}
            </div>
            <footer>
              <button
                onClick={() => {
                  auth.clear();
                  setReady(false);
                }}
              >
                <LogOut size={15} />
                退出登录
              </button>
            </footer>
        </aside>
        <main className="mission-main">
          <header className="mission-header">
            <div className="mission-ident">
              <small>当前任务</small>
              <b>
                {current?.title ||
                  (detail.title as string) ||
                  current?.goal ||
                  (detail.goal as string) ||
                  "未选择任务"}
              </b>
            </div>
            <span className={`phase-chip ${phase}`}>{phaseLabel(phase)}</span>
            <div className="header-actions">
              {active && isLive && (
                <button
                  className="stop"
                  onClick={() =>
                    api
                      .cancel(active)
                      .then(() => toast.success("已请求停止任务"))
                  }
                >
                  <Square size={14} />
                  停止
                </button>
              )}
              {active && !isLive && (
                <button
                  className="rerun"
                  onClick={() => void rerun()}
                  title="沿用当前任务配置和上下文再次执行"
                >
                  <RotateCcw size={14} />
                  再次攻击
                </button>
              )}
              <button
                className="icon-button"
                onClick={() => setKnowledge(true)}
              >
                <Database size={17} />
              </button>
              {active && (
                <button
                  className="icon-button danger"
                  onClick={() =>
                    api.remove(active).then(() => {
                      setActive("");
                      void load();
                    })
                  }
                >
                  <Trash2 size={16} />
                </button>
              )}
            </div>
          </header>
          <section className="mission-strip">
            <div>
              <span>目标</span>
              <b>{current?.target || (detail.target as string) || "--"}</b>
            </div>
            <div>
              <span>任务</span>
              <b>{String(detail.goal || current?.goal || "--")}</b>
            </div>
            <div>
              <span>审批</span>
              <b className={detail.exploitation_approved ? "good" : ""}>
                {detail.exploitation_approved ? "已批准" : "待审批"}
              </b>
            </div>
            <div>
              <span>发现</span>
              <b>
                {Array.isArray(detail.findings) ? detail.findings.length : 0} 条
              </b>
            </div>
          </section>
          <section
            className="agent-feed"
            ref={feedRef}
            onScroll={(event) => {
              const feed = event.currentTarget;
              autoScroll.current =
                feed.scrollHeight - feed.scrollTop - feed.clientHeight < 96;
            }}
          >
            {events.length ? (
              events.map((event, i) => (
                <AgentCard key={`${event.seq || "s"}-${i}`} event={event} />
              ))
            ) : (
              <div className="empty-feed">
                <div>
                  <Bot size={38} />
                  <b>等待任务指令</b>
                  <p>选择会话，或从左侧启动一项授权安全测试。</p>
                </div>
              </div>
            )}
          </section>
          <footer className="command-bar">
            <span className="prompt">OPERATOR@LINGSHU:~$</span>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void send();
                }
              }}
              placeholder="输入任务指令或审批答复…"
              rows={1}
            />
            <button onClick={() => void send()}>
              <Send size={17} />
            </button>
          </footer>
        </main>
        <aside className="intel-panel">
          <section className="side-section status-card">
            <div className="side-title">
              <ShieldAlert size={15} />
              任务态势 <span className="live-dot" />
            </div>
            <div className="radar">
              <i />
              <i />
              <i />
              <b>{phaseLabel(phase)}</b>
            </div>
            {detail.flag && (
              <div className="flag-box">
                FLAG<code>{detail.flag}</code>
              </div>
            )}
          </section>
          <PlanPanel mission={detail} phase={phase} />
          <section className="side-section">
            <div className="side-title">
              <Terminal size={15} />
              智能体活动
            </div>
            <div className="agent-roster">
              {Object.entries(AGENTS)
                .filter(([n]) => !["system", "user"].includes(n))
                .slice(0, 6)
                .map(([name, a]) => {
                  const Icon = a.icon;
                  const activeAgent = events
                    .slice(-8)
                    .some((e) => agentOf(e).agentKey === name);
                  return (
                    <div key={name} className={activeAgent ? "working" : ""}>
                      <span className={a.tone}>
                        <Icon size={13} />
                      </span>
                      <b>
                        {name}
                        <em>{a.expert}</em>
                      </b>
                      <small>{activeAgent ? "工作中" : "待命"}</small>
                    </div>
                  );
                })}
            </div>
          </section>
        </aside>
      </div>
      <Knowledge open={knowledge} onClose={() => setKnowledge(false)} />
    </div>
  );
}
