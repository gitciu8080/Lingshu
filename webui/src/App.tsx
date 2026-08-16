import { FormEvent, memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Bot,
  ArrowDown,
  ArrowUp,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  ClipboardList,
  Crosshair,
  Database,
  FlaskConical,
  FileDown,
  LogOut,
  LoaderCircle,
  Moon,
  Network,
  Plus,
  Upload,
  Search,
  Send,
  ShieldAlert,
  RotateCcw,
  Sparkles,
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
import { api, auth, Event, ModelApiConfig, ModelApiConfigInput, ModelProviderOption, Session, stream, SystemUser } from "./api";
import lightLogo from "./logo2.png";
import darkLogo from "./logored.png";

type ThemeMode = "light" | "dark" | "liquid";

const liquidDisplacementMap = `data:image/svg+xml,${encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 200">
  <defs>
    <radialGradient id="lens" cx="50%" cy="45%" r="72%">
      <stop offset="0" stop-color="#8a8a8a"/>
      <stop offset=".5" stop-color="#808080"/>
      <stop offset=".72" stop-color="#4d8dff"/>
      <stop offset=".88" stop-color="#57c7ff"/>
      <stop offset="1" stop-color="#eaf6ff"/>
    </radialGradient>
    <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#5ab0ff"/>
      <stop offset=".4" stop-color="#808080"/>
      <stop offset=".7" stop-color="#4d8dff"/>
      <stop offset="1" stop-color="#ffffff"/>
    </linearGradient>
  </defs>
  <rect width="320" height="200" fill="#808080"/>
  <rect width="320" height="200" fill="url(#lens)" opacity=".78"/>
  <rect width="320" height="200" fill="url(#sweep)" opacity=".30"/>
</svg>
`)}`;

function LiquidGlassLayer() {
  const sceneRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;
    // 射灯追踪指针：rAF 节流写入 CSS 变量，位移平滑交给 CSS transition
    let raf = 0;
    let tx = window.innerWidth / 2;
    let ty = window.innerHeight * 0.4;
    const apply = () => {
      raf = 0;
      scene.style.setProperty("--px", `${tx}px`);
      scene.style.setProperty("--py", `${ty}px`);
    };
    const onPointerMove = (e: PointerEvent) => {
      tx = e.clientX;
      ty = e.clientY;
      if (!raf) raf = requestAnimationFrame(apply);
    };
    window.addEventListener("pointermove", onPointerMove);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);
  return (
    <div className="liquid-scene" aria-hidden="true" ref={sceneRef}>
      <div className="pointer-glow" />
      <svg className="liquid-filter" width="0" height="0">
        <defs>
          <filter id="liquid-refraction" colorInterpolationFilters="sRGB">
            <feImage
              href={liquidDisplacementMap}
              width="100%"
              height="100%"
              preserveAspectRatio="none"
              result="liquid-map"
            />
            <feDisplacementMap
              in="SourceGraphic"
              in2="liquid-map"
              scale="42"
              xChannelSelector="R"
              yChannelSelector="G"
            />
          </filter>
          <filter id="liquid-refraction-soft" colorInterpolationFilters="sRGB">
            <feImage
              href={liquidDisplacementMap}
              width="100%"
              height="100%"
              preserveAspectRatio="none"
              result="liquid-map-soft"
            />
            <feDisplacementMap
              in="SourceGraphic"
              in2="liquid-map-soft"
              scale="18"
              xChannelSelector="R"
              yChannelSelector="G"
            />
          </filter>
          <filter id="liquid-chromatic" x="-6%" y="-6%" width="112%" height="112%" colorInterpolationFilters="sRGB">
            <feColorMatrix
              in="SourceGraphic"
              type="matrix"
              values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0"
              result="chroma-r"
            />
            <feColorMatrix
              in="SourceGraphic"
              type="matrix"
              values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0"
              result="chroma-g"
            />
            <feColorMatrix
              in="SourceGraphic"
              type="matrix"
              values="0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0"
              result="chroma-b"
            />
            <feOffset in="chroma-r" dx="-1.6" dy="0" result="chroma-r2" />
            <feOffset in="chroma-b" dx="1.6" dy="0" result="chroma-b2" />
            <feBlend in="chroma-g" in2="chroma-r2" mode="screen" result="chroma-gr" />
            <feBlend in="chroma-gr" in2="chroma-b2" mode="screen" />
          </filter>
        </defs>
      </svg>
    </div>
  );
}

type Mission = Record<string, unknown> & {
  plan_items?: PlanItem[];
  findings?: unknown[];
  flag?: string;
  goal?: string;
  phase?: string;
  exploitation_approved?: boolean;
  report_available?: boolean;
  report_url?: string;
  provider?: string;
  model?: string;
  model_level?: string;
  model_name?: string;
};
type AttackOption = {
  id: string;
  title: string;
  risk: string;
  summary: string;
  steps: string[];
};
type OutgoingMessage = {
  sessionId: string;
  content: string;
  clientId: string;
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
  Summary: {
    label: "报告总结",
    expert: "Mia - 对话总结与报告专家",
    icon: ClipboardList,
    tone: "analysis",
    role: "总结归档",
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
  [/Mia|对话总结|报告专家/, "Summary"],
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
      (kindOf(event) === "user_message" ? "user" : "system"),
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

function eventRenderKey(event: Event, fallbackIndex: number) {
  const data = dataOf(event);
  return String(
    event.client_id ||
      event._streamKey ||
      data.block_id ||
      data.tool_call_id ||
      data.source_id ||
      event.seq ||
      `${kindOf(event)}:${String(event.agent_name || event.agent || "system")}:${fallbackIndex}`,
  );
}

const TOOL_LABELS: Record<string, string> = {
  scoped_shell: "安全执行命令",
  dispatch_recon: "调度侦察智能体",
  dispatch_attack: "调度验证智能体",
  analysis: "漏洞研判",
  cve_search: "检索 CVE 情报",
  request_exploitation_approval: "请求人工审批",
  ocr_image: "Tesseract OCR 文字识别",
  view_mission_state: "查看任务状态",
  complete_mission: "结束任务",
  AddPlan: "添加计划",
  UpdatePlan: "更新计划",
  DeletePlan: "删除计划",
  ListPlan: "查看计划",
};

export type EventStore = {
  sessionId: string;
  items: Event[];
  toolItems: Event[];
  streamIndex: Map<string, number>;
  familyIndex: Map<string, number>;
  toolIndex: Map<string, number>;
  toolListIndex: Map<string, number>;
};

export function emptyEventStore(sessionId = ""): EventStore {
  return {
    sessionId,
    items: [],
    toolItems: [],
    streamIndex: new Map(),
    familyIndex: new Map(),
    toolIndex: new Map(),
    toolListIndex: new Map(),
  };
}

function cloneEventStore(store: EventStore): EventStore {
  return {
    sessionId: store.sessionId,
    items: [...store.items],
    toolItems: [...store.toolItems],
    streamIndex: new Map(store.streamIndex),
    familyIndex: new Map(store.familyIndex),
    toolIndex: new Map(store.toolIndex),
    toolListIndex: new Map(store.toolListIndex),
  };
}

export function mergeEventInto(store: EventStore, value: Event): void {
  const event = safeEvent(value);
  const kind = kindOf(event);
  const data = dataOf(event);
  const agent = agentOf(event).name;
  const family =
    kind === "stream_snapshot"
      ? String(data.stream_type || "text")
      : kind.startsWith("thinking_")
        ? "thinking"
        : "text";
  const explicitStreamKey =
    data.block_id || data.reply_id || data._streamKey || event._streamKey;
  const streamKey = String(explicitStreamKey || `${agent}:${family}`);
  const familyKey = `${agent}:${family}`;

  if (["plan_updated", "target_info"].includes(kind)) return;

  // 已归并的 EventStore 在操作员发送状态更新等低频场景会重建索引；
  // 重建时必须重新登记仍在流式输出的块，后续 delta 才能 O(1) 命中。
  if (["text_stream", "thinking_stream"].includes(kind)) {
    const index = store.items.length;
    store.items.push({ ...event, _streamKey: streamKey, _family: family });
    store.streamIndex.set(streamKey, index);
    store.familyIndex.set(familyKey, index);
    return;
  }

  if (kind === "stream_snapshot") {
    const index =
      store.streamIndex.get(streamKey) ??
      (!explicitStreamKey ? store.familyIndex.get(familyKey) : undefined) ??
      -1;
    const snapshot: Event = {
      ...event,
      event_type: `${family}_stream`,
      content: String(data.full_text || data.content || ""),
      _streamKey: streamKey,
      _family: family,
    };
    if (index < 0) {
      if (!snapshot.content) return;
      const nextIndex = store.items.length;
      store.items.push(snapshot);
      store.streamIndex.set(streamKey, nextIndex);
      store.familyIndex.set(familyKey, nextIndex);
      return;
    }
    store.items[index] = { ...store.items[index], ...snapshot };
    store.streamIndex.set(streamKey, index);
    store.familyIndex.set(familyKey, index);
    return;
  }

  if (["text_start", "thinking_start"].includes(kind)) {
    // 同一 Agent 的上一块可能因 task.cancel() 没有及时收到 end。新块必须
    // 使用自己的 block_id，不能复用 family 索引覆盖上一条已有内容。
    const previousFamilyIndex = store.familyIndex.get(familyKey);
    if (previousFamilyIndex !== undefined) {
      const previous = store.items[previousFamilyIndex];
      if (previous && kindOf(previous).endsWith("_stream")) {
        store.items[previousFamilyIndex] = {
          ...previous,
          event_type: `${family}_end`,
          interrupted: true,
        };
        const previousKey = String(previous._streamKey || "");
        if (previousKey) store.streamIndex.delete(previousKey);
      }
      store.familyIndex.delete(familyKey);
    }
    const index = store.items.length;
    store.items.push({ ...event, content: "", _streamKey: streamKey, _family: family });
    store.streamIndex.set(streamKey, index);
    store.familyIndex.set(familyKey, index);
    return;
  }

  if (["text_delta", "thinking_delta", "text_end", "thinking_end"].includes(kind)) {
    // 事件携带 block/reply id 时只能命中同一块；family 回退仅用于旧版无 id
    // 事件。否则恢复快照会覆盖同 Agent 已完成的上一条消息。
    const index =
      store.streamIndex.get(streamKey) ??
      (!explicitStreamKey ? store.familyIndex.get(familyKey) : undefined) ??
      -1;
    const isEnd = kind.endsWith("_end");
    const full = String(data.full_text || "");
    const delta = String(data.delta || "");
    if (index >= 0) {
      const previous = store.items[index];
      const content = isEnd
        ? full || String(previous.content || "")
        : String(previous.content || "") + delta;
      store.items[index] = {
        ...previous,
        ...event,
        event_type: isEnd ? kind : `${family}_stream`,
        content,
        _streamKey: streamKey,
        _family: family,
      };
      if (isEnd) {
        store.streamIndex.delete(streamKey);
        if (store.familyIndex.get(familyKey) === index)
          store.familyIndex.delete(familyKey);
      } else {
        store.streamIndex.set(streamKey, index);
        store.familyIndex.set(familyKey, index);
      }
      return;
    }
    const content = full || delta || eventText(event);
    if (!content) return;
    const nextIndex = store.items.length;
    store.items.push({
      ...event,
      event_type: isEnd ? kind : `${family}_stream`,
      content,
      _streamKey: streamKey,
      _family: family,
    });
    if (!isEnd) {
      store.streamIndex.set(streamKey, nextIndex);
      store.familyIndex.set(familyKey, nextIndex);
    }
    return;
  }

  if (kind.startsWith("tool_call")) {
    const id = String(data.tool_call_id || data.reply_id || "");
    const index = id ? store.toolIndex.get(id) ?? -1 : -1;
    if (kind === "tool_call_delta" && index < 0) return;
    const previous = index >= 0 ? store.items[index] : undefined;
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
      store.items[index] = merged;
      const toolListIndex = store.toolListIndex.get(id);
      if (toolListIndex !== undefined) store.toolItems[toolListIndex] = merged;
      return;
    }
    const nextIndex = store.items.length;
    store.items.push(merged);
    store.toolItems.push(merged);
    if (id) {
      store.toolIndex.set(id, nextIndex);
      store.toolListIndex.set(id, store.toolItems.length - 1);
    }
    return;
  }

  const text = eventText(event);
  const previous = store.items.at(-1);
  if (
    text &&
    previous &&
    eventText(previous) === text &&
    agentOf(previous).name === agent
  )
    return;
  store.items.push(event);
}

function normalizeEvents(values: Event[], sessionId = ""): EventStore {
  const store = emptyEventStore(sessionId);
  values.forEach((event) => mergeEventInto(store, event));
  return store;
}

function mergeEventBatch(store: EventStore, values: Event[]): EventStore {
  if (!values.length) return store;
  // Responses API 经常按单个汉字产生 delta。先把同一内容块的相邻
  // 增量压成一段，再进入 mergeEvent，避免一帧内反复复制整个事件数组。
  const compacted: Event[] = [];
  for (const value of values) {
    const event = safeEvent(value);
    const kind = kindOf(event);
    const previous = compacted.at(-1);
    const previousKind = previous ? kindOf(previous) : "";
    if (
      previous &&
      (kind === "text_delta" || kind === "thinking_delta") &&
      previousKind === kind &&
      String(dataOf(previous).block_id || dataOf(previous).reply_id || "") ===
        String(dataOf(event).block_id || dataOf(event).reply_id || "") &&
      String(previous.agent_name || previous.agent || "system") ===
        String(event.agent_name || event.agent || "system")
    ) {
      compacted[compacted.length - 1] = {
        ...previous,
        ...event,
        delta: String(dataOf(previous).delta || "") + String(dataOf(event).delta || ""),
      };
    } else {
      compacted.push(event);
    }
  }
  const next = cloneEventStore(store);
  compacted.forEach((event) => mergeEventInto(next, event));
  return next;
}

function mapEventStore(store: EventStore, mapper: (event: Event) => Event): EventStore {
  return normalizeEvents(store.items.map(mapper), store.sessionId);
}

export function eventsForSession(store: EventStore, sessionId: string): Event[] {
  return store.sessionId === sessionId ? store.items : [];
}

const MarkdownContent = memo(function MarkdownContent({ children }: { children: string }) {
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
});

const StreamingMarkdown = memo(function StreamingMarkdown({ children }: { children: string }) {
  const latestText = useRef(children);
  const timerRef = useRef(0);
  const [renderedText, setRenderedText] = useState(children);
  latestText.current = children;
  useEffect(() => {
    if (timerRef.current) return;
    // Markdown 解析比纯文本昂贵：以约 8 FPS 增量排版，流结束时由
    // MarkdownContent 立即接管最终全文，兼顾实时格式与输入响应性。
    timerRef.current = window.setTimeout(() => {
      timerRef.current = 0;
      setRenderedText(latestText.current);
    }, 120);
  }, [children]);
  useEffect(
    () => () => {
      if (timerRef.current) window.clearTimeout(timerRef.current);
    },
    [],
  );
  return <MarkdownContent>{renderedText}</MarkdownContent>;
});

function sameToolEvents(previous: { events: Event[] }, next: { events: Event[] }) {
  let previousIndex = previous.events.length - 1;
  let nextIndex = next.events.length - 1;
  while (true) {
    while (previousIndex >= 0 && !kindOf(previous.events[previousIndex]).startsWith("tool_call"))
      previousIndex -= 1;
    while (nextIndex >= 0 && !kindOf(next.events[nextIndex]).startsWith("tool_call"))
      nextIndex -= 1;
    if (previousIndex < 0 || nextIndex < 0)
      return previousIndex === nextIndex;
    if (previous.events[previousIndex] !== next.events[nextIndex]) return false;
    previousIndex -= 1;
    nextIndex -= 1;
  }
}

const TOOL_ARG_LABELS: Record<string, string> = {
  id: "计划编号",
  content: "计划内容",
  phase: "执行阶段",
  status: "执行状态",
  evidence: "完成证据",
  command: "执行命令",
  focus: "侦察重点",
  objective: "行动目标",
  reason: "执行理由",
  target: "目标地址",
  input_path: "输入文件",
  image_path: "图片路径",
  language: "语言",
  selected_plan_id: "选定方案",
  priority_order: "优先级顺序",
};

const TOOL_ARG_VALUE_LABELS: Record<string, string> = {
  planning: "规划阶段",
  recon: "侦察阶段",
  analysis: "分析阶段",
  exploitation: "攻击验证阶段",
  post_exploitation: "后渗透阶段",
  completed: "已完成",
  in_progress: "进行中",
  pending: "待执行",
  failed: "失败",
  skipped: "已跳过",
};

function parseToolArguments(raw: string): { parsed: boolean; value: unknown } {
  let value: unknown = raw.trim();
  if (!value) return { parsed: false, value: "" };
  for (let depth = 0; depth < 3 && typeof value === "string"; depth += 1) {
    const candidate = value.trim();
    if (!candidate.startsWith("{") && !candidate.startsWith("[") && !candidate.startsWith('"'))
      break;
    try {
      value = JSON.parse(candidate);
    } catch {
      break;
    }
  }
  return { parsed: typeof value !== "string", value };
}

function ToolArgumentValue({ value, field = "" }: { value: unknown; field?: string }) {
  if (Array.isArray(value)) {
    return (
      <div className="tool-arg-array">
        {value.map((item, index) => (
          <div className="tool-arg-array-item" key={index}>
            <span>{index + 1}</span>
            <ToolArgumentValue value={item} />
          </div>
        ))}
      </div>
    );
  }
  if (value && typeof value === "object")
    return <ToolArgumentsObject value={value as Record<string, unknown>} />;
  if (typeof value === "boolean")
    return <span className={`tool-arg-chip ${value ? "positive" : "negative"}`}>{value ? "是" : "否"}</span>;
  if (value === null || value === undefined)
    return <span className="tool-arg-empty">未设置</span>;
  const text = String(value);
  const translated = TOOL_ARG_VALUE_LABELS[text.toLowerCase()];
  if (translated || field === "phase" || field === "status")
    return <span className="tool-arg-chip">{translated || text}</span>;
  return <span className="tool-arg-text">{text}</span>;
}

function ToolArgumentsObject({ value }: { value: Record<string, unknown> }) {
  return (
    <div className="tool-args-structured">
      {Object.entries(value).map(([key, item]) => (
        <div className="tool-arg-row" key={key}>
          <div className="tool-arg-name">
            <b>{TOOL_ARG_LABELS[key] || key.replaceAll("_", " ")}</b>
            {TOOL_ARG_LABELS[key] && <code>{key}</code>}
          </div>
          <div className="tool-arg-value">
            <ToolArgumentValue value={item} field={key} />
          </div>
        </div>
      ))}
    </div>
  );
}

const ToolHistoryEntry = memo(function ToolHistoryEntry({
  event,
  isLatest,
}: {
  event: Event;
  isLatest: boolean;
}) {
  const [expanded, setExpanded] = useState(isLatest);
  const data = dataOf(event);
  const info = agentOf(event);
  const toolName = String(data.tool_name || "执行工具");
  const args = String(data.full_args || "");
  const output = String(data.output || "");
  const formatArgs = (raw: unknown) => {
    const text = String(raw || "").trim();
    if (!text) return null;
    const result = parseToolArguments(text);
    if (result.parsed && result.value && typeof result.value === "object")
      return <ToolArgumentValue value={result.value} />;
    return <pre className="tool-command">{String(result.value || text)}</pre>;
  };
  return (
    <details
      className={`tool-history-entry ${info.tone}`}
      open={expanded}
      onToggle={(toggleEvent) => setExpanded(toggleEvent.currentTarget.open)}
    >
      <summary>
        <span className={`tool-history-agent ${info.tone}`}>{info.agentKey}</span>
        <b>{TOOL_LABELS[toolName] || toolName}</b>
        <small>{toolName}</small>
      </summary>
      {expanded && (
        <div className="tool-history-detail">
          <label>调用参数</label>
          {formatArgs(args) || <em>未提供参数</em>}
          {output && (
            <>
              <label>工具结果</label>
              <div className="tool-history-output">
                <MarkdownContent>{output}</MarkdownContent>
              </div>
            </>
          )}
        </div>
      )}
    </details>
  );
});

const ToolHistoryPanel = memo(function ToolHistoryPanel({ events }: { events: Event[] }) {
  const calls = events;
  const [visibleTools, setVisibleTools] = useState(60);
  const listRef = useRef<HTMLDivElement>(null);
  const followLatestRef = useRef(true);
  const scrollFrameRef = useRef(0);
  const hiddenTools = Math.max(0, calls.length - visibleTools);
  const visibleCalls = hiddenTools ? calls.slice(-visibleTools) : calls;
  const latestCall = visibleCalls.at(-1);
  const latestData = latestCall ? dataOf(latestCall) : {};
  const latestSignature = latestCall
    ? `${String(latestData.tool_call_id || latestCall.seq || visibleCalls.length)}:${String(latestData.full_args || "").length}:${String(latestData.output || "").length}`
    : "";

  useEffect(() => {
    if (!followLatestRef.current) return;
    cancelAnimationFrame(scrollFrameRef.current);
    scrollFrameRef.current = requestAnimationFrame(() => {
      const list = listRef.current;
      if (list) list.scrollTop = list.scrollHeight;
    });
    return () => cancelAnimationFrame(scrollFrameRef.current);
  }, [latestSignature]);

  return (
    <section className="side-section tool-history-section">
      <div className="side-title">
        <Terminal size={15} />
        工具调用历史 <span>{calls.length}</span>
      </div>
      <div
        className="tool-history-list"
        ref={listRef}
        onScroll={(scrollEvent) => {
          const list = scrollEvent.currentTarget;
          followLatestRef.current =
            list.scrollHeight - list.scrollTop - list.clientHeight < 72;
        }}
      >
        {hiddenTools > 0 && (
          <button
            type="button"
            className="quiet-button full"
            onClick={() => setVisibleTools((count) => Math.min(count + 60, calls.length))}
          >
            加载更早的 {hiddenTools} 条工具记录
          </button>
        )}
        {calls.length ? (
          visibleCalls.map((event, index) => (
            <ToolHistoryEntry
              event={event}
              isLatest={index === visibleCalls.length - 1}
              key={String(dataOf(event).tool_call_id || event.seq || index)}
            />
          ))
        ) : (
          <p className="empty-note">暂无工具调用记录</p>
        )}
      </div>
    </section>
  );
}, sameToolEvents);

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
  if (kind === "steering_received") return "📥 已接收新情报，行动指挥正在调整任务";
  if (kind === "report_ready") return "📄 对话总结与 PDF 报告已生成";
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
        cancelled: "已停止",
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
        <footer>广交院·信智学院 | Lingshu Agent 项目 | c62d95e <br/>
          <a href="https://beian.miit.gov.cn/">粤ICP备2024275751号</a>
          <br/>
          <a href="https://beian.miit.gov.cn/">粤ICP备2025430595号</a>
          </footer>
      </form>
    </main>
  );
}

function useModelProviders() {
  const [providers, setProviders] = useState<ModelProviderOption[]>([]);
  useEffect(() => { void api.modelProviders().then((data) => setProviders(data.providers || [])).catch(() => setProviders([])); }, []);
  return providers;
}

function NewMission({ onCreated }: { onCreated: (id: string) => void }) {
  const providers = useModelProviders();
  const [open, setOpen] = useState(false),
    [target, setTarget] = useState(""),
    [files, setFiles] = useState<File[]>([]),
    [submitting, setSubmitting] = useState(false),
    [goal, setGoal] = useState("获取 Flag"),
    [provider, setProvider] = useState(""),
    [model, setModel] = useState("Min"),
    [qwenToolMode, setQwenToolMode] = useState("simple");
  const submitLock = useRef(false);
  useEffect(() => {
    if (providers.length && !providers.some((item) => item.id === provider)) {
      setProvider(providers[0].id);
    }
  }, [providers, provider]);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (submitLock.current) return;
    if (!target.trim() && files.length === 0) {
      toast.error("请输入授权目标或上传目标文件");
      return;
    }
    if (!provider) {
      toast.error("尚未启用任何模型，请先由超级管理员配置模型 API");
      return;
    }
    submitLock.current = true;
    setSubmitting(true);
    try {
      const resolvedTarget = files.length ? (await api.upload(files)).target : target.trim();
      const r = await api.create({
        target: resolvedTarget,
        goal,
        provider,
        model,
        ...(provider === "qwen" ? { qwen_tool_call_mode: qwenToolMode } : {}),
      });
      setOpen(false);
      setFiles([]);
      setTarget("");
      onCreated(r.session_id);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setSubmitting(false);
      submitLock.current = false;
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
        <Dialog.Content className="modal submission-modal">
          <Dialog.Title>创建授权测试任务</Dialog.Title>
          <p>所有攻击类操作都将在利用前要求人工批准。</p>
          <form onSubmit={submit}>
            <fieldset disabled={submitting} className="submission-fields">
            <label>
              授权目标
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="IP / 主机名 / 文件路径"
                disabled={files.length > 0}
              />
            </label>
            <div className="target-divider"><span>或</span></div>
            <label className={`upload-field ${files.length ? "selected" : ""}`}>
              <Upload size={18} />
              <span>
                <b>{files.length ? `已选择 ${files.length} 个文件` : "上传目标文件（可多选）"}</b>
                <small>
                  {files.length
                    ? `${(files.reduce((sum, file) => sum + file.size, 0) / 1024 / 1024).toFixed(2)} MB · ${files.map((file) => file.name).join("、")}`
                    : "支持压缩包、二进制、流量包和图片等；单文件 100MB，总计 300MB"}
                </small>
              </span>
              <input
                type="file"
                multiple
                onChange={(e) => {
                  const selected = Array.from(e.target.files || []);
                  setFiles(selected);
                  if (selected.length) setTarget("");
                }}
              />
            </label>
            <label>
              任务目标
              <textarea
                className="mission-goal"
                value={goal}
                onChange={(e) => setGoal(e.target.value)}
                rows={3}
                placeholder="描述授权测试目标；可拖动右下角调整文本框高度"
              />
            </label>
            <div className="select-row">
              <label>
                模型提供商
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  disabled={!providers.length}
                >
                  {!providers.length && <option value="">未配置可用模型</option>}
                  {providers.map((item) => <option key={item.id} value={item.id}>{item.label} · {item.id}</option>)}
                </select>
                {!providers.length && <small>请先前往 /superadmin 启用一个大模型 API</small>}
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
            {provider === "qwen" && <label>
              工具调用难度
              <select value={qwenToolMode} onChange={(e) => setQwenToolMode(e.target.value)}>
                <option value="simple">简单（兼容 AgentWorld）</option>
                <option value="standard">标准（批量嵌套参数）</option>
              </select>
            </label>}
            </fieldset>
            <div className="modal-actions">
              <Dialog.Close className="quiet-button" disabled={submitting}>取消</Dialog.Close>
              <button className="danger-button" disabled={submitting || !providers.length}>
                {submitting ? <><LoaderCircle className="button-spinner" size={15} /> 正在创建会话…</> : "启动任务"}
              </button>
            </div>
          </form>
          {submitting && <div className="submission-loading"><LoaderCircle className="loading-orbit" size={30} /><b>正在创建任务</b><small>请勿重复点击，正在分配独立会话与执行环境…</small></div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function RerunMission({
  open,
  source,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  source: (Session & Record<string, unknown>) | null;
  onOpenChange: (open: boolean) => void;
  onCreated: (id: string) => void;
}) {
  const providers = useModelProviders();
  const [target, setTarget] = useState(""),
    [goal, setGoal] = useState("获取 Flag"),
    [provider, setProvider] = useState("deepseek"),
    [model, setModel] = useState("Min"),
    [qwenToolMode, setQwenToolMode] = useState("simple"),
    [withContext, setWithContext] = useState(true),
    [submitting, setSubmitting] = useState(false);
  const submitLock = useRef(false);

  useEffect(() => {
    if (!open || !source) return;
    setTarget(String(source.target || ""));
    setGoal(String(source.goal || "获取 Flag"));
    setProvider(String(source.provider || "deepseek"));
    setModel(String(source.model || "Min"));
    setWithContext(true);
  }, [open, source]);

  useEffect(() => {
    if (open && providers.length && !providers.some((item) => item.id === provider)) {
      setProvider(providers[0].id);
    }
  }, [open, providers, provider]);

  if (!source) return null;
  const mission =
    source.mission_state && typeof source.mission_state === "object"
      ? (source.mission_state as Mission)
      : (source as Mission);
  const priorPhase = String(mission.phase || source.phase || "未知");
  const priorSuccess =
    mission.success === true || source.success === true
      ? "成功"
      : mission.success === false || source.success === false
        ? "失败"
        : "未完成或已中断";
  const findingsCount = Array.isArray(mission.findings)
    ? mission.findings.length
    : 0;
  const attackCount = Array.isArray(mission.attack_chain)
    ? mission.attack_chain.length
    : 0;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitLock.current) return;
    if (!target.trim()) return;
    if (!providers.some((item) => item.id === provider)) {
      toast.error("尚未启用任何模型，请先由超级管理员配置模型 API");
      return;
    }
    submitLock.current = true;
    setSubmitting(true);
    try {
      const result = await api.create({
        target: target.trim(),
        goal: goal.trim() || "获取 Flag",
        provider,
        model,
        ...(provider === "qwen" ? { qwen_tool_call_mode: qwenToolMode } : {}),
        ...(withContext ? { source_session_id: source.id } : {}),
      });
      onOpenChange(false);
      onCreated(result.session_id);
    } catch (err) {
      toast.error(`再次攻击失败：${String(err)}`);
    } finally {
      setSubmitting(false);
      submitLock.current = false;
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="modal rerun-modal submission-modal">
          <Dialog.Title>
            <RotateCcw size={18} /> 再次执行任务
          </Dialog.Title>
          <Dialog.Description>
            可修改靶机目标和模型配置，再基于当前会话创建一项新任务。
          </Dialog.Description>
          <div className="rerun-summary">
            <header>
              <b>前次任务结果</b>
              <span className={priorSuccess === "成功" ? "success" : ""}>
                {priorSuccess}
              </span>
            </header>
            <p>
              阶段：{phaseLabel(priorPhase)} · 侦察发现 {findingsCount} 条 · 攻击步骤 {attackCount} 条
            </p>
            {mission.flag && <code>{String(mission.flag)}</code>}
            {Boolean(mission.summary) && (
              <small>{String(mission.summary).slice(0, 300)}</small>
            )}
          </div>
          <form onSubmit={submit}>
            <fieldset disabled={submitting} className="submission-fields">
            <label>
              授权目标
              <input
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                required
                placeholder="IP / 主机名 / 文件路径"
              />
            </label>
            <label>
              任务目标
              <input
                value={goal}
                onChange={(event) => setGoal(event.target.value)}
              />
            </label>
            <div className="select-row">
              <label>
                模型提供商
                <select
                  value={provider}
                  onChange={(event) => setProvider(event.target.value)}
                  disabled={!providers.length}
                >
                  {!providers.length && <option value="">未配置可用模型</option>}
                  {providers.map((item) => <option key={item.id} value={item.id}>{item.label} · {item.id}</option>)}
                </select>
                {!providers.length && <small>请先前往 /superadmin 启用一个大模型 API</small>}
              </label>
              <label>
                思考级别
                <select
                  value={model}
                  onChange={(event) => setModel(event.target.value)}
                >
                  {["Low", "Min", "Max"].map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </label>
            </div>
            {provider === "qwen" && <label>
              工具调用难度
              <select value={qwenToolMode} onChange={(event) => setQwenToolMode(event.target.value)}>
                <option value="simple">简单（兼容 AgentWorld）</option>
                <option value="standard">标准（批量嵌套参数）</option>
              </select>
            </label>}
            <label className="rerun-context">
              <input
                type="checkbox"
                checked={withContext}
                onChange={(event) => setWithContext(event.target.checked)}
              />
              <span>
                <b>携带前次任务上下文</b>
                <small>复用已发现的服务、漏洞证据和攻击路径，避免重复侦察。</small>
              </span>
            </label>
            </fieldset>
            <div className="modal-actions">
              <Dialog.Close className="quiet-button" disabled={submitting}>
                取消
              </Dialog.Close>
              <button className="danger-button" disabled={submitting || !providers.length}>
                <RotateCcw size={14} />
                {submitting ? <><LoaderCircle className="button-spinner" size={15} /> 正在创建…</> : "开始再次攻击"}
              </button>
            </div>
          </form>
          {submitting && <div className="submission-loading"><LoaderCircle className="loading-orbit" size={30} /><b>正在创建新任务</b><small>正在复用配置并建立新会话，请稍候…</small></div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function ApprovalDialog({
  request,
  onDecision,
}: {
  request: Record<string, unknown> | null;
  onDecision: (
    decision: "批准" | "补充侦察" | "拒绝",
    selection: { selected_plan_id: string; priority_order: string[] },
  ) => Promise<void>;
}) {
  const [submitting, setSubmitting] = useState(false);
  const summary =
    request?.scan_summary && typeof request.scan_summary === "object"
      ? (request.scan_summary as Record<string, unknown>)
      : {};
  const options = (Array.isArray(summary.approval_options)
    ? summary.approval_options
    : [])
    .filter((value): value is Record<string, unknown> => Boolean(value) && typeof value === "object")
    .map((value): AttackOption => ({
      id: String(value.id || ""),
      title: String(value.title || "攻击验证方案"),
      risk: String(value.risk || "未知"),
      summary: String(value.summary || ""),
      steps: Array.isArray(value.steps) ? value.steps.map(String) : [],
    }))
    .filter((value) => value.id);
  const [selectedId, setSelectedId] = useState("");
  const [priority, setPriority] = useState<string[]>([]);
  useEffect(() => {
    const ids = options.map((option) => option.id);
    setSelectedId(ids[0] || "");
    setPriority(ids);
  }, [request]);
  if (!request) return null;
  const findings = Array.isArray(summary.findings) ? summary.findings : [];
  const plans = Array.isArray(summary.plan_items)
    ? summary.plan_items
      : Array.isArray(request?.plan_items)
      ? request.plan_items
      : [];
  const movePriority = (id: string, offset: -1 | 1) => {
    setPriority((current) => {
      const index = current.indexOf(id), nextIndex = index + offset;
      if (index < 0 || nextIndex < 0 || nextIndex >= current.length) return current;
      const next = [...current];
      [next[index], next[nextIndex]] = [next[nextIndex], next[index]];
      return next;
    });
  };
  const orderedOptions = priority
    .map((id) => options.find((option) => option.id === id))
    .filter((option): option is AttackOption => Boolean(option));
  const decide = async (decision: "批准" | "补充侦察" | "拒绝") => {
    if (submitting) return;
    setSubmitting(true);
    try {
      await onDecision(decision, {
        selected_plan_id: selectedId,
        priority_order: priority,
      });
    } finally {
      setSubmitting(false);
    }
  };
  return (
    <Dialog.Root open>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay approval-overlay" />
        <Dialog.Content
          className="approval-modal"
          onEscapeKeyDown={(event) => event.preventDefault()}
          onPointerDownOutside={(event) => event.preventDefault()}
        >
          <header>
            <span><ShieldAlert size={21} /></span>
            <div>
              <Dialog.Title>攻击阶段人工审批</Dialog.Title>
              <Dialog.Description>
                Orchestrator 请求进入 EXPLOITATION 阶段
              </Dialog.Description>
            </div>
          </header>
          <div className="approval-content">
            <section className="approval-meta">
              <span>授权目标</span>
              <b>{String(summary.target || request.target || "当前任务目标")}</b>
            </section>
            <section>
              <h3>申请理由</h3>
              <div className="approval-reason">
                <MarkdownContent>
                  {String(request.reason || "Orchestrator 请求执行验证或利用操作。")}
                </MarkdownContent>
              </div>
            </section>
            {findings.length > 0 && (
              <section>
                <h3>侦察依据</h3>
                <div className="approval-items">
                  {findings.slice(-5).map((finding, index) => {
                    const value =
                      finding && typeof finding === "object"
                        ? (finding as Record<string, unknown>)
                        : { report: String(finding) };
                    return (
                      <article key={index}>
                        <b>{String(value.source || `发现 ${index + 1}`)}</b>
                        <div className="approval-finding-markdown">
                          <MarkdownContent>
                            {String(value.report || value.content || "暂无可展示的侦察内容。")}
                          </MarkdownContent>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </section>
            )}
            {orderedOptions.length > 0 && (
              <section>
                <h3>选择攻击方案并调整优先级</h3>
                <p className="approval-help">单击方案完成选择；使用箭头调整候选方案执行优先级。</p>
                <div className="approval-options">
                  {orderedOptions.map((option, index) => (
                    <article
                      key={option.id}
                      className={selectedId === option.id ? "selected" : ""}
                      onClick={() => setSelectedId(option.id)}
                    >
                      <input
                        type="radio"
                        name="attack-option"
                        checked={selectedId === option.id}
                        onChange={() => setSelectedId(option.id)}
                      />
                      <div>
                        <header>
                          <b>{index + 1}. {option.title}</b>
                          <span className={`risk risk-${option.risk}`}>风险 {option.risk}</span>
                        </header>
                        <p>{option.summary}</p>
                        {option.steps.length > 0 && (
                          <ol>{option.steps.map((step, stepIndex) => <li key={stepIndex}>{step}</li>)}</ol>
                        )}
                      </div>
                      <aside>
                        <button
                          type="button"
                          title="提高优先级"
                          disabled={index === 0}
                          onClick={(event) => { event.stopPropagation(); movePriority(option.id, -1); }}
                        ><ArrowUp size={14} /></button>
                        <button
                          type="button"
                          title="降低优先级"
                          disabled={index === orderedOptions.length - 1}
                          onClick={(event) => { event.stopPropagation(); movePriority(option.id, 1); }}
                        ><ArrowDown size={14} /></button>
                      </aside>
                    </article>
                  ))}
                </div>
              </section>
            )}
            {plans.length > 0 && (
              <section>
                <h3>拟执行计划</h3>
                <div className="approval-plan">
                  {plans.map((plan, index) => {
                    const value =
                      plan && typeof plan === "object"
                        ? (plan as Record<string, unknown>)
                        : { content: String(plan) };
                    return (
                      <div key={String(value.id || index)}>
                        <CircleDot size={13} />
                        <span>{String(value.content || "待执行步骤")}</span>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}
          </div>
          <footer>
            <button
              className="approval-reject"
              disabled={submitting}
              onClick={() => void decide("拒绝")}
            >
              拒绝
            </button>
            <button
              className="approval-recon"
              disabled={submitting}
              onClick={() => void decide("补充侦察")}
            >
              补充侦察
            </button>
            <button
              className="approval-approve"
              disabled={submitting || (orderedOptions.length > 0 && !selectedId)}
              onClick={() => void decide("批准")}
            >
              <CheckCircle2 size={16} /> 批准攻击
            </button>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

const AgentCard = memo(function AgentCard({ event: value }: { event: Event }) {
  const event = safeEvent(value),
    info = agentOf(event),
    Icon = info.icon,
    text = eventText(event),
    kind = kindOf(event),
    data = dataOf(event),
    displayName = info.name.includes(" - ") ? info.name : info.expert;
  const isUserMessage = kind === "user_message" || info.agentKey === "user";
  const isStreaming = kind === "text_stream" || kind === "thinking_stream";
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
    (
      !isUserMessage &&
      String(event.agent_name || event.agent || "system").toLowerCase() === "system" &&
      !kind.includes("tool_call")
    ) ||
    [
      "approval_required",
      "approval_resolved",
      "phase_change",
      "mission_start",
      "mission_end",
      "mission_cancelled",
      "steering_received",
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
          {isStreaming ? (
            <StreamingMarkdown>{text || "正在推理…"}</StreamingMarkdown>
          ) : (
            <MarkdownContent>{text || "正在推理…"}</MarkdownContent>
          )}
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
            {isUserMessage && event.delivery_state === "queued" ? " · 排队发送" : ""}
            {isUserMessage && event.delivery_state === "sent" ? " · 已发送" : ""}
            {isUserMessage && event.delivery_state === "failed" ? " · 发送失败" : ""}
          </small>
        </div>
        <i>{kind.replaceAll("_", " ")}</i>
      </header>
      <div className="agent-body">
        {isStreaming ? (
          <StreamingMarkdown>{text || "正在输出…"}</StreamingMarkdown>
        ) : (
          <MarkdownContent>
            {text || (kind === "text_start" ? "正在输出…" : "任务状态已更新")}
          </MarkdownContent>
        )}
      </div>
    </article>
  );
});

function PlanPanel({ mission, phase }: { mission: Mission; phase?: string }) {
  const items = mission.plan_items || [];
  return (
    <section className="side-section plan-section">
      <div className="side-title">
        <ClipboardList size={15} />
        作战计划 <span>{items.length}</span>
      </div>
      <div className="plan-list">
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
      </div>
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
              disabled={!query.trim()}
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

function SuperAdminLogin({ onReady }: { onReady: () => void }) {
  const [username, setUsername] = useState(""), [password, setPassword] = useState(""), [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await api.login(username, password);
      auth.set(result.access_token);
      const user = await api.me();
      if (user.role !== "superadmin") throw new Error("该账户没有超级管理员权限");
      onReady();
    } catch (error) {
      auth.clear();
      toast.error(String(error));
    } finally { setBusy(false); }
  };
  return <main className="login-page superadmin-login"><form className="login-card" onSubmit={submit}>
    <div className="login-mark"><img className="theme-logo-light" src={lightLogo} alt="灵枢" /><img className="theme-logo-dark" src={darkLogo} alt="灵枢" /><i /></div>
    <h1>系统管理 <small>SUPERADMIN</small></h1><p className="kicker">RESTRICTED SYSTEM ADMINISTRATION</p>
    <label>超级管理员账号<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
    <label>专用密码<input value={password} type="password" onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
    <button className="danger-button" disabled={busy}>{busy ? "验证中…" : "进入管理中心"} <span>→</span></button>
    <footer>仅限已授权的系统超级管理员</footer>
  </form></main>;
}

type SuperAdminTab = "users" | "llm" | "embedding";
type ModelDraft = ModelApiConfigInput & { clear_api_key?: boolean };

function blankModelDraft(category: "llm" | "embedding"): ModelDraft {
  return category === "llm" ? {
    name: "", category, provider: "deepseek", api_style: "responses", base_url: "https://api.deepseek.com",
    api_key: "", model_low: "deepseek-v4-flash", model_min: "deepseek-v4-flash", model_max: "deepseek-v4-pro",
    model_name: "", dimensions: 0, pass_dimensions: true, enabled: true,
    settings: { temperature: 0.7, top_p: 0.95, max_tokens: 0, max_retries: 3, context_size: 200000, timeout_seconds: 600, thinking_enabled: true },
  } : {
    name: "", category, provider: "openai-compatible", api_style: "embeddings", base_url: "",
    api_key: "", model_low: "", model_min: "", model_max: "", model_name: "",
    dimensions: 1536, pass_dimensions: true, enabled: true,
    settings: { temperature: 0.7, top_p: 0.95, max_tokens: 0, max_retries: 3, context_size: 8191, timeout_seconds: 600, thinking_enabled: false },
  };
}

function modelDraftFromConfig(item: ModelApiConfig): ModelDraft {
  return {
    name: item.name, category: item.category, provider: item.provider,
    api_style: item.api_style, base_url: item.base_url, api_key: "",
    model_low: item.model_low, model_min: item.model_min, model_max: item.model_max,
    model_name: item.model_name, dimensions: item.dimensions,
    pass_dimensions: item.pass_dimensions, enabled: item.enabled,
    settings: { ...blankModelDraft(item.category).settings, ...(item.settings || {}) },
  };
}

function ModelConfigDialog({ editing, category, onClose, onSaved }: {
  editing: ModelApiConfig | null; category: "llm" | "embedding"; onClose: () => void; onSaved: () => void;
}) {
  const [draft, setDraft] = useState<ModelDraft>(() => editing ? modelDraftFromConfig(editing) : blankModelDraft(category));
  const [saving, setSaving] = useState(false);
  const change = (key: keyof ModelDraft, value: string | number | boolean) => setDraft((old) => ({ ...old, [key]: value }));
  const changeSetting = (key: keyof ModelDraft["settings"], value: number | boolean) => setDraft((old) => ({ ...old, settings: { ...old.settings, [key]: value } }));
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setSaving(true);
    try {
      if (editing) await api.updateModelConfig(editing.id, draft);
      else await api.createModelConfig(draft);
      toast.success(editing ? "模型 API 配置已更新" : "模型 API 配置已创建");
      onSaved(); onClose();
    } catch (error) { toast.error(String(error)); }
    finally { setSaving(false); }
  };
  const embedding = category === "embedding";
  const modelClass = embedding ? "OpenAIEmbeddingModel" : draft.provider === "qwen" ? "QwenChatModel · OpenAIChatModel" : draft.provider === "deepseek" ? (draft.api_style === "responses" ? "DeepSeekResponsesModel · OpenAIResponseModel" : "DeepSeekChatModel") : draft.api_style === "responses" ? "OpenAIResponseModel" : "OpenAIChatModel";
  const credentialClass = !embedding && draft.provider === "deepseek" && draft.api_style === "chat_completions" ? "DeepSeekCredential" : "OpenAICredential";
  return <Dialog.Root open onOpenChange={(open) => !open && onClose()}><Dialog.Portal><Dialog.Overlay className="overlay model-config-overlay" />
    <Dialog.Content className="modal model-config-modal"><Dialog.Title>{editing ? "修改" : "添加"}{embedding ? "嵌入模型" : "大模型"} API</Dialog.Title>
      <Dialog.Description>遵循 AgentScope Chat Model / Embedding Model 构造标准；密钥加密保存，编辑时留空不会替换。 <a href="https://docs.agentscope.io/versions/2.0.7dev/en/building-blocks/model/llm" target="_blank" rel="noreferrer">查看官方参数说明 ↗</a></Dialog.Description>
      <form onSubmit={submit} className="model-config-form">
        <section className="model-runtime-card"><span>AGENTSCOPE RUNTIME</span><b>{modelClass}</b><small>{credentialClass} · stream={embedding ? "N/A" : "True"}</small></section>
        <fieldset className="model-form-section"><legend><i>01</i> 基本信息与 Provider</legend><div className="model-form-grid"><label>配置名称<small>仅用于管理后台识别</small><input value={draft.name} onChange={(e) => change("name", e.target.value)} required /></label>
          <label>Provider 标识<small>可自行输入；小写字母开头，仅允许字母、数字、_、-</small><input list={`provider-presets-${category}`} pattern="[a-z][a-z0-9_-]{1,31}" value={draft.provider} onChange={(e) => { const provider = e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ""); setDraft((old) => ({ ...old, provider, api_style: !embedding && provider === "qwen" ? "chat_completions" : old.api_style, settings: { ...old.settings, temperature: provider === "qwen" ? 0.3 : 0.7, context_size: provider === "qwen" ? 128000 : old.api_style === "responses" ? 200000 : 65536 } })); }} required /><datalist id={`provider-presets-${category}`}>{embedding && <option value="openai-compatible" />}<option value="deepseek" /><option value="qwen" /><option value="openai" /><option value="ollama" /><option value="vllm" /><option value="moonshot" /></datalist></label></div>
          <label>API 协议<small>必须与服务端端点实际协议一致</small><select value={draft.api_style} onChange={(e) => { const api_style = e.target.value as ModelDraft["api_style"]; setDraft((old) => ({ ...old, api_style, settings: { ...old.settings, context_size: api_style === "responses" ? 200000 : 65536 } })); }} disabled={embedding || draft.provider === "qwen"}>{embedding ? <option value="embeddings">Embeddings API</option> : draft.provider === "qwen" ? <option value="chat_completions">Chat Completions</option> : <><option value="responses">Responses API</option><option value="chat_completions">Chat Completions</option></>}</select></label>
        </fieldset>
        <fieldset className="model-form-section"><legend><i>02</i> Credential</legend><label>Base URL<small>仅填写基础地址，不要包含凭据、查询参数或片段</small><input value={draft.base_url} onChange={(e) => change("base_url", e.target.value)} placeholder="https://example.com/v1" required /></label>
          <label>API Key<small>{editing?.has_api_key ? `当前 ${editing.api_key_masked}；留空则保持不变` : "将使用 Fernet 加密后保存"}</small><input type="password" value={draft.api_key || ""} onChange={(e) => change("api_key", e.target.value)} placeholder={editing?.has_api_key ? "留空保持现有密钥" : "sk-…"} autoComplete="new-password" disabled={!!draft.clear_api_key} /></label>
          {editing?.has_api_key && <label className="inline-danger"><input type="checkbox" checked={!!draft.clear_api_key} onChange={(e) => change("clear_api_key", e.target.checked)} /> 删除已保存 API Key</label>}
        </fieldset>
        <fieldset className="model-form-section"><legend><i>03</i> Model</legend>{!embedding ? <><p className="field-help">灵枢按任务强度映射模型；Qwen 单模型端点仍会以 Min 名称作为服务端模型标识。</p><div className="model-form-grid three"><label>Low / 快速<input value={draft.model_low} onChange={(e) => change("model_low", e.target.value)} required /></label><label>Min / 平衡<input value={draft.model_min} onChange={(e) => change("model_min", e.target.value)} required /></label><label>Max / 深度<input value={draft.model_max} onChange={(e) => change("model_max", e.target.value)} required /></label></div></>
          : <div className="model-form-grid"><label>Embedding 模型<input value={draft.model_name} onChange={(e) => change("model_name", e.target.value)} required /></label><label>输出向量维度<small>必须与模型真实输出一致</small><input type="number" min={1} max={65536} value={draft.dimensions} onChange={(e) => change("dimensions", Number(e.target.value))} required /></label></div>}</fieldset>
        <fieldset className="model-form-section"><legend><i>04</i> Parameters</legend>{!embedding && <><div className="model-form-grid three"><label>Temperature<small>0 稳定 · 2 发散</small><input type="number" min={0} max={2} step={0.05} value={draft.settings.temperature} onChange={(e) => changeSetting("temperature", Number(e.target.value))} /></label><label>Top P<small>核采样范围</small><input type="number" min={0.01} max={1} step={0.01} value={draft.settings.top_p} onChange={(e) => changeSetting("top_p", Number(e.target.value))} /></label><label>Max Tokens<small>0 使用服务端默认值</small><input type="number" min={0} max={1048576} value={draft.settings.max_tokens} onChange={(e) => changeSetting("max_tokens", Number(e.target.value))} /></label></div><label className="inline-toggle"><input type="checkbox" checked={draft.settings.thinking_enabled} onChange={(e) => changeSetting("thinking_enabled", e.target.checked)} /><span><b>启用推理能力</b><small>Low 始终关闭；Min/Max 纯文本开启；带 tools 的调用强制关闭</small></span></label></>}
          <details className="model-advanced"><summary>高级运行参数</summary><div className="model-form-grid three"><label>Max Retries<input type="number" min={0} max={10} value={draft.settings.max_retries} onChange={(e) => changeSetting("max_retries", Number(e.target.value))} /></label><label>Context Size<input type="number" min={1024} max={10485760} value={draft.settings.context_size} onChange={(e) => changeSetting("context_size", Number(e.target.value))} /></label><label>Timeout / 秒<input type="number" min={1} max={3600} value={draft.settings.timeout_seconds} onChange={(e) => changeSetting("timeout_seconds", Number(e.target.value))} disabled={embedding} /></label></div></details>
        </fieldset>
        <section className="model-policy"><b>灵枢运行策略</b><span>Streaming {embedding ? "—" : "ON"}</span><span>TOOLS STATE-GUARDED</span><span>Formatter PROVIDER DEFAULT</span><small>为保证实时消息、状态机顺序和 DeepSeek reasoning_item_id 一致性，这些参数由系统锁定。</small></section>
        <div className="model-switches"><label><input type="checkbox" checked={draft.enabled} onChange={(e) => change("enabled", e.target.checked)} /> 启用此配置</label>{embedding && <label><input type="checkbox" checked={draft.pass_dimensions} onChange={(e) => change("pass_dimensions", e.target.checked)} /> 向 API 传递 dimensions</label>}</div>
        <div className="modal-actions"><button type="button" className="quiet-button" onClick={onClose}>取消</button><button className="danger-button" disabled={saving}>{saving ? "保存中…" : "保存配置"}</button></div>
      </form>
    </Dialog.Content></Dialog.Portal></Dialog.Root>;
}

function SuperAdminPage() {
  const [ready, setReady] = useState(!!auth.get()), [tab, setTab] = useState<SuperAdminTab>("users"),
    [users, setUsers] = useState<SystemUser[]>([]), [configs, setConfigs] = useState<ModelApiConfig[]>([]),
    [loading, setLoading] = useState(false), [target, setTarget] = useState<SystemUser | null>(null),
    [editor, setEditor] = useState<{ category: "llm" | "embedding"; config: ModelApiConfig | null } | null>(null),
    [newPassword, setNewPassword] = useState(""), [search, setSearch] = useState("");
  const loadData = async () => {
    setLoading(true);
    try { const [userData, modelData] = await Promise.all([api.superadminUsers(), api.modelConfigs()]); setUsers(userData.users || []); setConfigs(modelData.configs || []); }
    catch (error) { auth.clear(); setReady(false); toast.error(String(error)); }
    finally { setLoading(false); }
  };
  useEffect(() => { if (!ready) return; void api.me().then((me) => { if (me.role !== "superadmin") throw new Error("需要超级管理员权限"); }).then(loadData).catch((error) => { auth.clear(); setReady(false); toast.error(String(error)); }); }, [ready]);
  const resetPassword = async (event: FormEvent) => { event.preventDefault(); if (!target) return; try { await api.resetUserPassword(target.id, newPassword); toast.success(`已重置 ${target.username} 的密码，并使其旧登录失效`); setTarget(null); setNewPassword(""); void loadData(); } catch (error) { toast.error(String(error)); } };
  const removeUser = async (user: SystemUser) => { if (!window.confirm(`确定删除用户“${user.username}”？该操作不可恢复。`)) return; try { await api.deleteUser(user.id); toast.success("用户已删除"); void loadData(); } catch (error) { toast.error(String(error)); } };
  const removeConfig = async (config: ModelApiConfig) => { if (!window.confirm(`确定删除模型配置“${config.name}”？其加密密钥也会一并删除。`)) return; try { await api.deleteModelConfig(config.id); toast.success("模型 API 配置已删除"); void loadData(); } catch (error) { toast.error(String(error)); } };
  const filteredUsers = users.filter((user) => `${user.id} ${user.username} ${user.email || ""} ${user.role}`.toLowerCase().includes(search.toLowerCase()));
  const category = tab === "embedding" ? "embedding" : "llm", visibleConfigs = configs.filter((item) => item.category === category && `${item.name} ${item.provider} ${item.base_url}`.toLowerCase().includes(search.toLowerCase()));
  if (!ready) return <><LiquidGlassLayer /><SuperAdminLogin onReady={() => setReady(true)} /></>;
  const titles = tab === "users" ? ["系统用户管理", "USER ACCESS CONTROL / 账户、密码与访问权限"] : tab === "llm" ? ["大模型 API 管理", "LLM ENDPOINT REGISTRY / 模型、协议、地址与密钥"] : ["嵌入模型 API 管理", "EMBEDDING REGISTRY / 向量模型与知识库连接"];
  return <main className="superadmin-page"><LiquidGlassLayer />
    <aside className="superadmin-sidebar"><div className="superadmin-logo"><span>LS</span><b>LINGSHU<br /><small>CONTROL</small></b></div><p>ADMIN PANEL</p><button className={tab === "users" ? "active" : ""} onClick={() => { setTab("users"); setSearch(""); }}><Database size={17} /><span>用户数据库</span></button><button className={tab === "llm" ? "active" : ""} onClick={() => { setTab("llm"); setSearch(""); }}><BrainCircuit size={17} /><span>大模型 API</span></button><button className={tab === "embedding" ? "active" : ""} onClick={() => { setTab("embedding"); setSearch(""); }}><Network size={17} /><span>嵌入模型 API</span></button><button onClick={() => void loadData()}><RotateCcw size={17} /><span>{loading ? "同步中" : "同步数据"}</span></button><div className="superadmin-sidebar-bottom"><button onClick={() => { auth.clear(); setReady(false); }}><LogOut size={17} /><span>安全退出</span></button></div></aside>
    <section className="superadmin-content"><header className="superadmin-header"><div><p className="kicker">LINGSHU · RESTRICTED AREA</p><h1>{titles[0]}</h1><small>{titles[1]}</small></div><span className="superadmin-live"><i /> SYSTEM ONLINE</span></header>
      {tab === "users" ? <><section className="superadmin-stats"><article><span>USERS_TOTAL</span><b>{users.length}</b><i /></article><article><span>SUPERADMIN</span><b>{users.filter((user) => user.role === "superadmin").length}</b><i /></article><article><span>LOGGED_IN</span><b>{users.filter((user) => user.last_login).length}</b><i /></article><article className="danger"><span>FILTERED_VIEW</span><b>{filteredUsers.length}</b><i /></article></section>
        <section className="superadmin-database"><header><div><h2>USER_DATABASE</h2><em>共 {users.length} 条账户记录</em></div><div className="superadmin-toolbar"><label><Search size={14} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="搜索 UID / 用户名 / 邮箱…" /></label><button type="button" className="quiet-button" onClick={() => void loadData()} disabled={loading}>{loading ? "刷新中…" : "刷新"}</button></div></header><div className="superadmin-table-wrap"><table className="superadmin-table"><thead><tr><th>UID</th><th>用户 / USER</th><th>联系方式</th><th>角色权限</th><th>创建时间</th><th>最近登录</th><th>操作</th></tr></thead><tbody>{filteredUsers.map((user) => <tr key={user.id}><td><code>#{user.id}</code></td><td><div className="superadmin-user"><span>{user.username.slice(0, 1).toUpperCase()}</span><div><b>{user.username}</b><small>{user.role === "superadmin" ? "ROOT ACCESS" : "STANDARD ACCOUNT"}</small></div></div></td><td>{user.email || "--"}</td><td><span className={`role-badge ${user.role}`}>{user.role}</span></td><td>{user.created_at || "--"}</td><td><span className={user.last_login ? "login-state online" : "login-state"}><i />{user.last_login || "从未登录"}</span></td><td className="user-actions"><button type="button" className="quiet-button" onClick={() => { setTarget(user); setNewPassword(""); }}>重置密码</button>{user.role !== "superadmin" && <button type="button" className="danger-button compact" onClick={() => void removeUser(user)}><Trash2 size={13} /> 删除</button>}</td></tr>)}</tbody></table>{!loading && !filteredUsers.length && <p className="empty-note">未找到匹配的用户记录</p>}</div><footer><span>DATABASE STATUS: {loading ? "SYNCING" : "READY"}</span><span>DISPLAYING {filteredUsers.length} / {users.length}</span></footer></section></>
        : <><section className="superadmin-stats"><article><span>{category.toUpperCase()}_TOTAL</span><b>{configs.filter((item) => item.category === category).length}</b><i /></article><article><span>ENABLED</span><b>{configs.filter((item) => item.category === category && item.enabled).length}</b><i /></article><article><span>WITH_API_KEY</span><b>{configs.filter((item) => item.category === category && item.has_api_key).length}</b><i /></article><article className="danger"><span>PROVIDERS</span><b>{new Set(configs.filter((item) => item.category === category).map((item) => item.provider)).size}</b><i /></article></section>
          <section className="superadmin-database"><header><div><h2>{category === "llm" ? "LLM_ENDPOINTS" : "EMBEDDING_ENDPOINTS"}</h2><em>启用项优先覆盖服务器 .env</em></div><div className="superadmin-toolbar"><label><Search size={14} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="搜索名称 / 类型 / 地址…" /></label><button className="danger-button compact add-model" onClick={() => setEditor({ category, config: null })}><Plus size={14} /> 添加配置</button></div></header><div className="superadmin-table-wrap"><table className="superadmin-table model-config-table"><thead><tr><th>状态</th><th>配置 / PROVIDER</th><th>API 地址</th><th>模型</th><th>API Key</th><th>更新时间</th><th>操作</th></tr></thead><tbody>{visibleConfigs.map((item) => <tr key={item.id}><td><span className={item.enabled ? "endpoint-state enabled" : "endpoint-state"}><i />{item.enabled ? "启用" : "停用"}</span></td><td><div className="superadmin-user"><span>{item.category === "llm" ? "AI" : "E"}</span><div><b>{item.name}</b><small>{item.provider} · {item.api_style}</small></div></div></td><td><code className="endpoint-url">{item.base_url}</code></td><td>{item.category === "llm" ? <small className="model-stack">LOW {item.model_low}<br />MIN {item.model_min}<br />MAX {item.model_max}</small> : <small className="model-stack">{item.model_name}<br />DIM {item.dimensions}</small>}</td><td><code>{item.api_key_masked}</code></td><td>{item.updated_at || "--"}</td><td className="user-actions"><button className="quiet-button" onClick={() => setEditor({ category: item.category, config: item })}>修改</button><button className="danger-button compact" onClick={() => void removeConfig(item)}><Trash2 size={13} /> 删除</button></td></tr>)}</tbody></table>{!loading && !visibleConfigs.length && <p className="empty-note">尚无模型 API 配置，请点击“添加配置”</p>}</div><footer><span>SECRETS: ENCRYPTED AT REST</span><span>DISPLAYING {visibleConfigs.length}</span></footer></section></>}
    </section>
    <Dialog.Root open={!!target} onOpenChange={(open) => !open && setTarget(null)}><Dialog.Portal><Dialog.Overlay className="overlay superadmin-reset-overlay" /><Dialog.Content className="modal superadmin-reset-modal"><Dialog.Title>重置用户密码</Dialog.Title><Dialog.Description>将立即使该用户当前所有登录状态失效。</Dialog.Description><form onSubmit={resetPassword}><label>用户<input value={target?.username || ""} disabled /></label><label>新密码（至少 8 位）<input value={newPassword} type="password" minLength={8} onChange={(e) => setNewPassword(e.target.value)} required autoFocus /></label><div className="modal-actions"><button type="button" className="quiet-button" onClick={() => setTarget(null)}>取消</button><button type="submit" className="danger-button">确认重置</button></div></form></Dialog.Content></Dialog.Portal></Dialog.Root>
    {editor && <ModelConfigDialog editing={editor.config} category={editor.category} onClose={() => setEditor(null)} onSaved={() => void loadData()} />}
  </main>;
}

function ConsoleApp() {
  const [ready, setReady] = useState(!!auth.get()),
    [theme, setTheme] = useState<ThemeMode>(() => {
      const stored = localStorage.getItem("lingshu_theme");
      return stored === "light" || stored === "liquid" ? stored : "dark";
    }),
    [sessions, setSessions] = useState<Session[]>([]),
    [hasMoreSessions, setHasMoreSessions] = useState(false),
    [loadingMoreSessions, setLoadingMoreSessions] = useState(false),
    [active, setActive] = useState(""),
    [eventStore, setEventStore] = useState<EventStore>(() => emptyEventStore()),
    [visibleCount, setVisibleCount] = useState(120),
    [historyHasMore, setHistoryHasMore] = useState(false),
    [detail, setDetail] = useState<Mission>({}),
    [text, setText] = useState(""),
    [autoScrollEnabled, setAutoScrollEnabled] = useState(
      () => localStorage.getItem("lingshu_auto_scroll") !== "0",
    ),
    [search, setSearch] = useState(""),
    [knowledge, setKnowledge] = useState(false),
    [mobileIntel, setMobileIntel] = useState(false),
    [rerunOpen, setRerunOpen] = useState(false),
    [rerunSource, setRerunSource] = useState<
      (Session & Record<string, unknown>) | null
    >(null),
    [pendingApproval, setPendingApproval] = useState<Record<
      string,
      unknown
    > | null>(null),
    [outgoingQueue, setOutgoingQueue] = useState<OutgoingMessage[]>([]);
  const feedRef = useRef<HTMLElement>(null);
  const autoScroll = useRef(true);
  const autoScrollEnabledRef = useRef(autoScrollEnabled);
  const sessionsRef = useRef<Session[]>([]);
  const eventsRef = useRef<Event[]>([]);
  const historyHasMoreRef = useRef(false);
  const oldestSeqRef = useRef(0);
  const loadingHistoryRef = useRef(false);
  const visibleCountRef = useRef(visibleCount);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const activeSessionRef = useRef(active);
  const outgoingQueueRef = useRef<OutgoingMessage[]>([]);
  const flushingOutgoingRef = useRef(false);
  const scrollFrameRef = useRef(0);
  const current = useMemo(
    () => sessions.find((s) => s.id === active),
    [sessions, active],
  );
  // active 在 render 阶段已经变化、清空 effect 尚未运行时，也绝不能渲染
  // 上一个会话的仓库。sessionId 是 EventStore 的硬隔离边界。
  const events = eventsForSession(eventStore, active);
  const toolEvents = eventStore.sessionId === active ? eventStore.toolItems : [];
  const phase = String(detail.phase || current?.phase || "");
  const modelLevel = String(
    detail.model_level || detail.model || current?.model_level || current?.model || "Min",
  );
  const modelName = String(detail.model_name || current?.model_name || "--");
  const modelDisplay =
    modelName && modelName !== "--" && modelName !== modelLevel
      ? `${modelLevel} · ${modelName}`
      : modelName === "--"
        ? modelLevel
        : modelName;
  const isLive = current?.is_live === true;
  activeSessionRef.current = active;
  sessionsRef.current = sessions;
  eventsRef.current = events;
  historyHasMoreRef.current = historyHasMore;
  visibleCountRef.current = visibleCount;
  const hiddenCount = Math.max(0, events.length - visibleCount);
  const renderedEvents = hiddenCount > 0 ? events.slice(-visibleCount) : events;
  const load = async (append = false) => {
    if (loadingMoreSessions) return;
    setLoadingMoreSessions(true);
    try {
      const offset = append ? sessionsRef.current.length : 0;
      const page = await api.sessions(offset, 30);
      const next = append
        ? [
            ...sessionsRef.current,
            ...page.sessions.filter(
              (item) => !sessionsRef.current.some((session) => session.id === item.id),
            ),
          ]
        : page.sessions;
      setSessions(next);
      setHasMoreSessions(page.hasMore);
      if (!active && next[0]) setActive(next[0].id);
    } catch {
      auth.clear();
      setReady(false);
    } finally {
      setLoadingMoreSessions(false);
    }
  };
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme === "light" ? "light" : "dark";
    localStorage.setItem("lingshu_theme", theme);
  }, [theme]);
  useEffect(() => {
    autoScrollEnabledRef.current = autoScrollEnabled;
    localStorage.setItem("lingshu_auto_scroll", autoScrollEnabled ? "1" : "0");
    if (autoScrollEnabled) {
      autoScroll.current = true;
      requestAnimationFrame(() => {
        const feed = feedRef.current;
        if (feed) feed.scrollTop = feed.scrollHeight;
      });
    }
  }, [autoScrollEnabled]);
  useEffect(() => {
    if (ready) void load();
  }, [ready]);
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    autoScroll.current = autoScrollEnabledRef.current;
    const sessionId = active;
    setEventStore(emptyEventStore(sessionId));
    setVisibleCount(120);
    visibleCountRef.current = 120;
    setHistoryHasMore(false);
    historyHasMoreRef.current = false;
    oldestSeqRef.current = 0;
    setDetail({});
    setPendingApproval(null);
    api
      .session(sessionId)
      .then((r) => {
        if (
          !controller.signal.aborted &&
          activeSessionRef.current === sessionId
        ) setDetail({ ...r, ...((r.mission_state as Mission) || {}) });
      })
      .catch(() => {});
    api
      .approval(sessionId)
      .then((result) => {
        if (
          !controller.signal.aborted &&
          activeSessionRef.current === sessionId &&
          result.pending &&
          result.event
        )
          setPendingApproval(result.event);
      })
      .catch(() => {});
    (async () => {
      let afterSeq = 0;
      let pendingEvents: Event[] = [];
      let flushTimer = 0;
      const flushEvents = () => {
        flushTimer = 0;
        if (controller.signal.aborted || !pendingEvents.length) return;
        const batch = pendingEvents;
        pendingEvents = [];
        setEventStore((currentEvents) =>
          currentEvents.sessionId === sessionId
            ? mergeEventBatch(currentEvents, batch)
            : currentEvents,
        );
      };
      const enqueueEvent = (event: Event) => {
        pendingEvents.push(event);
        const eventKind = kindOf(event);
        if (eventKind.endsWith("_end") || eventKind === "error") {
          if (flushTimer) window.clearTimeout(flushTimer);
          flushEvents();
        } else if (!flushTimer) {
          // 25 FPS 足以保持连续观感，同时避免单字 delta 抢占主线程。
          flushTimer = window.setTimeout(flushEvents, 40);
        }
      };
      try {
        const history = await api.messages(sessionId, { limit: 200 });
        if (
          controller.signal.aborted ||
          activeSessionRef.current !== sessionId
        ) return;
        const historyEvents = history.messages || [];
        afterSeq = historyEvents.reduce(
          (maximum, event) => Math.max(maximum, Number(event.seq || 0)),
          0,
        );
        oldestSeqRef.current = history.oldestSeq;
        setHistoryHasMore(history.hasMore);
        setEventStore(
          normalizeEvents(
            [...historyEvents, ...(history.snapshots || [])],
            sessionId,
          ),
        );
      } catch (err) {
        if (!controller.signal.aborted) toast.error(String(err));
      }
      try {
        for await (const event of stream(
          sessionId,
          controller.signal,
          afterSeq,
        )) {
          if (
            controller.signal.aborted ||
            activeSessionRef.current !== sessionId ||
            (event.session_id && String(event.session_id) !== sessionId)
          ) continue;
          enqueueEvent(event);
          const payload = dataOf(event);
          const eventKind = kindOf(event);
          if (eventKind === "approval_required")
            setPendingApproval(payload);
          if (eventKind === "approval_resolved") setPendingApproval(null);
          if (eventKind === "report_ready")
            setDetail((value) => ({
              ...value,
              report_available: true,
              report_url: String(payload.url || ""),
            }));
          if (
            ["mission_end", "mission_cancelled", "session_deleted"].includes(
              eventKind,
            )
          )
            setSessions((currentSessions) =>
              currentSessions.map((session) =>
                session.id === sessionId
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
      } finally {
        if (flushTimer) window.clearTimeout(flushTimer);
        flushEvents();
      }
    })();
    return () => controller.abort();
  }, [active]);
  useEffect(() => {
    const feed = feedRef.current;
    if (!feed || !autoScrollEnabled || !autoScroll.current) return;
    if (scrollFrameRef.current) return;
    scrollFrameRef.current = requestAnimationFrame(() => {
      scrollFrameRef.current = 0;
      const currentFeed = feedRef.current;
      if (currentFeed && autoScrollEnabledRef.current && autoScroll.current)
        currentFeed.scrollTop = currentFeed.scrollHeight;
    });
  }, [events, autoScrollEnabled]);
  useEffect(
    () => () => {
      if (scrollFrameRef.current) cancelAnimationFrame(scrollFrameRef.current);
    },
    [],
  );
  // 聊天懒加载：只渲染最近 visibleCount 条，向上滚动经哨兵分批加载更早历史
  const loadMoreEvents = useCallback(() => {
    if (loadingHistoryRef.current) return;
    const feed = feedRef.current;
    const previousHeight = feed ? feed.scrollHeight : 0;
    const currentLength = eventsRef.current.length;
    if (visibleCountRef.current < currentLength) {
      const nextCount = Math.min(visibleCountRef.current + 120, currentLength);
      visibleCountRef.current = nextCount;
      setVisibleCount(nextCount);
      requestAnimationFrame(() => {
        const nextFeed = feedRef.current;
        if (nextFeed) nextFeed.scrollTop += nextFeed.scrollHeight - previousHeight;
      });
      return;
    }
    if (!historyHasMoreRef.current || !oldestSeqRef.current) return;

    const sessionId = activeSessionRef.current;
    loadingHistoryRef.current = true;
    void api
      .messages(sessionId, { beforeSeq: oldestSeqRef.current, limit: 200 })
      .then((page) => {
        if (activeSessionRef.current !== sessionId) return;
        const olderEvents = page.messages || [];
        if (olderEvents.length) {
          setEventStore((currentStore) =>
            currentStore.sessionId === sessionId
              ? normalizeEvents(
                  [...olderEvents, ...currentStore.items],
                  sessionId,
                )
              : currentStore,
          );
          const nextVisibleCount = visibleCountRef.current + olderEvents.length;
          visibleCountRef.current = nextVisibleCount;
          setVisibleCount(nextVisibleCount);
          oldestSeqRef.current = page.oldestSeq || oldestSeqRef.current;
        }
        setHistoryHasMore(page.hasMore);
        historyHasMoreRef.current = page.hasMore;
        requestAnimationFrame(() => {
          const nextFeed = feedRef.current;
          if (nextFeed) nextFeed.scrollTop += nextFeed.scrollHeight - previousHeight;
        });
      })
      .catch((error) => toast.error(`读取更早记录失败：${String(error)}`))
      .finally(() => {
        loadingHistoryRef.current = false;
      });
  }, []);
  useEffect(() => {
    const sentinel = sentinelRef.current;
    const feed = feedRef.current;
    if (!sentinel || !feed || (events.length <= visibleCount && !historyHasMore)) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) loadMoreEvents();
      },
      { root: feed, rootMargin: "180px 0px 0px" },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [visibleCount, events.length, historyHasMore, loadMoreEvents]);
  if (!ready)
    return (
      <>
        <LiquidGlassLayer />
        <Login onReady={() => setReady(true)} />
      </>
    );
  const filtered = sessions.filter((s) =>
    `${s.title || ""} ${s.target || ""}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const flushOutgoing = async () => {
    if (flushingOutgoingRef.current) return;
    flushingOutgoingRef.current = true;
    try {
      while (outgoingQueueRef.current.length) {
        const item = outgoingQueueRef.current[0];
        try {
          await api.send(item.sessionId, item.content);
          if (activeSessionRef.current === item.sessionId) {
            setEventStore((currentEvents) =>
              currentEvents.sessionId === item.sessionId
                ? mapEventStore(currentEvents, (event) =>
                    event.client_id === item.clientId
                      ? { ...event, delivery_state: "sent" }
                      : event,
                  )
                : currentEvents,
            );
          }
        } catch (err) {
          if (activeSessionRef.current === item.sessionId) {
            setEventStore((currentEvents) =>
              currentEvents.sessionId === item.sessionId
                ? mapEventStore(currentEvents, (event) =>
                    event.client_id === item.clientId
                      ? { ...event, delivery_state: "failed" }
                      : event,
                  )
                : currentEvents,
            );
          }
          toast.error(`指令发送失败：${String(err)}`);
        } finally {
          outgoingQueueRef.current.shift();
          setOutgoingQueue([...outgoingQueueRef.current]);
        }
      }
    } finally {
      flushingOutgoingRef.current = false;
      // 请求完成边界若恰好又入队，重新接管，保证队列不会遗漏。
      if (outgoingQueueRef.current.length) void flushOutgoing();
    }
  };
  const send = () => {
    const content = text.trim();
    if (!active || !content) return;
    // 页面可能通过局域网 HTTP 地址访问；这类非安全上下文不保证提供
    // crypto.randomUUID，不能让本地队列编号阻断整个发送入口。
    const clientId = `client:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`;
    const sessionId = active;
    // 先落入本地队列、立即显示和清空输入框；网络取消/Agent 清理较慢时，
    // 操作员仍可连续补充多条情报，队列会按顺序提交给后端。
    outgoingQueueRef.current.push({ sessionId, content, clientId });
    setOutgoingQueue([...outgoingQueueRef.current]);
    setEventStore((currentEvents) => {
      const sessionStore = currentEvents.sessionId === sessionId
        ? currentEvents
        : emptyEventStore(sessionId);
      return mergeEventBatch(sessionStore, [{
        event_type: "user_message",
        agent_name: "user",
        content,
        client_id: clientId,
        delivery_state: "queued",
      }]);
    });
    setText("");
    void flushOutgoing();
  };
  const rerun = async () => {
    if (!active) return;
    try {
      const source = await api.session(active);
      setRerunSource(source);
      setRerunOpen(true);
    } catch (err) {
      toast.error(`无法读取原任务配置：${String(err)}`);
    }
  };
  const downloadReport = async () => {
    if (!active) return;
    try {
      const blob = await api.report(active);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `lingshu-report-${active}.pdf`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error(`报告下载失败：${String(err)}`);
    }
  };
  return (
    <div className="console-shell">
      <LiquidGlassLayer />
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
                <button
                  className={`theme-switch ${theme}`}
                  onClick={() =>
                    setTheme((currentTheme) =>
                      currentTheme === "light"
                        ? "dark"
                        : currentTheme === "dark"
                          ? "liquid"
                          : "light",
                    )
                  }
                  title={
                    theme === "light"
                      ? "当前：亮色；切换到暗色"
                      : theme === "dark"
                        ? "当前：暗色；切换到液态玻璃"
                        : "当前：液态玻璃；切换到亮色"
                  }
                  aria-label="切换显示样式"
                >
                  {theme === "light" ? (
                    <Moon size={15} />
                  ) : theme === "dark" ? (
                    <Sparkles size={15} />
                  ) : (
                    <Sun size={15} />
                  )}
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
                <b>{filtered.length}{hasMoreSessions ? "+" : ""}</b>
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
              {!search.trim() && hasMoreSessions && (
                <button
                  className="load-more-sessions"
                  type="button"
                  disabled={loadingMoreSessions}
                  onClick={() => void load(true)}
                >
                  {loadingMoreSessions ? "正在加载…" : "加载更多会话"}
                </button>
              )}
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
              <button
                className={`icon-button mobile-intel-toggle ${mobileIntel ? "active" : ""}`}
                onClick={() => setMobileIntel((open) => !open)}
                title="查看任务情报与工具历史"
                aria-label="查看任务情报与工具历史"
                aria-expanded={mobileIntel}
              >
                <ClipboardList size={16} />
              </button>
              <button
                className={`auto-scroll-toggle ${autoScrollEnabled ? "enabled" : ""}`}
                onClick={() => setAutoScrollEnabled((enabled) => !enabled)}
                title={autoScrollEnabled ? "自动滚动：开启" : "自动滚动：关闭"}
                aria-pressed={autoScrollEnabled}
              >
                <ArrowDown size={14} />
                自动滚动
              </button>
              {active && detail.report_available && (
                <button className="report-download" onClick={() => void downloadReport()}>
                  <FileDown size={14} />
                  下载报告
                </button>
              )}
              {active && isLive && (
                <button
                  className="stop"
                  onClick={async () => {
                    try {
                      await api.cancel(active);
                      setSessions((items) =>
                        items.map((item) =>
                          item.id === active
                            ? { ...item, is_live: false, phase: "cancelled" }
                            : item,
                        ),
                      );
                      setDetail((value) => ({
                        ...value,
                        phase: "cancelled",
                      }));
                      setPendingApproval(null);
                      toast.success("任务及后台 Agent 已全部停止");
                    } catch (err) {
                      toast.error(`停止失败：${String(err)}`);
                    }
                  }}
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
              <span>模型</span>
              <b title={`${modelLevel} · ${modelName}`}>{modelDisplay}</b>
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
            {(hiddenCount > 0 || historyHasMore) && (
              <div
                className="history-sentinel"
                ref={sentinelRef}
                onClick={loadMoreEvents}
              >
                <span>{hiddenCount > 0 ? `更早 ${hiddenCount} 条消息` : "加载更早历史"}</span>
                <small>{loadingHistoryRef.current ? "正在读取…" : "向上滚动或点击加载"}</small>
              </div>
            )}
            {renderedEvents.length ? (
              renderedEvents.map((event, i) => (
                <AgentCard key={eventRenderKey(event, i)} event={event} />
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
            {outgoingQueue.length > 0 && (
              <div className="outgoing-queue" aria-live="polite">
                <b>待发送队列 · {outgoingQueue.length}</b>
                {outgoingQueue.map((item, index) => (
                  <div key={item.clientId}>
                    <span>{index === 0 ? "发送中" : `等待 ${index}`}</span>
                    <p>{item.content}</p>
                  </div>
                ))}
              </div>
            )}
            <div className="command-input-row">
              <span className="prompt">OPERATOR@LINGSHU:~$</span>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
                placeholder="输入任务指令或审批答复…"
                rows={1}
              />
              <button type="button" onClick={send} aria-label="发送消息">
                <Send size={17} />
              </button>
            </div>
          </footer>
        </main>
        <aside className={`intel-panel ${mobileIntel ? "mobile-open" : ""}`}>
          <button
            className="mobile-intel-close"
            onClick={() => setMobileIntel(false)}
            aria-label="关闭任务情报面板"
          >
            <X size={18} />
          </button>
          <div className="intel-grid">
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
            <section className="side-section activity-section">
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
            <ToolHistoryPanel events={toolEvents} />
            <PlanPanel mission={detail} phase={phase} />
          </div>
        </aside>
        {mobileIntel && (
          <button
            className="mobile-intel-scrim"
            onClick={() => setMobileIntel(false)}
            aria-label="关闭任务情报面板"
          />
        )}
      </div>
      <Knowledge open={knowledge} onClose={() => setKnowledge(false)} />
      <RerunMission
        open={rerunOpen}
        source={rerunSource}
        onOpenChange={setRerunOpen}
        onCreated={(id) => {
          setActive(id);
          void load();
          toast.success("已启动再次攻击任务");
        }}
      />
      <ApprovalDialog
        request={pendingApproval}
        onDecision={async (decision, selection) => {
          if (!active) return;
          try {
            const result = (await api.approvalDecision(active, decision, selection)) as {
              status?: string;
            };
            if (result.status === "approval_already_resolved") {
              setPendingApproval(null);
              toast.info("该审批已处理");
              return;
            }
            setPendingApproval(null);
            toast.success(
              decision === "批准" ? "已批准攻击阶段" : `已提交：${decision}`,
            );
          } catch (err) {
            toast.error(`审批提交失败：${String(err)}`);
            throw err;
          }
        }}
      />
    </div>
  );
}

export default function App() {
  return window.location.pathname.replace(/\/+$/, "") === "/superadmin" ? <SuperAdminPage /> : <ConsoleApp />;
}
