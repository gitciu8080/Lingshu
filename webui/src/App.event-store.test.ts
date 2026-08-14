import { beforeAll, describe, expect, it, vi } from "vitest";

let emptyEventStore: typeof import("./App").emptyEventStore;
let mergeEventInto: typeof import("./App").mergeEventInto;
let eventsForSession: typeof import("./App").eventsForSession;

beforeAll(async () => {
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
    clear: () => values.clear(),
  });
  ({ emptyEventStore, mergeEventInto, eventsForSession } = await import("./App"));
});

describe("Agent stream event isolation", () => {
  it("never exposes the previous session store after switching sessions", () => {
    const store = emptyEventStore("session-old");
    mergeEventInto(store, {
      event_type: "message",
      agent_name: "Attack",
      content: "旧会话最后一条消息",
    });

    expect(eventsForSession(store, "session-old")).toHaveLength(1);
    expect(eventsForSession(store, "session-new")).toEqual([]);
  });

  it("does not replace a completed Attack message with another block snapshot", () => {
    const store = emptyEventStore();
    mergeEventInto(store, {
      event_type: "text_end",
      agent_name: "Attack",
      block_id: "attack-old",
      full_text: "前一轮验证结论",
    });
    mergeEventInto(store, {
      event_type: "stream_snapshot",
      agent_name: "Attack",
      block_id: "attack-new",
      stream_type: "text",
      content: "中断前的部分新内容",
    });

    expect(store.items).toHaveLength(2);
    expect(store.items[0].content).toBe("前一轮验证结论");
    expect(store.items[1].content).toBe("中断前的部分新内容");
  });

  it("freezes an unfinished Attack block before a new block starts", () => {
    const store = emptyEventStore();
    mergeEventInto(store, {
      event_type: "text_start",
      agent_name: "Attack",
      block_id: "attack-first",
    });
    mergeEventInto(store, {
      event_type: "text_delta",
      agent_name: "Attack",
      block_id: "attack-first",
      delta: "必须保留的已有内容",
    });
    mergeEventInto(store, {
      event_type: "text_start",
      agent_name: "Attack",
      block_id: "attack-second",
    });
    mergeEventInto(store, {
      event_type: "text_delta",
      agent_name: "Attack",
      block_id: "attack-second",
      delta: "根据补充情报重新分析",
    });

    expect(store.items).toHaveLength(2);
    expect(store.items[0].content).toBe("必须保留的已有内容");
    expect(store.items[0].event_type).toBe("text_end");
    expect(store.items[1].content).toBe("根据补充情报重新分析");
  });

  it("deduplicates the persisted echo of an optimistic user message", () => {
    const store = emptyEventStore();
    mergeEventInto(store, {
      event_type: "user_message",
      agent_name: "user",
      client_id: "client-1",
      content: "补充情报",
      delivery_state: "queued",
    });
    mergeEventInto(store, {
      type: "user_message",
      content: "补充情报",
      seq: 42,
    });

    expect(store.items).toHaveLength(1);
    expect(store.items[0].content).toBe("补充情报");
  });
});
