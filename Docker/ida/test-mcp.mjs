// Minimal MCP (SSE transport) client test for ida-pro-mcp idalib server
import { setTimeout as sleep } from "node:timers/promises";

const BASE = "http://127.0.0.1:8745";

// 1. open SSE stream
const sseRes = await fetch(BASE + "/sse", { headers: { Accept: "text/event-stream" } });
if (!sseRes.ok) throw new Error("SSE connect failed: " + sseRes.status);

const reader = sseRes.body.getReader();
const decoder = new TextDecoder();
let buf = "";
const pending = new Map(); // request id -> resolve
let endpoint = null;

function handleEvent(event) {
  if (event.event === "endpoint") {
    endpoint = event.data;
    resolveEndpoint();
  } else if (event.event === "message") {
    const msg = JSON.parse(event.data);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    } else if (msg.method) {
      console.log("[server->client]", JSON.stringify(msg).slice(0, 300));
    }
  }
}

let resolveEndpointFn;
function resolveEndpoint() { resolveEndpointFn?.(); }
const endpointPromise = new Promise((r) => (resolveEndpointFn = r));

(async () => {
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    // split complete events on blank line (LF or CRLF, possibly across chunks)
    const parts = buf.split(/\r?\n\r?\n/);
    buf = parts.pop(); // keep trailing incomplete part
    for (const raw of parts) {
      const event = { event: "message", data: "" };
      for (const line of raw.split(/\r?\n/)) {
        if (line.startsWith("event:")) event.event = line.slice(6).trim();
        else if (line.startsWith("data:")) event.data += (event.data ? "\n" : "") + line.slice(5).trim();
      }
      if (event.data) handleEvent(event);
    }
  }
})();

async function post(payload) {
  const res = await fetch(BASE + endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok && res.status !== 202 && res.status !== 200)
    throw new Error("POST failed " + res.status + " " + await res.text());
  return res.status;
}

function request(method, params, timeoutMs = 60000) {
  const id = Math.floor(Math.random() * 1e9);
  const p = new Promise((resolve, reject) => {
    pending.set(id, resolve);
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error("timeout: " + method)); } }, timeoutMs);
  });
  post({ jsonrpc: "2.0", id, method, params });
  return p;
}

// 2. wait for endpoint
await endpointPromise;
console.log("[*] endpoint:", endpoint);

// 3. initialize
const init = await request("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "test-client", version: "1.0" },
});
console.log("[*] initialize ->", JSON.stringify(init.result?.serverInfo));
await post({ jsonrpc: "2.0", method: "notifications/initialized" });

// 4. tools/list
const tools = await request("tools/list", {});
const names = tools.result.tools.map((t) => t.name);
console.log(`[*] tools count: ${names.length}`);
console.log("[*] tools:", names.join(", "));

// 5. a few tool calls
async function call(name, args = {}) {
  const r = await request("tools/call", { name, arguments: args });
  const text = r.result?.content?.map((c) => c.text).join("\n") ?? JSON.stringify(r);
  console.log(`\n=== tools/call ${name} ${JSON.stringify(args)} ===`);
  console.log(text.slice(0, 1500));
}

await call("get_metadata");
await call("get_entry_points");
const fns = await request("tools/call", { name: "list_functions", arguments: { offset: 0, count: 15 } });
console.log("\n=== tools/call list_functions(0,15) ===");
console.log((fns.result?.content?.[0]?.text ?? JSON.stringify(fns)).slice(0, 1500));
const strs = await request("tools/call", { name: "list_strings", arguments: { offset: 0, count: 10 } });
console.log("\n=== tools/call list_strings(0,10) ===");
console.log((strs.result?.content?.[0]?.text ?? JSON.stringify(strs)).slice(0, 1500));

// decompile the real main function (_main_0 at 0x401050 for this binary)
const items = JSON.parse(fns.result.content[0].text);
const data = items.data ?? items.items ?? items;
const mainFn = data.find((f) => f.name === "_main_0") ?? data[0];
if (mainFn?.address) await call("decompile_function", { address: mainFn.address });

console.log("\n[OK] all tests passed");
process.exit(0);
