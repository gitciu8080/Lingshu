#!/usr/bin/env node
/**
 * AntSwordMCP 连通性验证脚本
 * 用法: node docker/test-mcp.js [url]   默认 http://localhost:30080/sse
 */
'use strict';

const http = require('http');

const url = process.argv[2] || 'http://localhost:30080/sse';
const u = new URL(url);
const port = u.port || 80;
const hostHeader = u.host; // 必须保持 localhost/127.0.0.1，否则被插件 Host 白名单 403

function req(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request(
      { host: u.hostname, port, path, method, headers: {
        'Content-Type': 'application/json',
        'Host': hostHeader,
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      } },
      (res) => {
        let buf = '';
        res.on('data', (c) => (buf += c));
        res.on('end', () => resolve({ status: res.statusCode, body: buf }));
      }
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  // 1) 建立 SSE 长连接
  const res = await new Promise((resolve, reject) => {
    const r = http.get({ host: u.hostname, port, path: u.pathname, headers: { 'Host': hostHeader } }, resolve);
    r.on('error', reject);
  });
  res.setEncoding('utf8');

  let sessionId = null;
  const pending = new Map();
  const timeout = setTimeout(() => { console.error('FAIL: timeout waiting for response'); process.exit(1); }, 15000);

  res.on('data', (chunk) => {
    for (const line of chunk.split('\n')) {
      if (line.startsWith('data: ')) {
        const payload = line.slice(6);
        if (payload.startsWith('/messages')) {
          sessionId = payload.split('session_id=')[1];
          console.log(`[ok] SSE endpoint: ${payload}`);
        } else {
          try {
            const msg = JSON.parse(payload);
            if (msg.id !== undefined && pending.has(msg.id)) {
              pending.get(msg.id)(msg);
              pending.delete(msg.id);
            }
          } catch (e) { /* ignore keep-alive */ }
        }
      }
    }
  });

  const call = (id, method, params) => new Promise((resolve) => {
    pending.set(id, resolve);
    req('POST', `/messages?session_id=${sessionId}`, { jsonrpc: '2.0', id, method, params }).catch((e) => {
      console.error('POST failed:', e.message);
      process.exit(1);
    });
  });

  const waitEndpoint = new Promise((r) => {
    const t = setInterval(() => sessionId && (clearInterval(t), r()), 50);
  });
  await waitEndpoint;

  // 2) initialize
  const init = await call(1, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'smoke-test', version: '1.0.0' },
  });
  console.log('[ok] initialize ->', JSON.stringify(init.result && init.result.serverInfo));

  // 3) initialized 通知
  req('POST', `/messages?session_id=${sessionId}`, { jsonrpc: '2.0', method: 'notifications/initialized' })
    .then((r) => console.log(`[ok] initialized notification -> HTTP ${r.status}`));

  // 4) tools/list
  const tools = await call(2, 'tools/list', {});
  const list = (tools.result && tools.result.tools) || [];
  console.log(`[ok] tools/list -> ${list.length} 个工具`);
  console.log(list.map((t) => t.name).join(' '));

  // 5) 调用一个只读工具 shell_list
  const sl = await call(3, 'tools/call', { name: 'shell_list', arguments: {} });
  const txt = sl.result && sl.result.content && sl.result.content[0] && sl.result.content[0].text;
  console.log('[ok] shell_list ->', (txt || JSON.stringify(sl)).slice(0, 200));

  clearTimeout(timeout);
  process.exit(0);
})().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
