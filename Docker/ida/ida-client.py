#!/usr/bin/env python3
"""
ida-client.py — 远程 Agent 用 IDA-MCP 客户端 (纯 Python 标准库, 无第三方依赖)

对接 ida-mcp-up 服务 (MCP SSE + 上传 API 同端口):

  上传:      POST /upload   (阻塞, 分析完成后返回)
  状态:      GET  /status
  MCP:       /sse           (JSON-RPC, 47 个工具)

用法:
  python3 ida-client.py status
  python3 ida-client.py upload /path/to/file.bin [--filename name] [--fresh]
  python3 ida-client.py call <tool> [json-args]
      例: python3 ida-client.py call get_metadata
          python3 ida-client.py call list_functions '{"offset":0,"count":20}'
          python3 ida-client.py call decompile_function '{"address":"0x401050"}'
  python3 ida-client.py demo /path/to/file.bin     # 上传 + 常用工具一条龙
  python3 ida-client.py tools                     # 列出全部 MCP 工具

全局选项:
  --url URL       服务地址 (默认 http://127.0.0.1:8745)
  --timeout SECS  请求超时 (默认 120; 大文件上传建议调大或用 --timeout 1800)

Agent 典型工作流:
  1) upload  返回 ok=true 即"加载完成"
  2) 之后任意 call 直接分析当前库
"""

import argparse
import http.client
import json
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_URL = "http://127.0.0.1:8745"


# ---------------------------------------------------------------------------
# 上传 API
# ---------------------------------------------------------------------------

def api_get(base: str, path: str, timeout: float = 30):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=timeout) as r:
        return r.status, r.read().decode()


def cmd_status(base: str, timeout: float = 30) -> int:
    code, body = api_get(base, "/status", timeout)
    print(json.dumps(json.loads(body), indent=2, ensure_ascii=False))
    return 0 if code == 200 else 1


def cmd_upload(base: str, file: str, filename: str | None, timeout: float, fresh: bool = False) -> int:
    p = Path(file)
    if not p.is_file():
        print(f"file not found: {file}", file=sys.stderr)
        return 2
    name = filename or p.name
    url = base.rstrip("/") + ("/upload?fresh=1" if fresh else "/upload")
    boundary = uuid.uuid4().hex
    data = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        p.read_bytes(),
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    print(f"[*] uploading {p.name} ({p.stat().st_size} bytes) as '{name}' ... (阻塞至 IDA 分析完成)",
          file=sys.stderr)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, body = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read().decode()
    dt = time.time() - t0
    try:
        parsed = json.loads(body)
        out = json.dumps(parsed, indent=2, ensure_ascii=False)
    except Exception:
        parsed, out = None, body
    print(f"[upload] HTTP {code} in {dt:.1f}s")
    print(out)
    if code == 200 and isinstance(parsed, dict) and parsed.get("ok"):
        print(f"\n[OK] 加载完成: {parsed.get('binary')} "
              f"({parsed.get('functions')} functions, 分析耗时 {parsed.get('analysis_ms')} ms)\n"
              f"     现在可以调用 MCP 工具: python3 {Path(__file__).name} call <tool>", file=sys.stderr)
        return 0
    return 1


# ---------------------------------------------------------------------------
# MCP (SSE) 会话
# ---------------------------------------------------------------------------

class MCPSession:
    """最小 MCP SSE 客户端: GET /sse 拿 endpoint, POST JSON-RPC, 响应走 SSE 流。"""

    def __init__(self, base: str, timeout: float = 15):
        p = urlparse(base)
        self.host = p.hostname
        self.port = p.port or 80
        self.timeout = timeout
        self.endpoint: str | None = None
        self._ep_evt = threading.Event()
        self.pending: dict = {}
        self._lock = threading.Lock()
        self._next_id = 0
        self._stop = threading.Event()
        self._err: list = []
        threading.Thread(target=self._sse_loop, daemon=True).start()
        if not self._ep_evt.wait(timeout=timeout):
            raise RuntimeError(f"无法连接 MCP SSE ({base}/sse): 服务未就绪?")
        if self._err:
            raise RuntimeError(self._err[0])

    def _sse_loop(self):
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=None)
            conn.request("GET", "/sse", headers={"Accept": "text/event-stream"})
            resp = conn.getresponse()
            if resp.status != 200:
                self._err.append(f"SSE 连接失败: HTTP {resp.status}")
                self._ep_evt.set()
                return
            # 注意: 不能用 resp.read(amt) — chunked 流上会读到满 amt 字节才返回,
            # SSE 长连接永远读不满。按行读取 (readline) 才是行级流式。
            event, data = "message", []
            while not self._stop.is_set():
                line = resp.readline()
                if not line:
                    break
                line = line.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":  # 空行 = 一个事件结束
                    if event == "endpoint" and data:
                        self.endpoint = data[0]
                        self._ep_evt.set()
                    elif data:
                        try:
                            msg = json.loads("\n".join(data))
                        except Exception:
                            msg = None
                        if msg is not None:
                            mid = msg.get("id")
                            if mid is not None and mid in self.pending:
                                self.pending[mid]["evt"].set()
                                self.pending[mid]["msg"] = msg
                    event, data = "message", []
                elif line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].strip())
        except Exception as e:  # noqa: BLE001
            if not self._ep_evt.is_set():
                self._err.append(str(e))
                self._ep_evt.set()

    def _post(self, payload: dict):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        conn.request("POST", self.endpoint, body=json.dumps(payload).encode("utf-8"),
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        body = r.read().decode()
        if r.status not in (200, 202):
            raise RuntimeError(f"POST {payload.get('method')} 失败: HTTP {r.status} {body[:200]}")
        conn.close()

    def request(self, method: str, params: dict | None = None, timeout: float | None = None):
        with self._lock:
            self._next_id += 1
            rid = self._next_id
        holder = {"evt": threading.Event()}
        self.pending[rid] = holder
        try:
            self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
            if not holder["evt"].wait(timeout=timeout or self.timeout):
                raise TimeoutError(f"等待 {method} 响应超时 ({timeout or self.timeout}s)")
            msg = holder.get("msg")
            if msg is None:
                raise RuntimeError(f"{method}: 未收到响应")
            if "error" in msg:
                raise RuntimeError(f"{method} 错误: {json.dumps(msg['error'], ensure_ascii=False)}")
            return msg.get("result")
        finally:
            self.pending.pop(rid, None)

    def notify(self, method: str, params: dict | None = None):
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def call_tool(self, name: str, arguments: dict | None = None, timeout: float = 120):
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}},
                              timeout=timeout)
        if isinstance(result, dict):
            for c in result.get("content", []):
                if c.get("type") == "text":
                    return c["text"]
        return json.dumps(result, ensure_ascii=False, indent=2)

    def close(self):
        self._stop.set()


def open_session(base: str, timeout: float = 15) -> MCPSession:
    s = MCPSession(base, timeout=timeout)
    s.request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "ida-client", "version": "1.0"},
    })
    s.notify("notifications/initialized")
    return s


def cmd_tools(base: str) -> int:
    s = open_session(base)
    try:
        res = s.request("tools/list", {})
        tools = res.get("tools", [])
        print(f"共 {len(tools)} 个工具:\n")
        for t in tools:
            desc = (t.get("description") or "").strip().splitlines()
            print(f"  {t['name']:40s} {desc[0] if desc else ''}")
        return 0
    finally:
        s.close()


def cmd_call(base: str, tool: str, args_json: str | None) -> int:
    args = json.loads(args_json) if args_json else {}
    s = open_session(base)
    try:
        text = s.call_tool(tool, args)
        print(text)
        return 0
    finally:
        s.close()


def cmd_demo(base: str, file: str, timeout: float) -> int:
    if cmd_upload(base, file, None, timeout) != 0:
        return 1
    s = open_session(base)
    try:
        for tool, args in [
            ("get_metadata", {}),
            ("get_entry_points", {}),
            ("list_functions", {"offset": 0, "count": 15}),
            ("list_strings", {"offset": 0, "count": 10}),
        ]:
            print(f"\n=== {tool} ===")
            print(s.call_tool(tool, args)[:2500])
        return 0
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="IDA-MCP 客户端 (上传 API + MCP 工具)")
    ap.add_argument("--url", default=DEFAULT_URL, help=f"服务地址 (默认 {DEFAULT_URL})")
    ap.add_argument("--timeout", type=float, default=120, help="请求超时秒 (默认 120)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="查询服务状态")

    p_up = sub.add_parser("upload", help="上传二进制并等待 IDA 分析完成")
    p_up.add_argument("file")
    p_up.add_argument("--filename", default=None, help="覆盖保存文件名")
    p_up.add_argument("--fresh", action="store_true", help="强制全量重新分析 (不复用旧 IDB)")

    p_call = sub.add_parser("call", help="调用一个 MCP 工具")
    p_call.add_argument("tool")
    p_call.add_argument("args", nargs="?", default=None, help='JSON 参数, 如 \'{"offset":0,"count":20}\'')

    p_demo = sub.add_parser("demo", help="上传 + 常用工具一条龙 (上传/元数据/入口/函数/字符串)")
    p_demo.add_argument("file")

    sub.add_parser("tools", help="列出全部 MCP 工具")

    a = ap.parse_args()
    if a.cmd == "status":
        return cmd_status(a.url, timeout=min(a.timeout, 60))
    if a.cmd == "upload":
        return cmd_upload(a.url, a.file, a.filename, timeout=a.timeout, fresh=a.fresh)
    if a.cmd == "call":
        return cmd_call(a.url, a.tool, a.args)
    if a.cmd == "tools":
        return cmd_tools(a.url)
    if a.cmd == "demo":
        return cmd_demo(a.url, a.file, timeout=a.timeout)
    return 2


if __name__ == "__main__":
    sys.exit(main())
