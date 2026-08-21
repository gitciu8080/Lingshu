#!/usr/bin/env bash
# 一键部署 ida-pro-mcp 升级版 (idalib + HTTP 上传 API) 容器
#
# 用法:
#   ./run-ida-mcp.sh                          # idle 启动, 等待 POST /upload
#   ./run-ida-mcp.sh <二进制文件路径>          # 启动即分析该文件 (兼容旧版用法)
#   ./run-ida-mcp.sh <二进制文件路径> 容器名   # 指定容器名 (默认 ida-mcp)
#
# 环境变量:
#   PORT   宿主机端口 (默认 8745)
set -euo pipefail

BIN="${1:-}"
NAME="${2:-ida-mcp}"
PORT="${PORT:-8745}"
IMAGE="ida-mcp-up:latest"

if [[ -n "$BIN" ]]; then
  [[ -f "$BIN" ]] || { echo "文件不存在: $BIN" >&2; exit 1; }
  DIR="$(cd "$(dirname "$BIN")" && pwd)"
  BASE="$(basename "$BIN")"
else
  DIR="/home/gitciu/ida"
  BASE=""
fi

# 同一个 server 实例绑定一个二进制; 切换目标 = 重建容器
docker rm -f "$NAME" >/dev/null 2>&1 || true

if [[ -n "$BASE" ]]; then
  docker run -d --name "$NAME" \
    -v "$DIR:/analysis" \
    -p "$PORT:$PORT" \
    "$IMAGE" "/analysis/$BASE" >/dev/null
  echo "[*] 容器 $NAME 已启动, 启动即分析: $BASE (挂载 $DIR -> /analysis)"
else
  docker run -d --name "$NAME" \
    -v "$DIR:/analysis" \
    -p "$PORT:$PORT" \
    "$IMAGE" >/dev/null
  echo "[*] 容器 $NAME 已启动 (idle, 等待 POST http://127.0.0.1:$PORT/upload; 挂载 $DIR -> /analysis)"
fi

echo "[*] 等待 IDA 就绪 ..."
for i in $(seq 1 300); do
  st="$(curl -s -m 2 "http://127.0.0.1:$PORT/status" 2>/dev/null || true)"
  if echo "$st" | grep -qE '"status":"(ready|idle)"'; then
    echo "$st" | python3 -c "import json,sys; d=json.load(sys.stdin); print('[+] 就绪: status=%s binary=%s' % (d['status'], d.get('binary')))"
    echo "[+] MCP:  http://127.0.0.1:$PORT/sse"
    echo "[+] 上传: curl -F 'file=@/path/to/bin' http://127.0.0.1:$PORT/upload"
    exit 0
  fi
  sleep 2
done
echo "[-] 启动超时(10 分钟), 查看日志: docker logs $NAME" >&2
exit 1
