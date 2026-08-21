#!/usr/bin/env bash
# 上传 API + MCP 全链路回归测试
# 用法: ./test-upload.sh [二进制文件] [端口]
set -euo pipefail
BIN="${1:-./c809d6f2590b8f72c2191c7fd222c7529af451a813bbf067c0fc2c1ed675e879.exe}"
PORT="${2:-8745}"
BASE="http://127.0.0.1:$PORT"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

say "1. 等待服务就绪 (GET /status)"
for i in $(seq 1 60); do
  S=$(curl -s -m 2 "$BASE/status" 2>/dev/null || true)
  [[ "$S" == *'"status"'* ]] && break
  sleep 1
done
[[ "$S" == *'"status"'* ]] || fail "服务未就绪"
echo "$S" | python3 -m json.tool

say "2. 上传 (multipart, 阻塞至分析完成)"
T0=$(date +%s%N)
R=$(curl -s --max-time 600 -X POST "$BASE/upload" -F "file=@$BIN")
T1=$(date +%s%N)
echo "$R" | python3 -m json.tool
echo "$R" | grep -q '"ok": true\|"ok":true' || fail "upload 未返回 ok"
echo "耗时: $(( (T1 - T0) / 1000000 )) ms"

say "3. GET /ready (期望 200)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ready")
[[ "$CODE" == "200" ]] || fail "/ready = $CODE"
echo "200 OK"

say "4. MCP 全链路 (握手 + 元数据 + 函数 + 字符串 + 反编译)"
cd "$(dirname "$0")"
node test-mcp.mjs | grep -E '^\[\*\] (initialize|tools count)|^\[OK\]' || fail "MCP 回归失败"

say "5. POST /close -> idle, /ready 期望 503"
curl -s -X POST "$BASE/close" | grep -q '"status": "idle"\|"status":"idle"' || fail "close 失败"
echo "closed -> idle"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ready")
[[ "$CODE" == "503" ]] || fail "/ready = $CODE (期望 503)"
echo "503 OK"

say "6. 重新上传同文件 (复用 IDB, 应很快)"
T0=$(date +%s%N)
curl -s --max-time 600 -X POST "$BASE/upload" -F "file=@$BIN" | grep -q '"ok": true\|"ok":true' || fail "re-upload 失败"
T1=$(date +%s%N)
echo "耗时: $(( (T1 - T0) / 1000000 )) ms"

echo
echo "ALL PASSED"
