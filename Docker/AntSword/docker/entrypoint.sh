#!/bin/bash
# antSword 容器入口：
#   1. 安装 AntSwordMCP 插件（幂等：不覆盖用户已修改的版本）
#   2. 启动 Xvfb 虚拟显示（无头环境）
#   3. 前台运行 antSword（root 运行 Electron 需要 --no-sandbox）
set -e

export AS_WORKDIR="${AS_WORKDIR:-/opt/antsword}"
mkdir -p "$AS_WORKDIR/antData/plugins"

PLUG_DIR="$AS_WORKDIR/antData/plugins/AntSwordMCP"
if [ ! -f "$PLUG_DIR/index.js" ]; then
  rm -rf "$PLUG_DIR"
  cp -r /opt/mcp-plugin "$PLUG_DIR"
  echo "[entrypoint] AntSwordMCP installed to $PLUG_DIR"
fi

# 虚拟显示（headless）——先清理残留锁文件, 否则 docker restart 后 Xvfb 无法启动
rm -f /tmp/.X99-lock
rm -f /tmp/.X11-unix/X99
Xvfb :99 -screen 0 1280x800x24 -nolisten tcp &
XVFB_PID=$!
sleep 1
export DISPLAY=:99

# 强制退出时同时清理锁文件, 保证下次 restart 可正常拉起
trap 'kill "$XVFB_PID" 2>/dev/null || true; rm -f /tmp/.X99-lock /tmp/.X11-unix/X99' EXIT

# 前台运行 antSword，MCP 服务随渲染进程自启动（见 app.entry.js 末尾追加代码）
/opt/electron/electron \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  /opt/antsword/app.js
