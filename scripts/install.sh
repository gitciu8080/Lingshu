#!/usr/bin/env bash
# 灵枢一键部署编排器：基础环境 → 安全工具 → Python 依赖 → GDB MCP → Node 组件 → 前端 → systemd。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
INSTALL_USER="${SUDO_USER:-$USER}"
INSTALL_HOME="$(getent passwd "$INSTALL_USER" 2>/dev/null | cut -d: -f6 || true)"
INSTALL_HOME="${INSTALL_HOME:-$HOME}"
CONDA_PREFIX="${LINGSHU_CONDA_PREFIX:-$INSTALL_HOME/miniconda3}"
ENV_NAME="${LINGSHU_CONDA_ENV:-agentscope}"
PYTHON_VERSION="${LINGSHU_CONDA_PYTHON_VERSION:-3.14}"
UV_BIN_DIR="${LINGSHU_UV_BIN_DIR:-$INSTALL_HOME/.local/bin}"
GDB_MCP_SOURCE="git+https://gh-proxy.org/https://github.com/Mistyovo/gdb-multi-mcp@6e8048b8e933bbbae79b6da16fe69249f56fe30d"
SECURITY_PROFILE="core"
SKIP_WEBUI=0
SKIP_SYSTEM_ENVIRONMENT=0
SKIP_SECURITY_TOOLS=0
WITH_SYSTEMD=0
DRY_RUN=0

log() { printf '\033[1;36m[灵枢部署]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  printf '%s\n' \
    '用法: sudo ./scripts/install.sh [选项]' \
    '' \
    '选项:' \
    '  --skip-system-environment  跳过基础系统/Miniconda/Conda 环境安装' \
    '  --skip-security-tools      跳过安全工具、OCR 语言包和 JDK 安装' \
    '  --security-profile core|extended  安全工具配置（默认 core）' \
    '  --skip-webui               跳过 React 前端构建' \
    '  --with-systemd             安装并启动 lingshu-agent.service' \
    '  --conda-prefix PATH        Miniconda 根目录（默认当前部署用户的 ~/miniconda3）' \
    '  --env-name NAME            Conda 环境名（默认 agentscope）' \
    '  --python-version VERSION   新建 Conda 环境的 Python 版本（默认 3.14）' \
    '  --dry-run                  仅打印安装动作，不修改系统' \
    '  -h, --help                 显示帮助'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-system-environment) SKIP_SYSTEM_ENVIRONMENT=1 ;;
    --skip-security-tools) SKIP_SECURITY_TOOLS=1 ;;
    --security-profile) SECURITY_PROFILE="${2:?--security-profile 需要 core 或 extended}"; shift ;;
    --skip-webui) SKIP_WEBUI=1 ;;
    --with-systemd) WITH_SYSTEMD=1 ;;
    --conda-prefix) CONDA_PREFIX="${2:?--conda-prefix 需要路径}"; shift ;;
    --env-name) ENV_NAME="${2:?--env-name 需要名称}"; shift ;;
    --python-version) PYTHON_VERSION="${2:?--python-version 需要版本}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
  shift
done

case "$SECURITY_PROFILE" in core|extended) ;; *) fail '安全工具 profile 仅支持 core 或 extended' ;; esac
[ -f "$ROOT/requirements.txt" ] || fail "未找到 $ROOT/requirements.txt"
[ -f "$ROOT/.env.example" ] || fail "未找到 $ROOT/.env.example"
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  fail '需要 root 权限：请使用 sudo ./scripts/install.sh 运行'
fi

as_install_user() {
  if [ "$(id -u)" -eq 0 ] && [ "$INSTALL_USER" != "root" ]; then
    runuser -u "$INSTALL_USER" -- env HOME="$INSTALL_HOME" "$@"
  else
    "$@"
  fi
}

child_args=(--conda-prefix "$CONDA_PREFIX" --env-name "$ENV_NAME" --python-version "$PYTHON_VERSION")
if [ "$DRY_RUN" -eq 1 ]; then child_args+=(--dry-run); fi

if [ "$SKIP_SYSTEM_ENVIRONMENT" -eq 0 ]; then
  log '== 1/7 基础系统、AgentScope Conda 与 uv/uvx =='
  "${SCRIPT_DIR}/install-system-environment.sh" "${child_args[@]}"
else
  log '== 1/7 已跳过基础系统、Conda 与 uv/uvx =='
fi

if [ "$SKIP_SECURITY_TOOLS" -eq 0 ]; then
  log '== 2/7 安全工具、Volatility、OCR 语言包与 JDK =='
  security_args=(--profile "$SECURITY_PROFILE")
  if [ "$DRY_RUN" -eq 1 ]; then security_args+=(--dry-run); fi
  LINGSHU_PYTHON_BIN="$CONDA_PREFIX/envs/$ENV_NAME/bin/python" \
    "${SCRIPT_DIR}/install-security-tools.sh" "${security_args[@]}"
else
  log '== 2/7 已跳过安全工具 =='
fi

PYTHON_BIN="$CONDA_PREFIX/envs/$ENV_NAME/bin/python"
if [ "$DRY_RUN" -eq 1 ]; then
  log "== 3/7 [dry-run] ${PYTHON_BIN} -m pip install -r requirements.txt =="
elif [ ! -x "$PYTHON_BIN" ]; then
  fail "未找到 AgentScope Python：$PYTHON_BIN；请勿在系统 Python 或其他 Conda 环境安装依赖"
else
  log '== 3/7 安装 AgentScope Python 依赖 =='
  as_install_user "$PYTHON_BIN" -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
  as_install_user "$PYTHON_BIN" -m pip install -r "$ROOT/requirements.txt" -i https://pypi.tuna.tsinghua.edu.cn/simple
  as_install_user "$PYTHON_BIN" -m pip check
fi

# API 的 .mcp.json 使用 uvx --offline；因此部署时必须先以固定 Git commit
# 安装 gdb-multi-mcp，使其入口和依赖均位于服务用户的本地环境。
UV_BIN="$UV_BIN_DIR/uv"
if [ ! -x "$UV_BIN" ]; then
  UV_BIN="$(command -v uv || true)"
fi
if [ "$DRY_RUN" -eq 1 ]; then
  log '== 4/7 [dry-run] 安装固定版本 GDB Multi MCP =='
  log "$UV_BIN_DIR/uv tool install --reinstall --from $GDB_MCP_SOURCE gdb-multi-mcp"
elif [ -z "$UV_BIN" ] || [ ! -x "$UV_BIN" ]; then
  fail '未找到 uv；请先执行 scripts/install-system-environment.sh，GDB Multi MCP 不能部署。'
else
  log '== 4/7 安装固定版本 GDB Multi MCP =='
  as_install_user "$UV_BIN" tool install --reinstall --from "$GDB_MCP_SOURCE" gdb-multi-mcp
fi

# AntSword 使用随项目交付的已编译 Loader，不在部署时安装或更新其 Node
# 依赖，避免改写客户已验证的运行环境。归档传输可能丢失可执行位，部署时
# 统一恢复 Loader 的执行权限。PDF Mermaid 渲染器仍需安装其自身的 Node
# 依赖，且不属于 React 前端，因此即使 --skip-webui 也必须处理。
ANTSWORD_EXECUTABLE="$ROOT/Tools/AntSword-Loader-v4.0.3-linux-x64/AntSword"
if [ -f "$ANTSWORD_EXECUTABLE" ]; then
  chmod +x "$ANTSWORD_EXECUTABLE"
else
  warn "未找到 AntSword Loader：$ANTSWORD_EXECUTABLE"
fi

MERMAID_DIR="$ROOT/Skills/beautiful-mermaid"
if [ ! -f "$MERMAID_DIR/package-lock.json" ]; then
  warn "未找到 Mermaid 渲染器 lockfile，报告中的流程图将自动降级为源码块。"
elif [ "$DRY_RUN" -eq 1 ]; then
  log '== 5/7 [dry-run] 安装 PDF Mermaid Node 依赖 =='
  log "cd $MERMAID_DIR && npm ci --omit=dev"
elif ! command -v npm >/dev/null 2>&1; then
  warn '未找到 npm，跳过 PDF Mermaid 渲染器 Node 依赖；报告中的流程图将降级为源码块。'
else
  log '== 5/7 安装 PDF Mermaid Node 依赖 =='
  as_install_user bash -lc "cd '$MERMAID_DIR' && npm ci --omit=dev"
fi

if [ "$SKIP_WEBUI" -eq 1 ]; then
  log '== 6/7 已跳过前端构建 =='
elif [ "$DRY_RUN" -eq 1 ]; then
  log '== 6/7 [dry-run] pnpm install && pnpm build =='
elif ! command -v node >/dev/null 2>&1; then
  warn '未找到 node，跳过前端构建；可修复系统环境后重跑本脚本。'
else
  log '== 6/7 构建 React 前端 =='
  if command -v corepack >/dev/null 2>&1; then
    # Debian/Kali 的 corepack enable 会尝试向 /usr/bin 写 pnpm/yarn
    # 软链接；以服务用户运行必然 EACCES。直接经 corepack 执行固定
    # pnpm 版本即可，无需修改系统目录。
    as_install_user bash -lc "cd '$ROOT/webui' && corepack pnpm@10.14.0 install && corepack pnpm@10.14.0 build"
  elif command -v pnpm >/dev/null 2>&1; then
    as_install_user bash -lc "cd '$ROOT/webui' && pnpm install && pnpm build"
  else
    as_install_user npm install -g pnpm@10.14.0
    as_install_user bash -lc "cd '$ROOT/webui' && pnpm install && pnpm build"
  fi
fi

if [ -f "$ROOT/.env" ]; then
  log '保留已有 .env（不会覆盖模型密钥或管理员密码）'
elif [ "$DRY_RUN" -eq 0 ]; then
  as_install_user cp "$ROOT/.env.example" "$ROOT/.env"
  warn '已创建 .env：首次启动前必须设置 JWT_SECRET、LINGSHU_SUPERADMIN_PASSWORD 和模型配置。'
fi

if [ "$WITH_SYSTEMD" -eq 1 ]; then
  log '== 7/7 安装 systemd 服务 =='
  [ "$DRY_RUN" -eq 0 ] || { log '[dry-run] 将写入并启动 lingshu-agent.service'; exit 0; }
  cat > /etc/systemd/system/lingshu-agent.service <<EOF
[Unit]
Description=Lingshu authorized security testing agent
After=network.target

[Service]
Type=simple
User=${INSTALL_USER}
Group=${INSTALL_USER}
WorkingDirectory=${ROOT}
ExecStart=${PYTHON_BIN} ${ROOT}/api.py
Restart=always
RestartSec=5
TimeoutStartSec=180s
TimeoutStopSec=90s
KillMode=control-group
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now lingshu-agent.service
  log 'systemd 服务已启动：systemctl status lingshu-agent'
else
  log '== 7/7 未安装 systemd 服务 =='
fi

log '部署完成。运行 API：'
log "  ${PYTHON_BIN} ${ROOT}/api.py"
