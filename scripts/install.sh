#!/usr/bin/env bash
#
# 灵枢（LingShu）一键部署脚本
#
# 面向全新 Ubuntu 22.04+/24.04、Debian 12+、Kali Linux 的源码一键部署：
#   系统依赖 -> Python venv + requirements.txt -> 前端构建(可选) -> .env 引导 -> (可选) systemd
#
# 用法:
#   sudo ./scripts/install.sh [--skip-webui] [--with-systemd] [--dry-run] [-h|--help]
#
# 特性: 幂等可重跑、.env 不覆盖、分步日志、关键步骤失败即非零退出。
#
set -euo pipefail

# ─────────────────────────── 常量 ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/lingshu-install.log"
VENV_DIR="${ROOT}/.venv"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11
NODE_MIN_MAJOR=20
PNPM_PIN="10.14.0"
SYSTEMD_UNIT="lingshu-agent.service"
API_PORT=8080

SKIP_WEBUI=0
WITH_SYSTEMD=0
DRY_RUN=0

# ─────────────────────────── 辅助函数 ───────────────────────────
log()  { printf '\033[1;36m[灵枢部署]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

usage() {
  cat <<'EOF'
灵枢（LingShu）一键部署脚本

用法: sudo ./scripts/install.sh [选项]

选项:
  --skip-webui     跳过 React 前端构建（仅使用旧版静态前端 frontend/）
  --with-systemd   安装 systemd 服务 lingshu-agent 并开机自启
  --dry-run        仅打印将执行的步骤，不实际安装
  -h, --help       显示本帮助

说明:
  - 幂等可重跑：已完成的步骤自动跳过，失败后重跑即可续传。
  - .env 仅在本不存在时生成，绝不覆盖已有配置。
EOF
}

version_ge() { # version_ge <major> <minor> <cur_major> <cur_minor>
  [ "$3" -gt "$1" ] || { [ "$3" -eq "$1" ] && [ "$4" -ge "$2" ]; }
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "需要 root 权限：请使用 sudo ./scripts/install.sh 运行"
  fi
}

# ─────────────────────────── 参数解析 ───────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-webui)   SKIP_WEBUI=1 ;;
    --with-systemd) WITH_SYSTEMD=1 ;;
    --dry-run)      DRY_RUN=1 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

# ─────────────────────────── 1. 环境检测 ───────────────────────────
# 失败时把退出命令与时间戳记入日志（dry-run 不写盘）
if [ "$DRY_RUN" -eq 0 ]; then
  trap 'printf "\n[%s] install.sh 失败于命令: %s\n" "$(date "+%Y-%m-%d %H:%M:%S")" "${BASH_COMMAND}" >> "${LOG_FILE}"' ERR
fi
log "== 1/6 环境检测 =="
if [ "$DRY_RUN" -eq 0 ]; then
  require_root
else
  log "dry-run 模式：仅打印将执行的步骤（无需 root）"
fi

# 1.1 操作系统识别
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian|kali)
      log "操作系统: ${PRETTY_NAME:-$ID}（受支持）"
      ;;
    *)
      warn "操作系统 ${ID:-未知} 未在官方支持列表（Ubuntu/Debian/Kali），继续尝试..."
      ;;
  esac
else
  warn "无法识别操作系统，假定为 Debian 系继续"
fi

# 1.2 Python 版本
if ! command -v python3 >/dev/null 2>&1; then
  fail "未找到 python3，请先安装: sudo apt install -y python3"
fi
PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"; PY_MINOR="${PY_VER#*.}"; PY_MINOR="${PY_MINOR%%.*}"
if ! version_ge "$PYTHON_MIN_MAJOR" "$PYTHON_MIN_MINOR" "$PY_MAJOR" "$PY_MINOR"; then
  fail "Python 版本过低: ${PY_VER}（需要 >= ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}）"
fi
log "Python: ${PY_VER}（满足 >= ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}）"

# 1.3 磁盘空间（建议 >= 5GB）
AVAIL_MB="$(df -Pk "${ROOT}" | awk 'NR==2 {print $4}')"
if [ "${AVAIL_MB:-0}" -lt 5242880 ]; then
  warn "磁盘剩余 ${AVAIL_MB} MB，建议至少 5 GB（依赖含 numpy/opencv/pwntools 等）"
fi

# 1.4 项目完整性
[ -f "${ROOT}/requirements.txt" ] || fail "未找到 requirements.txt，请确认在项目根目录执行"
[ -f "${ROOT}/.env.example" ]     || fail "未找到 .env.example"

# ─────────────────────────── 2. 系统依赖 ───────────────────────────
log "== 2/6 安装系统依赖 =="
SYS_PKGS=(
  python3 python3-venv python3-pip
  git curl
  tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim
  gdb xvfb
)
run apt-get update -y
run apt-get install -y "${SYS_PKGS[@]}"

# ─────────────────────────── 3. Python 环境 ───────────────────────────
log "== 3/6 创建 Python 虚拟环境并安装依赖 =="
if [ ! -d "${VENV_DIR}" ]; then
  run python3 -m venv "${VENV_DIR}"
  log "已创建虚拟环境 ${VENV_DIR}"
else
  log "虚拟环境已存在，跳过创建（幂等）"
fi

run "${VENV_DIR}/bin/pip" install --upgrade pip
# 幂等：已安装全部依赖时跳过（仍会尝试，pip 会自动跳过已满足项）
run "${VENV_DIR}/bin/pip" install -r "${ROOT}/requirements.txt"

# 关键包导入验证
if [ "$DRY_RUN" -eq 0 ]; then
  if "${VENV_DIR}/bin/python" -c 'import agentscope, fastapi, uvicorn' 2>/dev/null; then
    log "Python 依赖验证通过（agentscope/fastapi/uvicorn 可导入）"
  else
    warn "依赖安装后关键包导入失败，请检查上方 pip 输出；"
    warn "若为 opencv 冲突，可参考 docs/部署手册.md FAQ 处理（sed 去掉 opencv-python 后重装）"
  fi
fi

# ─────────────────────────── 4. 前端构建（可选） ───────────────────────────
if [ "$SKIP_WEBUI" -eq 1 ]; then
  log "== 4/6 前端构建 =="
  log "已跳过（--skip-webui），API 将回退托管旧版静态前端 frontend/"
elif [ -d "${ROOT}/webui/dist" ] && [ -f "${ROOT}/webui/dist/index.html" ]; then
  log "== 4/6 前端构建 =="
  log "webui/dist 已存在，跳过构建（幂等）"
else
  log "== 4/6 构建 React 前端（webui/） =="
  if command -v node >/dev/null 2>&1; then
    NODE_VER="$(node -v | sed 's/^v//')"
    NODE_MAJOR="${NODE_VER%%.*}"
    if [ "$NODE_MAJOR" -lt "$NODE_MIN_MAJOR" ]; then
      warn "Node 版本过低（${NODE_VER}，需要 >= ${NODE_MIN_MAJOR}），尝试继续..."
    fi
    # pnpm：优先 corepack，其次 npm 全局
    if command -v corepack >/dev/null 2>&1; then
      run corepack prepare "pnpm@${PNPM_PIN}" --activate
      PNPM="corepack pnpm@${PNPM_PIN}"
    elif command -v pnpm >/dev/null 2>&1; then
      PNPM="pnpm"
    else
      run npm install -g "pnpm@${PNPM_PIN}"
      PNPM="pnpm"
    fi
    if run bash -c "cd '${ROOT}/webui' && ${PNPM} install && ${PNPM} build"; then
      if [ "$DRY_RUN" -eq 0 ]; then
        if [ -f "${ROOT}/webui/dist/index.html" ]; then
          log "前端构建成功 → webui/dist/"
        else
          warn "前端构建结束但未找到 webui/dist/index.html，API 将回退旧版前端"
        fi
      fi
    else
      warn "前端构建失败，回退托管旧版静态前端 frontend/（可稍后重跑本脚本或手动构建）"
    fi
  else
    warn "未找到 node，跳过前端构建；API 将回退托管旧版静态前端 frontend/"
    warn "如需新版界面，请安装 Node >= ${NODE_MIN_MAJOR} 后重跑本脚本"
  fi
fi

# ─────────────────────────── 5. .env 配置引导 ───────────────────────────
log "== 5/6 生成 .env 配置 =="
if [ -f "${ROOT}/.env" ]; then
  log ".env 已存在，跳过（不会覆盖你的配置）"
else
  run cp "${ROOT}/.env.example" "${ROOT}/.env"
  log "已从 .env.example 生成 .env，请编辑填入模型密钥："
  log "  vim ${ROOT}/.env   （必填 DEEPSEEK_API_KEY=sk-xxx，或配置 Qwen 端点）"
  warn "生产环境请务必修改: JWT_SECRET / LINGSHU_SUPERADMIN_PASSWORD / LINGSHU_REGISTRATION_INVITE_CODE"
  warn "（LINGSHU_USER/LINGSHU_PASS 仅用于外部靶场 NSSCTF/SLAB 提交账号，非控制台认证）"
fi

# ─────────────────────────── 6. systemd 服务化（可选） ───────────────────────────
if [ "$WITH_SYSTEMD" -eq 1 ]; then
  log "== 6/6 安装 systemd 服务 ${SYSTEMD_UNIT} =="
  RUN_USER="${SUDO_USER:-root}"
  UNIT_FILE="/etc/systemd/system/${SYSTEMD_UNIT}"
  if [ "$DRY_RUN" -eq 0 ]; then
    cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=灵枢·利刃 Agent - 面向授权安全测试的多专家协作智能体
After=network.target

[Service]
Type=simple

User=${RUN_USER}
Group=${RUN_USER}

WorkingDirectory=${ROOT}

ExecStart=${VENV_DIR}/bin/python ${ROOT}/api.py

Restart=always

RestartSec=5

# 首次 RAG/Milvus 初始化可能超过 systemd 默认启动窗口。
TimeoutStartSec=180s
# MCP 客户端、RAG 连接和持久化队列需要异步收尾；15 秒会误判为卡死并强制 SIGKILL。
TimeoutStopSec=90s
KillMode=control-group

Environment="PYTHONUNBUFFERED=1"

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${SYSTEMD_UNIT}"
    log "systemd 服务已安装并启动: systemctl status ${SYSTEMD_UNIT}"
  else
    log "（dry-run）将写入 ${UNIT_FILE} 并 enable --now"
  fi
else
  log "== 6/6 systemd 服务 =="
  log "未指定 --with-systemd，跳过服务安装；手动启动: ${VENV_DIR}/bin/python ${ROOT}/api.py"
fi

# ─────────────────────────── 完成 ───────────────────────────
log "部署流程结束。下一步："
log "  1) 编辑 ${ROOT}/.env 填入模型 API Key"
log "  2) 启动 Web 控制台: ${VENV_DIR}/bin/python ${ROOT}/api.py   →  http://<服务器IP>:${API_PORT}"
log "  3) 或 CLI 单次任务: ${VENV_DIR}/bin/python ${ROOT}/main.py -t <目标>"
log "详细说明见 docs/部署手册.md；本脚本日志: ${LOG_FILE}"

# 记录部署结果（成功才执行到此处；失败由上方 ERR trap 记录）
if [ "$DRY_RUN" -eq 0 ]; then
  {
    echo "=== $(date '+%Y-%m-%d %H:%M:%S') : install.sh 部署成功 ==="
    echo "系统: ${PRETTY_NAME:-$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2)}"
    echo "Python: ${PY_VER} | WebUI跳过: ${SKIP_WEBUI} | systemd: ${WITH_SYSTEMD}"
  } >> "${LOG_FILE}" 2>/dev/null || true
fi

exit 0
