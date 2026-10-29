#!/usr/bin/env bash
# 灵枢攻防工具分层安装器。不会修改模型配置、数据库或启动服务。
set -euo pipefail

PROFILE="core"
DRY_RUN=0
CHECK_ONLY=0

usage() {
  printf '%s\n' \
    '用法: sudo ./scripts/install-security-tools.sh [--profile core|extended|ir] [--dry-run|--check]' \
    '  core      高频侦察、Web、取证（含 Volatility 2 Python 2）、OCR 语言包、逆向辅助工具与 OpenJDK JDK（默认）' \
    '  extended  在 core 基础上增加 Ghidra、Bettercap、Wine 等重型/特权组件' \
    '  ir        在 core 基础上增加应急响应取证组件（yara、plaso 日志时间线；chainsaw 需手动下载）' \
    '  --check   只检查包状态，不安装'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    --check) CHECK_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
  shift
done

case "$PROFILE" in
  core|extended|ir) ;;
  *) printf '不支持的 profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac

CORE_PACKAGES=(
  subfinder feroxbuster joomscan foremost ropper apktool steghide stegseek zbar-tools
  strace python2 default-jdk tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim tesseract-ocr-chi-tra
)
EXTENDED_PACKAGES=(ghidra bettercap wine wine64 wine32)
# 应急响应（IR）取证工具：YARA 规则扫描、plaso 日志时间线。
# chainsaw 为 GitHub 二进制发布，apt 无包——--check 提示手动安装。
IR_PACKAGES=(yara plaso-python3)
# 当前源可能缺失的可选工具：逐个容错安装，失败不阻断整体。
OPTIONAL_PACKAGES=(outguess)
PACKAGES=("${CORE_PACKAGES[@]}")
if [ "$PROFILE" = "extended" ]; then
  PACKAGES+=("${EXTENDED_PACKAGES[@]}")
fi
if [ "$PROFILE" = "ir" ] || [ "$PROFILE" = "extended" ]; then
  PACKAGES+=("${IR_PACKAGES[@]}")
fi
# chainsaw 无论何种 profile 都做存在性检查并提示（不自动下载）
if ! command -v chainsaw >/dev/null 2>&1; then
  printf '  [提示]   chainsaw 未安装（EVTX 狩猎）：从 https://github.com/WithSecureLabs/chainsaw/releases 下载二进制放入 PATH\n'
fi

printf '灵枢工具安装配置: %s\n' "$PROFILE"
for package in "${PACKAGES[@]}"; do
  if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
    printf '  [已安装] %s\n' "$package"
  else
    printf '  [缺失]   %s\n' "$package"
  fi
done

# Java 工具依赖 JDK 而不仅是 JRE：java 能运行程序，但 javac 缺失会导致
# APK/Java 分析与编译路径不完整。包管理器状态之外再做命令级验证。
for command in java javac; do
  if command -v "$command" >/dev/null 2>&1; then
    printf '  [可用]   %s (%s)\n' "$command" "$(command -v "$command")"
  else
    printf '  [缺失]   %s\n' "$command"
  fi
done

# 项目内置 Volatility 2.6 仍以 Python 2.7 运行。仅有 Python 3/Conda 环境
# 时内存取证工具会在真实任务中失败，故在 core 安装并单独报告。
if command -v python2 >/dev/null 2>&1; then
  printf '  [可用]   python2（Volatility 2）\n'
else
  printf '  [缺失]   python2（Volatility 2 无法运行）\n'
fi

if command -v tesseract >/dev/null 2>&1; then
  printf 'Tesseract 语言包检查:\n'
  available_languages="$(tesseract --list-langs 2>/dev/null || true)"
  for language in eng chi_sim chi_tra; do
    if printf '%s\n' "$available_languages" | grep -Fxq "$language"; then
      printf '  [可用]   %s\n' "$language"
    else
      printf '  [缺失]   %s\n' "$language"
    fi
  done
else
  printf '  [缺失]   tesseract（无法检查 OCR 语言包）\n'
fi

# requirements.txt 由项目运行解释器安装。优先允许部署人员显式指定，
# 其次自动识别项目 .venv 和常见 Conda 的 agentscope 环境，最后才退回
# 系统 python3；避免把“系统 Python 有包”误报成运行中的 AgentScope 环境有包。
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${LINGSHU_PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ] && [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
  PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
fi
if [ -z "$PYTHON_BIN" ]; then
  INSTALL_USER="${SUDO_USER:-$USER}"
  INSTALL_HOME="$(getent passwd "$INSTALL_USER" 2>/dev/null | cut -d: -f6 || true)"
  for candidate in \
    "${CONDA_PREFIX:-}/envs/agentscope/bin/python" \
    "${INSTALL_HOME:-}/miniconda3/envs/agentscope/bin/python" \
    "${INSTALL_HOME:-}/miniforge3/envs/agentscope/bin/python" \
    "${INSTALL_HOME:-}/anaconda3/envs/agentscope/bin/python"; do
    if [ -x "$candidate" ]; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi
if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3 || true)"
fi
if [ -n "$PYTHON_BIN" ] && [ -x "$PYTHON_BIN" ]; then
  printf 'Python 安全分析依赖检查（%s）:\n' "$PYTHON_BIN"
  for module in pwn capstone elftools pefile Crypto pytesseract; do
    if "$PYTHON_BIN" -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$module') else 1)"; then
      printf '  [可用]   %s\n' "$module"
    else
      printf '  [缺失]   %s（运行 %s -m pip install -r %s/requirements.txt）\n' "$module" "$PYTHON_BIN" "$PROJECT_ROOT"
    fi
  done
else
  printf '  [跳过]   未找到 Python；无法检查 requirements.txt 中的安全分析依赖\n'
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  exit 0
fi
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  printf '安装需要 root；可先使用 --check 或 --dry-run。\n' >&2
  exit 1
fi
if [ "$DRY_RUN" -eq 1 ]; then
  printf '[dry-run] apt-get update\n[dry-run] apt-get install -y'
  printf ' %q' "${PACKAGES[@]}"
  printf '\n'
  exit 0
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"
for package in "${OPTIONAL_PACKAGES[@]}"; do
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"; then
    printf '[可选] %s 在当前源不可用，已跳过\n' "$package"
  fi
done
printf '%s\n' '安装完成。请通过 Web“系统工具状态”或 GET /api/tooling/catalog?refresh=true 刷新健康状态。'
