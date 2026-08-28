#!/usr/bin/env bash
# 灵枢基础运行环境安装器：系统依赖 + Miniconda + AgentScope Conda 环境。
# 安全工具由 install-security-tools.sh 单独管理，便于最小化部署。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INSTALL_USER="${SUDO_USER:-$USER}"
INSTALL_HOME="$(getent passwd "$INSTALL_USER" 2>/dev/null | cut -d: -f6 || true)"
INSTALL_HOME="${INSTALL_HOME:-$HOME}"
CONDA_PREFIX="${LINGSHU_CONDA_PREFIX:-$INSTALL_HOME/miniconda3}"
ENV_NAME="${LINGSHU_CONDA_ENV:-agentscope}"
PYTHON_VERSION="${LINGSHU_CONDA_PYTHON_VERSION:-3.14}"
# uv 同时提供 uv 与 uvx；固定版本保证 GDB MCP 的安装过程可复现。
UV_VERSION="${LINGSHU_UV_VERSION:-0.12.1}"
UV_BIN_DIR="${LINGSHU_UV_BIN_DIR:-$INSTALL_HOME/.local/bin}"
DRY_RUN=0
CHECK_ONLY=0

usage() {
  printf '%s\n' \
    '用法: sudo ./scripts/install-system-environment.sh [--check|--dry-run] [--conda-prefix PATH] [--env-name NAME] [--python-version VERSION]' \
    '安装系统运行依赖、Miniconda、AgentScope Conda 环境和 uv/uvx；不安装攻防工具。' \
    '可通过 LINGSHU_CONDA_PREFIX / LINGSHU_CONDA_ENV / LINGSHU_CONDA_PYTHON_VERSION / LINGSHU_UV_VERSION 覆盖默认值。'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --conda-prefix) CONDA_PREFIX="${2:?--conda-prefix 需要路径}"; shift ;;
    --env-name) ENV_NAME="${2:?--env-name 需要名称}"; shift ;;
    --python-version) PYTHON_VERSION="${2:?--python-version 需要版本}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
  shift
done

# Kali/Debian 正处于 time_t 64 位迁移期：新系统是 libglib2.0-0t64，
# 较旧发行版仍是 libglib2.0-0。选择源中实际存在的包名，避免 apt 因旧名
# 无 Candidate 而中断整个一键安装。
if apt-cache show libglib2.0-0t64 >/dev/null 2>&1; then
  GLIB_RUNTIME_PACKAGE="libglib2.0-0t64"
else
  GLIB_RUNTIME_PACKAGE="libglib2.0-0"
fi

# 同一套 Electron 运行库在新 Kali 中也发生了 t64 改名；从源中选择实际
# 存在的包，兼容当前 Kali 与较旧的 Debian/Ubuntu。
pick_apt_package() {
  local candidate
  for candidate in "$@"; do
    if apt-cache show "$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  printf '%s' "$1"
}
GTK_RUNTIME_PACKAGE="$(pick_apt_package libgtk-3-0t64 libgtk-3-0)"
ALSA_RUNTIME_PACKAGE="$(pick_apt_package libasound2t64 libasound2)"
ATK_BRIDGE_RUNTIME_PACKAGE="$(pick_apt_package libatk-bridge2.0-0t64 libatk-bridge2.0-0)"
CUPS_RUNTIME_PACKAGE="$(pick_apt_package libcups2t64 libcups2)"

SYSTEM_PACKAGES=(
  ca-certificates curl git build-essential
  python3 python3-venv python3-pip
  nodejs xvfb gdb poppler-utils
  # WeasyPrint 的 Pango/Cairo 后端、字体发现与中文通用后备字体。
  # 项目内置微软雅黑字体仍是报告默认字体；Noto CJK 用于客户机替换字体时兜底。
  fontconfig fonts-noto-cjk
  libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 "$GLIB_RUNTIME_PACKAGE" libffi8
  shared-mime-info
  # 项目内置 AntSword 是 Electron 应用：无桌面环境会由 xvfb-run 托管，但
  # 以下动态库不会被 Electron 二进制打包，干净 Kali 必须显式安装。
  libnss3 "$GTK_RUNTIME_PACKAGE" "$ALSA_RUNTIME_PACKAGE" libxss1 "$ATK_BRIDGE_RUNTIME_PACKAGE"
  "$CUPS_RUNTIME_PACKAGE" libgbm1 libxcomposite1 libxdamage1 libxrandr2 libxkbcommon0
)

as_install_user() {
  if [ "$(id -u)" -eq 0 ] && [ "$INSTALL_USER" != "root" ]; then
    runuser -u "$INSTALL_USER" -- env HOME="$INSTALL_HOME" "$@"
  else
    "$@"
  fi
}

package_state() {
  if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; then
    printf '  [已安装] %s\n' "$1"
  else
    printf '  [缺失]   %s\n' "$1"
  fi
}

printf '灵枢系统环境：用户=%s，Conda=%s，环境=%s（Python %s）\n' \
  "$INSTALL_USER" "$CONDA_PREFIX" "$ENV_NAME" "$PYTHON_VERSION"
for package in "${SYSTEM_PACKAGES[@]}"; do package_state "$package"; done
for command in node npm uv uvx pdftoppm; do
  if command -v "$command" >/dev/null 2>&1; then
    printf '  [可用]   %s (%s)\n' "$command" "$(command -v "$command")"
  else
    printf '  [缺失]   %s\n' "$command"
  fi
done
if [ -x "$CONDA_PREFIX/bin/conda" ]; then
  printf '  [可用]   Miniconda\n'
else
  printf '  [缺失]   Miniconda\n'
fi
if [ -x "$UV_BIN_DIR/uv" ] && [ -x "$UV_BIN_DIR/uvx" ]; then
  printf '  [可用]   uv/uvx（%s）\n' "$UV_BIN_DIR"
else
  printf '  [缺失]   uv/uvx（GDB Multi MCP 安装器）\n'
fi
if [ -x "$CONDA_PREFIX/envs/$ENV_NAME/bin/python" ]; then
  printf '  [可用]   AgentScope Conda 环境\n'
  PYTHON_BIN="$CONDA_PREFIX/envs/$ENV_NAME/bin/python"
  "$PYTHON_BIN" --version
  printf '  [PDF]    报告运行环境检测\n'
  (
    cd "$PROJECT_ROOT"
    PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON_BIN" - <<'PY'
from Tools.tool_catalog import ToolCatalog

wanted = {
    "pdf-weasyprint-runtime",
    "pdf-reportlab-runtime",
    "pdf-chinese-fonts",
    "pdf-report-generation",
    "pdf-mermaid-renderer",
    "taskbook-pdf-ocr",
    "antsword-electron-runtime",
    "uv-uvx-runtime",
}
for item in ToolCatalog().snapshot(include_version=True):
    if item["id"] in wanted:
        detail = item["version"] or item["error"] or "已就绪"
        print(f"    [{item['status']}] {item['id']}: {detail}")
PY
  ) || printf '    [degraded] PDF 报告自检无法完成，请检查 Python 依赖与系统图形库。\n'
else
  printf '  [缺失]   AgentScope Conda 环境\n'
fi

if [ "$CHECK_ONLY" -eq 1 ]; then exit 0; fi
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  printf '安装需要 root；可先使用 --check 或 --dry-run。\n' >&2
  exit 1
fi
if [ "$DRY_RUN" -eq 1 ]; then
  printf '[dry-run] apt-get update\n[dry-run] apt-get install -y'
  printf ' %q' "${SYSTEM_PACKAGES[@]}"
  printf '\n[dry-run] Miniconda 安装到 %s；创建环境 %s (Python %s)\n' "$CONDA_PREFIX" "$ENV_NAME" "$PYTHON_VERSION"
  printf '[dry-run] 安装 uv %s 到 %s（提供 uv/uvx）\n' "$UV_VERSION" "$UV_BIN_DIR"
  exit 0
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y "${SYSTEM_PACKAGES[@]}"

if [ ! -x "$CONDA_PREFIX/bin/conda" ]; then
  case "$(uname -m)" in
    x86_64|amd64) MINICONDA_ARCH="x86_64" ;;
    aarch64|arm64) MINICONDA_ARCH="aarch64" ;;
    *) printf '不支持自动安装 Miniconda 的 CPU 架构: %s\n' "$(uname -m)" >&2; exit 1 ;;
  esac
  installer="$(mktemp /tmp/lingshu-miniconda.XXXXXX.sh)"
  trap 'rm -f "$installer"' EXIT
  curl --fail --location --retry 3 \
    "https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-${MINICONDA_ARCH}.sh" \
    --output "$installer"
  chown "$INSTALL_USER":"$(id -gn "$INSTALL_USER")" "$installer" 2>/dev/null || true
  as_install_user bash "$installer" -b -p "$CONDA_PREFIX"
fi

CONDA_BIN="$CONDA_PREFIX/bin/conda"

# Anaconda 新版渠道在首次使用前要求每个实际运行用户确认 ToS。部署脚本
# 后续通过 as_install_user 创建环境，因此也必须以同一用户写入确认状态；
# 否则会在 `conda create` 阶段以 CondaToSNonInteractiveError 中断。旧版
# Conda 未提供 `tos` 子命令时保持兼容并跳过。
accept_conda_tos() {
  if ! as_install_user "$CONDA_BIN" tos --help >/dev/null 2>&1; then
    return 0
  fi
  printf '接受 Anaconda 默认渠道 ToS（用户=%s）\n' "$INSTALL_USER"
  as_install_user "$CONDA_BIN" tos accept --override-channels \
    --channel https://repo.anaconda.com/pkgs/main
  as_install_user "$CONDA_BIN" tos accept --override-channels \
    --channel https://repo.anaconda.com/pkgs/r
}

accept_conda_tos

if [ ! -x "$CONDA_PREFIX/envs/$ENV_NAME/bin/python" ]; then
  as_install_user "$CONDA_BIN" create --yes --name "$ENV_NAME" "python=$PYTHON_VERSION"
fi

if [ ! -x "$UV_BIN_DIR/uv" ] || [ ! -x "$UV_BIN_DIR/uvx" ]; then
  uv_installer="$(mktemp /tmp/lingshu-uv.XXXXXX.sh)"
  trap 'rm -f "${installer:-}" "${uv_installer:-}"' EXIT
  curl --fail --location --retry 3 \
    "https://astral.sh/uv/${UV_VERSION}/install.sh" \
    --output "$uv_installer"
  chown "$INSTALL_USER":"$(id -gn "$INSTALL_USER")" "$uv_installer" 2>/dev/null || true
  as_install_user env UV_UNMANAGED_INSTALL="$UV_BIN_DIR" sh "$uv_installer"
fi
printf '系统环境已就绪：%s（uv=%s）\n' "$CONDA_PREFIX/envs/$ENV_NAME/bin/python" "$UV_BIN_DIR/uv"
