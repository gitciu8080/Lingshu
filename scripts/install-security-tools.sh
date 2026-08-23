#!/usr/bin/env bash
# 灵枢攻防工具分层安装器。不会修改模型配置、数据库或启动服务。
set -euo pipefail

PROFILE="core"
DRY_RUN=0
CHECK_ONLY=0

usage() {
  printf '%s\n' \
    '用法: sudo ./scripts/install-security-tools.sh [--profile core|extended] [--dry-run|--check]' \
    '  core      高频侦察、Web、取证、逆向辅助工具（默认）' \
    '  extended  在 core 基础上增加 Ghidra、Bettercap、Wine 等重型/特权组件' \
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
  core|extended) ;;
  *) printf '不支持的 profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac

CORE_PACKAGES=(
  subfinder feroxbuster joomscan foremost ropper apktool steghide zbar-tools
  strace python3-pytesseract
)
EXTENDED_PACKAGES=(ghidra bettercap wine wine64 wine32)
PACKAGES=("${CORE_PACKAGES[@]}")
if [ "$PROFILE" = "extended" ]; then
  PACKAGES+=("${EXTENDED_PACKAGES[@]}")
fi

printf '灵枢工具安装配置: %s\n' "$PROFILE"
for package in "${PACKAGES[@]}"; do
  if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
    printf '  [已安装] %s\n' "$package"
  else
    printf '  [缺失]   %s\n' "$package"
  fi
done

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
printf '%s\n' '安装完成。请通过 GET /api/superadmin/tooling/status?refresh=true 刷新健康状态。'
