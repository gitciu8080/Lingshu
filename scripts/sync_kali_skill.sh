#!/usr/bin/env bash
# 从 kali-full 镜像构建目录同步 kali-full-tools skill 到灵枢仓库。
#
# 用法:
#   ./scripts/sync_kali_skill.sh [镜像构建目录]
# 默认镜像构建目录: /home/gitciu/kali_Workspace/kali-full
#
# 镜像升级后（重打 Dockerfile 或更新 skills/kali-full-tools/SKILL.md）应
# 重新运行本脚本，避免仓库内的工具清单与镜像实际能力漂移。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_DIR="${1:-/home/gitciu/kali_Workspace/kali-full}"

SRC="${IMAGE_DIR}/skills/kali-full-tools"
DST="${REPO_ROOT}/Skills/kali-full-tools"

if [[ ! -d "${SRC}" ]]; then
    echo "错误: 源 skill 目录不存在: ${SRC}" >&2
    echo "请先确认镜像构建目录路径，或显式传入: $0 /path/to/kali-full" >&2
    exit 1
fi

mkdir -p "${DST}"
# 只同步 SKILL.md 与纯文本资源；排除隐藏文件与构建产物。
rsync -a --delete \
    --exclude=".git" \
    --exclude="*.pyc" \
    "${SRC}/" "${DST}/"

echo "已同步 ${SRC} -> ${DST}"
echo "请在提交中一起更新 docs 中关于 kali-full 工具能力的最新说明。"
