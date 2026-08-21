#!/usr/bin/env bash
# ============================================================================
# build_workspace_image.sh — 预热 agentscope DockerWorkspace 派生镜像
# ============================================================================
#
# 用途：
#   agentscope 的 DockerWorkspace 在首次初始化时会自动构建一个派生镜像
#  （基于 kali-full:latest 等基础镜像，安装 uv、gateway venv、agentscope）。
#   该构建使用默认网络驱动，在网络受限（仅 host 网络可达外网）的机器上会
#   失败。本脚本用 --network host 预先构建相同内容哈希的镜像，之后 agentscope
#   会命中缓存直接使用，不再触发网络构建。
#
# 原理：
#   镜像 tag 由 Dockerfile 内容 + COPY 进去的所有文件的内容哈希决定
#  （agentscope-workspace:<12hex>），与 agentscope 运行时的计算方式完全一致。
#
# 用法：
#   ./scripts/build_workspace_image.sh           # 使用默认基础镜像
#   ./scripts/build_workspace_image.sh ubuntu:22.04  # 指定基础镜像
#   ./scripts/build_workspace_image.sh --dry-run  # 仅预览，不构建
#   ./scripts/build_workspace_image.sh --show     # 构建后显示 Dockerfile
#
# 环境变量：
#   LINGSHU_WORKSPACE_BASE_IMAGE  基础镜像名（默认 kali-full:latest）
#   LINGSHU_WORKSPACE_DOCKER_EXTRA_PIP  额外 pip 包，逗号分隔
# ============================================================================

set -euo pipefail

# ── 参数解析 ────────────────────────────────────────────────────────
DRY_RUN=false
SHOW_DOCKERFILE=false
BASE_IMAGE=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --show)    SHOW_DOCKERFILE=true ;;
        --help|-h)
            sed -n '/^# 用途/,/^$/p' "$0" | sed 's/^# //; s/^#$//'
            exit 0
            ;;
        *)
            if [ -z "$BASE_IMAGE" ]; then
                BASE_IMAGE="$arg"
            else
                echo "错误: 未知参数 $arg" >&2
                exit 1
            fi
            ;;
    esac
done

# ── 加载 .env（可选）────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
fi

# ── 确定基础镜像 ─────────────────────────────────────────────────────
: "${LINGSHU_WORKSPACE_BASE_IMAGE:=kali-full:latest}"
BASE_IMAGE="${BASE_IMAGE:-$LINGSHU_WORKSPACE_BASE_IMAGE}"

# ── 确定 Python 解释器（含 agentscope）──────────────────────────────
if [ -x /home/gitciu/miniconda3/envs/agentscope/bin/python ]; then
    CONDA_PY=/home/gitciu/miniconda3/envs/agentscope/bin/python
elif command -v conda >/dev/null 2>&1; then
    CONDA_PY="$(command -v conda) run -n agentscope python"
elif command -v python3 >/dev/null 2>&1; then
    CONDA_PY=python3
else
    echo "错误: 找不到 python（需要已安装 agentscope 的环境）" >&2
    exit 1
fi

# ── 解析 extra_pip ──────────────────────────────────────────────────
EXTRA_PIP="${LINGSHU_WORKSPACE_DOCKER_EXTRA_PIP:-}"
EXTRA_PIP_JSON="[]"
if [ -n "$EXTRA_PIP" ]; then
    # 把逗号分隔转成 Python list 字符串
    EXTRA_PIP_JSON="["
    first=true
    IFS=',' read -ra pkgs <<< "$EXTRA_PIP"
    for pkg in "${pkgs[@]}"; do
        pkg="$(echo "$pkg" | xargs)"  # trim
        [ -z "$pkg" ] && continue
        if [ "$first" = true ]; then first=false; else EXTRA_PIP_JSON+=", "; fi
        EXTRA_PIP_JSON+="\"$pkg\""
    done
    EXTRA_PIP_JSON+="]"
fi

# ── 生成构建上下文 ───────────────────────────────────────────────────
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "[INFO] 生成构建上下文 (base=${BASE_IMAGE}) ..."
echo "[INFO] 使用 Python: $CONDA_PY"
if [ -n "$EXTRA_PIP" ]; then
    echo "[INFO] 额外 pip 包: $EXTRA_PIP"
fi

"$CONDA_PY" - "$BASE_IMAGE" "$BUILD_DIR" "$EXTRA_PIP_JSON" <<'PYEOF'
import json
import sys
from pathlib import Path
from agentscope.workspace._docker._make_dockerfile import prepare_build_context

base_image = sys.argv[1]
outdir = Path(sys.argv[2])
extra_pip = json.loads(sys.argv[3]) if len(sys.argv) > 3 else []

outdir.mkdir(parents=True, exist_ok=True)
ctx, tag, files = prepare_build_context(
    base_image=base_image,
    extra_pip=extra_pip,
)
(outdir / "Dockerfile").write_text((ctx / "Dockerfile").read_text())
(outdir / "requirements.txt").write_bytes(files["requirements.txt"])
(outdir / "_mcp_gateway_app.py").write_bytes(files["_mcp_gateway_app.py"])
(outdir / "_glob_helper.py").write_bytes(files["_glob_helper.py"])
Path(outdir / "TAG").write_text(tag)
PYEOF

TAG="$(cat "$BUILD_DIR/TAG")"

echo "[INFO] 派生镜像 tag: ${TAG}"

# ── dry-run 模式 ────────────────────────────────────────────────────
if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "========== DRY RUN =========="
    echo "基础镜像:         ${BASE_IMAGE}"
    echo "镜像 tag:         ${TAG}"
    if [ -n "$EXTRA_PIP" ]; then
        echo "额外 pip:         ${EXTRA_PIP}"
    fi
    echo "构建上下文:       ${BUILD_DIR}"
    echo "Dockerfile:"
    echo "------------------------------"
    cat "$BUILD_DIR/Dockerfile"
    echo "------------------------------"
    echo "命令: docker build --network host -t ${TAG} -f ${BUILD_DIR}/Dockerfile ${BUILD_DIR}"
    echo "=============================="
    exit 0
fi

# ── 检查是否已存在 ───────────────────────────────────────────────────
if sg docker -c "docker image inspect ${TAG}" >/dev/null 2>&1; then
    echo "[INFO] 镜像已存在，跳过构建（缓存命中）"
    if [ "$SHOW_DOCKERFILE" = true ]; then
        echo ""
        echo "========== Dockerfile =========="
        cat "$BUILD_DIR/Dockerfile"
        echo "================================"
    fi
    exit 0
fi

# ── 构建镜像 ─────────────────────────────────────────────────────────
echo "[INFO] 开始构建（--network host），需数分钟 ..."
sg docker -c "docker build --network host -t ${TAG} -f ${BUILD_DIR}/Dockerfile ${BUILD_DIR}"

echo ""
echo "[OK] 构建完成: ${TAG}"
echo "    agentscope 运行时将命中此缓存，不再重复构建。"

if [ "$SHOW_DOCKERFILE" = true ]; then
    echo ""
    echo "========== Dockerfile =========="
    cat "$BUILD_DIR/Dockerfile"
    echo "================================"
fi