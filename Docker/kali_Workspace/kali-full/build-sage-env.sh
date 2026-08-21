#!/usr/bin/env bash
# 在宿主机预构建 SageMath conda 环境并打包为 conda-pack (供 Dockerfile COPY)
# 用法: ./build-sage-env.sh
# 前提: 宿主机已安装 Miniforge3 到 /opt/miniforge3
#   bash <(curl -fsSL https://gh-proxy.org/https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh) -b -p /opt/miniforge3
set -euo pipefail
cd "$(dirname "$0")"

CONDA=/opt/miniforge3/bin/conda

# conda 源: 清华镜像 conda-forge
$CONDA config --system --remove-key channels || true
$CONDA config --system --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge
$CONDA config --system --set channel_priority strict

# 创建/更新 sage 环境 (约 5GB, 视网络 30~100 分钟)
$CONDA create -y -n sage sage

# 安装 conda-pack 并打包 (自包含, 解压后改一下前缀路径即可运行)
$CONDA install -y -n base conda-pack
rm -f sage-env.tar.gz
$CONDA pack -n sage -o sage-env.tar.gz
echo "OK: $(du -h sage-env.tar.gz)"
echo "现在可以重新构建镜像: docker build -t kali-full:latest ."
