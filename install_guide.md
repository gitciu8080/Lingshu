# 灵枢（Lingshu）安装与环境部署指南

> 适用环境：Ubuntu 22.04 / 24.04 LTS，Python 3.12+，Docker CE  
> 最后更新：2026-08-20

---

## 目录

- [1. 系统基础依赖](#1-系统基础依赖)
- [2. Conda 环境与 Python 依赖](#2-conda-环境与-python-依赖)
- [3. GDB 动态调试（容器内置，无需安装）](#3-gdb-动态调试容器内置无需安装)
- [4. IDA MCP Docker 服务（逆向分析）](#4-ida-mcp-docker-服务逆向分析)
- [5. Docker 工作区（kali-full 镜像）](#5-docker-工作区kali-full-镜像)
- [6. AntSword MCP 服务](#6-antsword-mcp-服务)
- [7. Tesseract OCR](#7-tesseract-ocr)
- [8. SageMath（密码学计算）](#8-sagemath密码学计算)
- [9. 环境变量参考](#9-环境变量参考)
- [10. 安装验证清单](#10-安装验证清单)

---

## 1. 系统基础依赖

```bash
sudo apt-get update && sudo apt-get install -y \
    build-essential git curl wget vim less \
    docker.io docker-compose \
    gdb gdb-multiarch \
    tesseract-ocr tesseract-ocr-chi-sim tesseract-ocr-eng \
    poppler-utils
```

> **注意**：GDB 动态调试在 Docker 工作区容器内进行，宿主机无需安装 gdb。  
> 如果 Docker 由 snap 或独立方式安装，确保当前用户在 `docker` 组中：
> ```bash
> sudo usermod -aG docker $USER
> newgrp docker
> ```

---

## 2. Conda 环境与 Python 依赖

```bash
# 安装 Miniconda（如尚未安装）
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh

# 创建 agentscope 环境
conda create -n agentscope python=3.14 -y
conda activate agentscope

# 安装 Python 依赖
cd /home/$USER/Lingshu
pip install -r requirements.txt
```

---

## 3. GDB 动态调试（容器内置，无需安装）

Reserve（逆向分析 Agent）的动态调试通过 `gdb_debug` 工具完成：直接在会话
Docker 容器（kali-full 镜像）内以 batch 模式运行 GDB，**无需在宿主机安装
gdb 或 gdb-multi-mcp**。

### 3.1 前置条件

- Docker 工作区镜像已构建：`python scripts/build_workspace_image.py`
- 容器内自带 gdb 17.x（kali-full 镜像），无需额外配置

### 3.2 用法说明

Agent 调用 `gdb_debug(program=容器内绝对路径, commands=GDB 命令脚本)`：

```text
gdb_debug(
  program="/workspace/input/tmp/demo",
  commands="b *0x12a0\nrun < /workspace/input/payload.txt\ninfo registers\nx/s $rdi"
)
```

- 每次调用都是全新会话（batch 模式），多步探察需根据上次输出调整脚本重调；
- 待调试二进制必须在 `/workspace` 下，否则拒绝执行；
- 超时（默认 300s，上限 600s）会被强杀并在输出尾部标记；
- 完整输出同时落盘到工作区 `tmp/gdb-NNNN.out`。

---

## 4. IDA MCP Docker 服务（逆向分析）

IDA MCP 以 Docker 容器方式运行 IDA Pro headless 模式，提供 47 个逆向分析工具。

### 4.1 构建镜像

```bash
cd /home/$USER/ida

# 构建升级版镜像（含 HTTP 上传 API）
docker build -t ida-mcp-up:latest build/
```

### 4.2 启动服务

```bash
# idle 模式（等待 Agent 上传二进制）
/home/$USER/ida/run-ida-mcp.sh

# 或直接分析指定文件
/home/$USER/ida/run-ida-mcp.sh /path/to/binary
```

### 4.3 验证

```bash
# 检查服务状态
curl http://127.0.0.1:8745/status
# 期望返回：{"status":"idle","binary":null,...}

# 检查 MCP 端点
curl http://127.0.0.1:8745/sse
```

### 4.4 工作原理

```
Agent 调用 ida_open_binary(path)
  → POST /upload（二进制文件）
  → 服务器自动分析（阻塞，可能数分钟）
  → 返回元数据 JSON
  → Agent 动态获取完整 47 个 IDA MCP 工具
  → 调用 decompile / list_funcs / xrefs_to 等
```

---

## 5. Docker 工作区（kali-full 镜像）

灵枢在 Docker 容器中执行 `scoped_shell` 命令，容器基于 `kali-full` 镜像。

### 5.1 构建镜像

```bash
cd /home/$USER/kali_Workspace/kali-full

# 构建（首次需要下载大量包，耗时较长）
docker build -t kali-full:latest .

# 验证
docker images | grep kali-full
```

### 5.2 镜像内容

`kali-full` 基于 `kalilinux/kali-rolling`，预装：

- **渗透工具**：kali-linux-headless、crackmapexec、feroxbuster、subfinder
- **逆向分析**：ghidra、gdb、gdbserver、apktool
- **取证**：volatility3、steghide、zbar-tools
- **密码学**：python3-sympy、pycryptodome、SageMath（conda-pack → `/opt/sage`）
- **调试**：gdb + libc6-dbg + strace + ropper
- **兼容层**：wine（含 wine32 运行 32 位 Windows 程序）

### 5.3 容器配置

灵枢自动创建容器时使用以下配置：

- `NetworkMode: host`（与宿主机共享网络栈，nmap SYN 扫描需要）
- `CapAdd: [NET_RAW, NET_ADMIN]`（原始套接字能力）
- 挂载会话目录到 `/workspace`

---

## 6. AntSword MCP 服务

AntSword MCP 提供 WebShell 管理工具（37 个工具），以 SSE 方式运行。

### 6.1 启动

```bash
# AntSword MCP 通常以 Docker 容器或 systemd 服务常驻运行
# 默认监听 127.0.0.1:30080/sse

# 检查服务状态
curl http://127.0.0.1:30080/sse
```

### 6.2 验证

灵枢 Attack Agent 启动时会自动连接 AntSword MCP。连接失败不会阻断任务（降级运行）。

---

## 7. Tesseract OCR

用于从图片中提取文字（CTF 截图、扫描文档等）。

```bash
# 安装（已在步骤 1 中包含）
sudo apt-get install -y tesseract-ocr tesseract-ocr-chi-sim tesseract-ocr-eng

# 验证
tesseract --version
tesseract --list-langs
# 应包含：eng、chi_sim
```

> **Docker 模式下**：OCR 工具会在容器内执行 `tesseract`，需要确保 `kali-full` 镜像中也安装了 tesseract。  
> 如果容器内未安装，工具会返回 `[OCR 不可用]` 文本，不影响其他功能。

---

## 8. SageMath（密码学计算）

Attack Agent 使用 SageMath 处理 RSA/ECC/离散对数等密码学计算。

### 8.1 部署方式

SageMath 以 **conda-pack 自包含包** 的形式预装在 `kali-full` Docker 镜像中：

- 构建期由 `build-sage-env.sh` 在宿主机生成 `sage-env.tar.gz`（约 1.8 GB）
- Dockerfile 将其解压到容器内 `/opt/sage`，并创建 `sage` / `sage-py` 软链到 `/usr/local/bin/`
- 无需构建期网络（conda-forge 依赖已全部打包）

### 8.2 执行位置

`Tools/SageMath.py` 的 `execute_sagemath()` 将代码送入会话 Docker 工作区容器内执行
（镜像内 `/usr/local/bin/sage`），无需宿主机安装 SageMath 或 conda。

### 8.3 环境变量

```bash
LINGSHU_SAGE_TIMEOUT=120      # 执行超时（秒）
```

> SageMath 在会话 Docker 工作区容器内执行（镜像自带 sage），无需宿主机安装。

---

## 9. 环境变量参考

在 `.env` 文件或系统环境中配置：

```bash
# ── LLM Provider ──
DEEPSEEK_API_KEY=sk-xxx           # DeepSeek API Key
# ZHIPU_API_KEY=xxx               # 智谱 GLM API Key（可选）

# ── Docker 工作区 ──
LINGSHU_WORKSPACE_BASE_IMAGE=kali-full:latest

# ── MCP 服务地址 ──
LINGSHU_IDA_MCP_URL=http://127.0.0.1:8745
LINGSHU_ANTSWORD_MCP_URL=http://127.0.0.1:30080/sse

# ── 超时 ──
LINGSHU_COMMAND_TIMEOUT=300       # 命令执行超时（秒）

# ── Qwen（本地模型）──
# QWEN_TOOL_CALL_MODE=simple     # simple | standard
# QWEN_REPEAT_PENALTY=1.2        # 建议 ≤ 1.2
```

---

## 10. 安装验证清单

激活 conda 环境后运行以下检查：

```bash
conda activate agentscope
cd /home/$USER/Lingshu
```

| # | 检查项 | 命令 | 期望结果 |
|---|---|---|---|
| 1 | Python 环境 | `python3 --version` | 3.12+ |
| 2 | GDB 二进制 | `gdb --version` | GNU gdb 版本号 |
| 3 | gdb-multi-mcp | `gdb-multi-mcp --help` | 显示帮助信息 |
| 4 | IDA MCP 服务 | `curl -s http://127.0.0.1:8745/status` | `{"status":"idle",...}` |
| 5 | AntSword MCP | `curl -s http://127.0.0.1:30080/sse` | SSE 流响应 |
| 6 | Docker daemon | `docker info` | 正常输出 |
| 7 | kali-full 镜像 | `docker images \| grep kali-full` | 镜像存在 |
| 8 | Tesseract | `tesseract --version` | 版本号 |
| 9 | Python 依赖 | `python3 -c "import agentscope; print(agentscope.__version__)"` | 2.0.6+ |
| 10 | 完整 Agent 创建 | 见下方脚本 | 所有 Agent 创建成功 |

### 完整验证脚本

```bash
conda run -n agentscope python3 -c "
import asyncio

async def verify():
    from agent.Reserve import create_reverse_agent, _find_gdb_mcp_executable
    from agent.Analysis import create_analysis_agent
    from LLM.model import create_model
    from config import RuntimeConfig

    runtime = RuntimeConfig.from_env()
    model = create_model(provider='deepseek', Ver='Min', temperature=None, config=runtime)

    # GDB 探测
    gdb_path = _find_gdb_mcp_executable()
    print(f'gdb-multi-mcp: {gdb_path or \"未找到\"}')

    # Agent 创建
    analysis = create_analysis_agent(model)
    agent = await create_reverse_agent(model, analysis, '127.0.0.1:80', '/tmp', 60)
    available = await agent.toolkit._get_available_tools(None)
    gdb_tools = [n for n in available if 'GDB' in n]
    ida_tools = [n for n in available if 'IDA' in n]
    print(f'Agent 工具: {len(available)} 个 (GDB: {len(gdb_tools)}, IDA: {len(ida_tools)})')
    print('✅ 验证通过' if len(gdb_tools) > 10 else '⚠️ GDB 工具不足')

asyncio.run(verify())
"
```

---

## 故障排查

### GDB MCP 连接失败

```bash
# 1. 确认可执行文件存在
conda run -n agentscope which gdb-multi-mcp

# 2. 确认 GDB 底层可用
conda run -n agentscope gdb --version

# 3. 手动测试 stdio 连接
echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | gdb-multi-mcp --transport stdio
```

### IDA MCP 无法连接

```bash
# 检查容器是否运行
docker ps | grep ida-mcp

# 重启容器
docker rm -f ida-mcp
/home/$USER/ida/run-ida-mcp.sh

# 检查端口
ss -tlnp | grep 8745
```

### Docker 工作区创建失败

```bash
# 确认 docker 权限
groups | grep docker

# 确认镜像存在
docker images | grep kali-full

# 手动测试容器创建
docker run --rm -it kali-full:latest echo "hello"
```
