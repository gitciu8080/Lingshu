# 灵枢（Lingshu）

灵枢是一个基于 **AgentScope 2.0.6** 的多专家、授权安全测试系统。它覆盖 CTF 解题、应急响应、附件取证、代码与二进制逆向，以及在明确授权范围内的渗透测试。

> 仅可用于竞赛靶场、本地实验环境或已获得书面授权的目标。系统保留范围校验和人工审批；不要为真实资产关闭这些控制。

## 当前工作流

```text
用户目标 / 上传附件
        │
        ├─ 目标规范化、附件安全解压、初始分类
        │
        ├─ ArtifactTriage（文件）或 NetworkRecon（网络）首轮证据
        │
        ├─ Brain：登记 4～8 项结构化计划
        │
        └─ Orchestrator：唯一调度者和状态变更者
              ├─ dispatch_recon        聚焦补侦 / 本地附件分析
              ├─ dispatch_reverse      IDA / GDB / 静态逆向
              ├─ request_scope_expansion  新网络目标范围审批
              ├─ request_exploitation_approval  利用前人工审批
              ├─ dispatch_attack       攻击验证或 CTF 利用
              └─ Summary               Markdown、PDF、JSONL 导出
```

核心原则：**只有 Orchestrator 能推进任务状态；其他专家只提交证据和结果。**

### 任务模式和授权

| 模式 | 典型输入 | 网络范围规则 |
|---|---|---|
| `ctf` | 任务目标含 `CTF` / `NSSCTF` / `challenge` | 题目声明目标作为初始范围；不弹出范围扩展审批 |
| `incident_response` | 应急响应、取证、日志/内存镜像 | 本地分析优先；按任务声明执行 |
| `authorized_pentest` | IP/域名目标或授权渗透测试 | 新发现网络目标必须走范围审批 |
| `hybrid_taskbook` | 任务书/附件 + 网络目标 | 附件分析先行，网络目标按范围审批控制 |

CTF 模式不需要 `request_scope_expansion`，但进入实际利用阶段仍会触发攻击动作审批。所有网络命令必须显式包含当前授权目标，破坏性本机命令会被拦截。

## 功能概览

- Web 多会话控制台：FastAPI + SSE + React；支持断线恢复、历史分页、审批和报告下载。
- CLI 单任务入口：IP、域名、文件、压缩包或目录均可作为目标。
- 文件与网络双目标：上传附件后仍可输入 IP/主机名；附件用于本地分析，IP 用于网络授权范围。
- 专家路由：Iris（附件）、Ethan（网络）、Sophia（Brain）、Alex（Orchestrator）、Attack、Ryan（逆向）、Analysis、Summary。
- 任务权威状态：`.TaskMemory/sessions/<session_id>.json` 采用原子写入。
- Web 会话投影：SQLite 保存会话索引、消息、流快照、审批和报告状态；JSONL 是可下载的完整会话导出格式。
- 工具状态面板：显示普通系统工具以及 IDA Lib MCP、GDB Multi MCP、AntSword MCP 的可用/缺失/降级和错误原因。

## 环境要求

- Kali Linux、Debian 或 Ubuntu。
- 项目当前开发环境为 Miniconda 的 `agentscope` 环境；一键部署默认创建 Python **3.14** 环境，可按客户环境覆盖。
- Node.js 20+ 与 pnpm 10.14+（仅重新构建前端时需要）。
- 一个已启用的 LLM Provider（推荐通过 Web 超级管理员页面配置）。
- 可选：IDA Pro + 合法许可证、`idalib-mcp`、GDB、`gdb-multi-mcp`、AntSword；OCR 需要 Tesseract 及 `eng`、`chi_sim`、`chi_tra` 语言包。

> `requirements.txt` 固定 `agentscope==2.0.6`。请始终使用同一个 Python 环境启动服务和安装依赖。

## 快速启动（已有 Miniconda）

以下示例使用当前项目的 Conda 环境路径；客户机可替换为自己的环境路径。

```bash
cd /home/kali/agentscope/lingshu_agent_aicreate/Lingshu

# 首次部署：从模板创建本地配置，绝不提交 .env
cp .env.example .env
chmod 600 .env

# 使用指定 AgentScope 环境安装依赖
/home/kali/miniconda3/envs/agentscope/bin/python -m pip install -r requirements.txt

# 构建 React 前端（仓库已有 dist 时可跳过）
cd webui
pnpm install --frozen-lockfile
pnpm build
cd ..

# 启动 Web 服务
/home/kali/miniconda3/envs/agentscope/bin/python api.py
```

默认监听 `0.0.0.0:8080`。浏览器访问：

```text
http://<服务器地址>:8080/
```

开发时也可以使用：

```bash
/home/kali/miniconda3/envs/agentscope/bin/python -m uvicorn api:app --host 0.0.0.0 --port 8080
```

生产环境建议用反向代理提供 HTTPS，并让 Uvicorn 仅监听 `127.0.0.1:8080`。SQLite 与任务状态采用单进程协调，不建议启用多个 Uvicorn worker。

## 一键安装

对于全新 Kali/Debian/Ubuntu，可使用项目脚本：

```bash
sudo ./scripts/install.sh

# 安装并启用 systemd 服务
sudo ./scripts/install.sh --with-systemd

# 仅安装基础系统、Miniconda 和 agentscope Conda 环境
sudo ./scripts/install-system-environment.sh

# 仅安装常用安全分析工具、OCR 语言包和 JDK
sudo ./scripts/install-security-tools.sh --profile core

# 查看工具是否已安装，不修改系统
sudo ./scripts/install-security-tools.sh --check
```

`install.sh` 会顺序调用基础环境与安全工具安装器，并统一在 Miniconda 的 `agentscope` 环境安装 `requirements.txt`；不会在系统 Python 或 `.venv` 中混装依赖。它还会安装 PDF 报告的 WeasyPrint 图形库、中文字体后备和 Mermaid SVG 渲染依赖。可通过 `--skip-system-environment`、`--skip-security-tools` 或 `--security-profile extended` 控制范围。

## 配置 `.env`

`.env.example` 是完整模板。以下是一个最小、安全的启动配置示例；请替换所有示例密钥和密码。

```dotenv
# 至少启用一个模型 Provider。也可启动后进入 /superadmin 在界面中保存模型配置。
DEEPSEEK_API_KEY=sk-替换为真实密钥
DEEPSEEK_BASE_URL=https://api.deepseek.com

# 必须设置为稳定的随机值；未设置时会在每次进程启动生成临时值，旧登录态会失效。
JWT_SECRET=替换为至少32字节的随机字符串
JWT_EXPIRE_MINUTES=10080

# 首次初始化时创建；账户已存在时修改这里不会重置其密码。
LINGSHU_SUPERADMIN_USERNAME=superadmin
LINGSHU_SUPERADMIN_PASSWORD=替换为高强度且仅管理员持有的密码

# 不开放公开注册时必须留空；需要开放时改为随机邀请码。
LINGSHU_REGISTRATION_INVITE_CODE=

# 可选：部署机器上的工具/MCP 路径。
LINGSHU_IDA_DIR=/opt/ida-pro
LINGSHU_IDALIB_MCP_COMMAND=/home/lingshu/.local/bin/idalib-mcp
LINGSHU_GDB_MCP_COMMAND=/home/lingshu/.local/bin/gdb-multi-mcp
LINGSHU_UVX_COMMAND=/home/lingshu/.local/bin/uvx
LINGSHU_ANTSWORD_EXECUTABLE=/opt/lingshu/Tools/AntSword-Loader-v4.0.3-linux-x64/AntSword

# 上传与工作区限制（可按服务器磁盘空间调整）。
LINGSHU_UPLOAD_MAX_FILE_BYTES=104857600
LINGSHU_UPLOAD_MAX_BATCH_BYTES=314572800
LINGSHU_MIN_FREE_DISK_BYTES=10737418240
```

### 常用配置项

| 变量 | 说明 |
|---|---|
| `DEEPSEEK_*`、`ZHIPU_*`、`QWEN_*` | 模型 Provider 的回退配置；Web 超级管理员配置优先。 |
| `JWT_SECRET` | JWT 签名密钥；生产环境必须显式配置并保密。 |
| `LINGSHU_SUPERADMIN_*` | 首次初始化时创建超级管理员。 |
| `LINGSHU_REGISTRATION_INVITE_CODE` | 公开注册邀请码；留空即关闭公开注册。 |
| `LINGSHU_IDA_DIR`、`LINGSHU_IDALIB_MCP_COMMAND` | IDA Pro 和 IDA Lib MCP 的路径。 |
| `LINGSHU_GDB_MCP_COMMAND`、`LINGSHU_UVX_COMMAND` | GDB Multi MCP 或其 `uvx` 离线回退启动器。 |
| `LINGSHU_ANTSWORD_EXECUTABLE` | AntSword Electron 启动器路径；API 会按配置托管其 SSE MCP。 |
| `LINGSHU_COMMAND_TIMEOUT` | 单条工具命令的默认超时秒数。 |
| `LINGSHU_UPLOAD_MAX_FILE_BYTES` / `LINGSHU_UPLOAD_MAX_BATCH_BYTES` | 单文件/单批附件上传上限。 |
| `LINGSHU_WORKSPACE_*`、`LINGSHU_UPLOAD_RETENTION_SECONDS` | 工作区、上传附件和回收站生命周期。 |

`LINGSHU_USER` / `LINGSHU_PASS` **不是 Web 控制台账户**。它们仅用于需要时向 NSSCTF/SLAB 等外部靶场提交结果；不需要外部平台集成时可留空或不使用。

## 数据库、默认账户与首次登录

系统使用 SQLite，主要数据库文件为：

```text
data/users.db
```

SQLite 是本地文件数据库，**没有数据库服务器用户名和密码**。下表中的账户是 Web 控制台的应用账户，保存在 `users` 表中。

| 账户类型 | 默认用户名 | 默认密码 | 权限与处理方式 |
|---|---|---|---|
| 内置管理员 | `admin` | `admin123` | 角色为 `admin`，仅用于首次本地初始化；不能进入 `/superadmin`。首次部署后应立即重置或删除。 |
| 超级管理员 | `superadmin` | 取自 `LINGSHU_SUPERADMIN_PASSWORD` | 角色为 `superadmin`，可管理用户、模型和运行状态。只有环境变量密码非空时才会首次创建。 |
| 普通用户 | 自行注册 | 自行设置 | 仅当 `LINGSHU_REGISTRATION_INVITE_CODE` 非空且输入匹配时可注册。 |

重要规则：

1. `admin/admin123` 是代码内置的开发初始账户，绝不可用于生产或公网部署。
2. `.env.example` 中的 `LINGSHU_SUPERADMIN_PASSWORD=change-this-to-a-long-random-password` 只是占位样例。首次启动前必须替换。
3. 超级管理员账户一旦创建，之后改 `.env` 中的密码**不会覆盖数据库内密码**；请通过 `/superadmin` 的“重置密码”操作修改。
4. 现有数据库不会被 `.env.example` 或数据库示例文件自动覆盖。迁移/部署前请备份。

首次登录建议：

```text
1. 使用 superadmin 与 .env 中首次设置的密码登录 /superadmin。
2. 重置或删除内置 admin 账户。
3. 在模型管理页面新增/启用至少一个 LLM Provider。
4. 关闭公开注册，或配置不可猜测的邀请码。
```

## 数据目录与备份

| 路径 | 用途 | 是否应备份 |
|---|---|---|
| `data/users.db` | 用户、会话索引、消息、审批、流快照 | 是 |
| `.TaskMemory/sessions/` | 每个任务的权威运行状态 JSON | 是 |
| `.LongMemory/` | 长期记忆 | 建议 |
| `.Reports/` | Markdown/PDF 报告 | 建议 |
| `WorkDir/` | 上传、解压、分析工件与临时工作区 | 按合规与保留策略决定 |
| `.env` | 密钥和部署配置 | 是，且必须加密保管 |

升级或排障前，至少备份 `data/users.db`、`.TaskMemory/`、`.LongMemory/`、`.Reports/` 和 `.env`。不要使用 `.example` 数据库覆盖现有生产数据库或会话目录。

## Web 控制台使用

### 新建任务

1. 点击“新建测试任务”。
2. 输入网络授权目标，或上传附件；两者可以同时填写。
3. 附件 + IP 的场景中：
   - 上传内容是本地分析对象；
   - IP/主机名是网络授权范围；
   - 例如 PWN 题、应急任务书、PCAP + 靶机地址。
4. 在“任务目标”中明确说明任务类型，例如 `CTF PWN`、`应急响应` 或 `授权渗透测试`。
5. 在进入利用阶段时，按弹窗选择“批准”“补充侦察”或“拒绝”。

顶部扳手图标打开“系统工具状态”，其中 `MCP` 分类会显示 IDA Lib、GDB Multi 和 AntSword MCP 的健康情况；系统环境还会显示 PDF 主/回退引擎、中文字体、Mermaid 图表渲染和端到端 PDF 自检。缺失或降级时先处理面板中的错误，再运行依赖它的专家任务。

### 报告与历史

- 会话结束后可下载 Markdown、PDF 和完整原始 JSONL。
- 页面刷新或 SSE 重连时，前端会从 SQLite 消息和流快照恢复会话。
- 历史消息可继续加载；任务 JSON 是恢复和审计的权威来源。

## CLI 用法

```bash
# 网络目标
/home/kali/miniconda3/envs/agentscope/bin/python main.py \
  -t 127.0.0.1:8080 -g "授权安全测试：仅做被动服务识别"

# 本地 CTF 附件
/home/kali/miniconda3/envs/agentscope/bin/python main.py \
  -t challenge.zip -g "CTF PWN：分析附件并恢复 Flag"

# 指定 Provider 和思考级别
/home/kali/miniconda3/envs/agentscope/bin/python main.py \
  -t evidence.pcapng -g "应急响应：分析流量证据" -p deepseek -m Min
```

参数：

| 参数 | 说明 |
|---|---|
| `-t` / `--target` | 必填；IP、IP:端口、主机名、文件、压缩包或目录。 |
| `-g` / `--goal` | 任务目标描述，默认“获取 Flag”。 |
| `-p` / `--provider` | `deepseek`、`qwen`、`zhipu` 或 Web 管理中注册的 Provider。 |
| `-m` / `--model` | `Low`、`Min`、`Max`；Zhipu 未指定时默认 `Max`。 |
| `--qwen-tool-mode` | `simple` 或 `standard`。 |

## 工具与 MCP 配置

普通系统工具由 `config/tool_catalog.json` 声明，并在运行时检查可执行文件。可通过：

```bash
sudo ./scripts/install-security-tools.sh --profile core
```

安装常用辅助工具。使用 Web 顶部“系统工具状态”抽屉或接口查看当前状态：

```text
GET /api/tooling/catalog?refresh=true
```

### GDB Multi MCP（可选）

```bash
sudo apt-get install -y gdb
uv tool install --from \
  git+https://github.com/Mistyovo/gdb-multi-mcp@6e8048b8e933bbbae79b6da16fe69249f56fe30d \
  gdb-multi-mcp
```

将 `LINGSHU_GDB_MCP_COMMAND` 指向安装后的 `gdb-multi-mcp`。如果只配置 `uvx`，面板会显示“降级”，因为运行时仍依赖本机已缓存的依赖。

### IDA Lib MCP（可选）

1. 合法安装 IDA Pro 并确认 `idat` 或 `idat64` 可执行。
2. 安装 `idalib-mcp`。
3. 在 `.env` 设置 `LINGSHU_IDA_DIR` 和 `LINGSHU_IDALIB_MCP_COMMAND`。
4. 刷新工具状态；两项均通过后 Reserve 才能连接 IDA MCP。

### AntSword MCP（可选）

API 启动时会尝试托管 AntSword SSE MCP（默认 `127.0.0.1:30080/sse`）。无图形环境下会尝试使用 `xvfb-run`。AntSword 只会在发现 WebShell 相关证据后由 Attack 按需连接；攻击类操作仍受人工审批约束。

## 验证与测试夹具

运行单元测试：

```bash
/home/kali/miniconda3/envs/agentscope/bin/python -m unittest discover \
  -s tests -p "test_*.py"
```

生成安全的本地功能测试附件：

```bash
/home/kali/miniconda3/envs/agentscope/bin/python \
  scripts/generate-agent-test-fixtures.py
```

使用生成的合成附件逐个创建会话，验证附件分析、网络 Recon、审批、MCP、报告、页面刷新和历史恢复。

## 常见问题

### 无法登录 `/superadmin`

确认数据库初始化前 `.env` 中已设置非空的 `LINGSHU_SUPERADMIN_PASSWORD`。若账户已经创建，请用现有超级管理员登录后重置密码；仅修改 `.env` 不会重置它。

### 工具状态显示“缺失”或 MCP 显示“降级”

点击“重新探测工具”，阅读状态面板中的错误。常见原因是 systemd 没继承交互式 Shell 的 `PATH`；将启动器的绝对路径写入 `.env`，然后重启 API。

### AntSword MCP 未就绪

检查 `LINGSHU_ANTSWORD_EXECUTABLE`、`xvfb-run`、`WorkDir/antsword-mcp.log` 和端口 `30080`。不需要 AntSword 时可设置 `LINGSHU_ANTSWORD_AUTOSTART=false`。

### 刷新页面后会话不完整

先检查服务日志、`data/users.db` 读写权限和磁盘空间。不要手动删除 `.TaskMemory/sessions/` 或运行中的会话工件；它们用于会话恢复和审计校正。

### 多会话时 CPU 占用过高

先检查模型调用、工具进程和编辑器文件索引。API 模式下建议减少高并发会话，避免同时运行重型 IDA/GDB/取证任务，并观察工具状态和服务日志。

## 项目结构

```text
api.py                       FastAPI + SSE 多会话 Web 后端
main.py                      CLI 与核心任务工作流
agent/                       Brain、Recon、Orchestrator、Attack、Reserve 等专家
agent/Prompt/                所有 Agent 系统提示词
core/TaskState.py            状态机、审计链、MissionStore
core/session_store.py        SQLite 会话存储
core/persistence_service.py  批量持久化队列
Tools/                       受限 Shell、计划、范围、RAG、工具目录等
config/tool_catalog.json     系统工具能力声明
webui/                       React 控制台
scripts/                     安装、工具安装、测试夹具生成脚本
```
