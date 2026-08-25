# 灵枢 (Lingshu) — 多智能体授权安全测试系统

基于 [AgentScope 2.x](https://github.com/agentscope-ai/agentscope) 的多智能体框架，通过 **Brain → Orchestrator → Recon → Attack** 链完成授权渗透测试。状态机驱动、全程可审计、安全边界可复现。

---

## 设计理念

> **所有 Agent 只负责"产生结果"，只有 Orchestrator 可以"改变任务状态"。**

灵枢将安全测试分解为**战略（Brain）→ 战术（Orchestrator）→ 执行（Recon/Attack/Analysis/CVE_Search）**三个层次，每个执行层 Agent 不拥有决策权。这确保了：

- **决策路径单向**：信息从侦察向上流动，指令从指挥向下流动，不存在横向越权
- **状态迁移可追踪**：每一次阶段变化都记录在审计日志中，包含行为者、原因和时间戳
- **攻击链可回放**：任何一次任务的所有 Agent 调用、工具执行、状态迁移都可以从持久化记录中完整重建

---

## 架构概览

```
                          ┌──────────────┐
                          │    用户      │
                          └──────┬───────┘
                                 │ 任务目标
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                        main.py (入口)                            │
│  parse_target() → prepare_workspace() → classify()               │
│  解析目标 · 安全解压 · 题型自动分类                                │
└─────────────────────────────────────────────────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │  Brain   │ │TaskState │ │AgenticMem│
              │  战略规划  │ │  任务状态  │ │  长期记忆  │
              └──────────┘ └──────────┘ └──────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Orchestrator (唯一决策者)                      │
│                                                                  │
│  dispatch_recon()    →  派侦察兵收集证据                          │
│  dispatch_attack()   →  派攻击手分析/利用                         │
│  view_mission_state() → 查看结构化任务状态                        │
│  complete_mission()  →  结束任务 · 写入长期记忆                    │
│                                                                  │
│  唯一可推进阶段 · 唯一可修改状态 · 唯一可宣布结束                    │
└─────────────────────────────────────────────────────────────────┘
           │                                    │
    ┌──────┴──────┐                    ┌───────┴───────┐
    ▼             ▼                    ▼               ▼
┌────────┐ ┌────────────┐    ┌────────────┐   ┌────────────┐
│ Recon  │ │ArtifactTriage│   │   Attack   │   │  Analysis  │
│ 网络扫描│ │  文件分析    │    │  攻击验证   │   │  漏洞研判   │
└────────┘ └────────────┘    └─────┬──────┘   └────────────┘
                                   │
                            ┌──────┴──────┐
                            ▼             ▼
                      ┌──────────┐  ┌──────────┐
                      │CVE_Search│  │scoped_sh │
                      │ CVE 情报  │  │  受限Shell│
                      └──────────┘  └──────────┘
```

---

## 核心特性

### 1. 全程可审计

**每条决策、每次工具调用、每次状态迁移均被记录。**

| 审计维度 | 实现方式 |
|----------|----------|
| **Agent 调用链** | `AuditEvent` 记录 `timestamp`、`actor`、`action`、`phase`、`details` |
| **阶段迁移日志** | `transition()` 拒绝非法迁移并记录 `previous → current` 及 `reason` |
| **攻击链追踪** | `attack_chain` 保存每次 `dispatch_attack` 的 `objective` + `report` |
| **侦察发现** | `findings` 保存每次 `dispatch_recon` 的原始证据 |
| **持久化安全** | `MissionStore.save()` 使用临时文件 + `os.fsync` + `os.replace` 原子写入，断电不丢数据 |
| **长期记忆** | `AgenticMemory` 保存最近 50 次任务的成功攻击链，Brain 可查询历史经验 |

**审计日志示例**（`.TaskMemory/current_mission.json` 片段）：

```json
{
  "target": "10.8.21.128:49152",
  "phase": "exploitation",
  "category_decision": {
    "primary": "web",
    "confidence": 0.7,
    "stage": "initial",
    "evidence": ["goal 关键词命中 web: 1 个"]
  },
  "events": [
    {"timestamp": "2025-01-18T14:32:01", "actor": "system",   "action": "mission_created"},
    {"timestamp": "2025-01-18T14:32:15", "actor": "Brain",    "action": "plan_created"},
    {"timestamp": "2025-01-18T14:32:16", "actor": "Orchestrator", "action": "phase_transition", "details": {"previous": "planning", "current": "recon", "reason": "战略计划已制定"}},
    {"timestamp": "2025-01-18T14:32:30", "actor": "Orchestrator", "action": "dispatch_recon", "details": {"focus": "全面扫描端口和服务"}},
    {"timestamp": "2025-01-18T14:33:05", "actor": "Orchestrator", "action": "finding_added", "details": {"source": "Recon"}},
    {"timestamp": "2025-01-18T14:33:06", "actor": "Orchestrator", "action": "phase_transition", "details": {"previous": "recon", "current": "analysis", "reason": "收到新的侦察证据"}}
  ],
  "findings": [{"timestamp": "...", "source": "Recon", "report": "49152/tcp → HTTP → Apache/2.4.49"}],
  "attack_chain": [{"timestamp": "...", "objective": "漏洞分析", "report": "..."}]
}
```

---

### 2. 多层权限控制

灵枢实现**五层纵深权限体系**，确保 Agent 的任何操作均受约束：

```
┌──────────────────────────────────────────────┐
│ 第 1 层：目标范围约束 (scoped_shell)           │
│   · 所有网络命令必须显式包含授权目标 IP          │
│   · 检测并拦截授权范围外的 IP 地址               │
│   · 网络工具（nmap/curl/sqlmap…）强制校验目标    │
├──────────────────────────────────────────────┤
│ 第 2 层：破坏性命令拦截                         │
│   · rm -rf / · reboot · shutdown             │
│   · mkfs · dd of=/dev/ · fork bomb           │
│   · 正则匹配，实时拒绝                          │
├──────────────────────────────────────────────┤
│ 第 3 层：Agent 职能边界                         │
│   · 仅 Orchestrator 可推进阶段、修改状态         │
│   · Recon/Attack/Analysis 只返回结果            │
│   · 非法状态迁移被 ValueError 拒绝               │
├──────────────────────────────────────────────┤
│ 第 4 层：文件安全 (safe_extract)                │
│   · 防 Zip Slip 路径穿越                       │
│   · 防压缩炸弹（200x 压缩比上限）                 │
│   · Tar 拒绝符号链接/设备文件/FIFO               │
│   · 清除 setuid/setgid 危险权限位               │
├──────────────────────────────────────────────┤
│ 第 5 层：AgentScope 原生权限                     │
│   · AllowedFunctionTool 绕过默认 ASK 检查        │
│   · 内部已完成范围校验，仅放行已授权操作            │
└──────────────────────────────────────────────┘
```

**权限边界示例**：

```python
# scoped_shell 拦截非授权 IP
scoped_shell("nmap 192.168.1.1")   # ❌ PermissionError: 命令包含授权范围外 IP

# 网络工具必须包含目标
scoped_shell("nmap -p80")          # ❌ PermissionError: 网络命令必须显式包含本次授权目标

# 破坏性命令阻断
scoped_shell("rm -rf /")           # ❌ PermissionError: 命令命中本机破坏性操作拦截规则

# 正确用法
scoped_shell("nmap -p80 10.8.21.128")  # ✅ 通过所有校验
```

---

### 3. 决策可复现

**同一输入 → 同一状态流转 → 同一攻击路径 → 同一审计日志。**

| 可复现性保障 | 实现方式 |
|-------------|----------|
| **状态机约束** | `_ALLOWED_TRANSITIONS` 定义 7 阶段合法迁移，非法迁移抛出异常 |
| **单一事实来源** | `MissionState` 是唯一的状态持有者，所有 Agent 从中读取、Orchestrator 写入 |
| **题型分类归档** | `CategoryDecision` 记录 `primary` + `secondary` + `confidence` + `evidence` + `scores`，分类依据可追溯 |
| **结构化目标模型** | `TargetSpec` 明确 `kind` / `host` / `port` / `authorization_scope`，不再依赖字符串解析 |
| **长期经验复用** | 成功攻击链（service → CVE → exploit）持久化到 `AgenticMemory`，Brain 规划时自动参考 |
| **题型修正可追溯** | `category_history` 记录 `initial → post_recon → manual` 的完整分类演变 |

**阶段状态机**：

```
PLANNING ──→ RECON ──→ ANALYSIS ──→ EXPLOITATION ──→ POST_EXPLOITATION ──→ COMPLETED
    │           │           │              │                  │
    └───────────┴───────────┴──────────────┴──────────────────┴──────────→ FAILED

合法迁移（共 15 条边）：
  PLANNING        → RECON, FAILED
  RECON           → RECON (补充侦察), ANALYSIS, FAILED
  ANALYSIS        → RECON (证据不足), ANALYSIS (深入分析), EXPLOITATION, FAILED
  EXPLOITATION    → RECON, ANALYSIS, EXPLOITATION (重试), POST_EXPLOITATION, COMPLETED, FAILED
  POST_EXPLOITATION → POST_EXPLOITATION, COMPLETED, FAILED
  COMPLETED/FAILED → (终态，不可迁移)
```

---

## 快速开始

### 环境要求

- Python 3.11+
- DeepSeek API Key 或 Qwen API 端点
- Docker daemon + `kali-full:latest` 镜像（默认 docker 工作区模式）
- 容器化 IDA MCP（`http://127.0.0.1:8745`，见 `/home/gitciu/ida/IDA-MCP-使用文档.md`）
  与 AntSword MCP（`http://127.0.0.1:30080/sse`，见 `/home/gitciu/AntSword/README.md`）已部署

### 安装

```bash
git clone <repo-url> Lingshu
cd Lingshu
pip install -r requirements.txt
cp .env.example .env
# 编辑 .env 填入 API Key
```

OCR 功能还需要系统安装 Tesseract。Debian/Kali/Ubuntu 可执行：

```bash
sudo apt-get install tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim
```

未安装时主系统仍可启动，但 `ocr_image` 工具会返回明确的依赖缺失提示。

Reverse/Pwn 的 GDB 动态调试使用 `gdb-multi-mcp`。先安装 `uv` 和 GDB，
再缓存灵枢锁定并验证过的 MCP 版本：

```bash
sudo apt-get install gdb
uv tool install --from git+https://github.com/Mistyovo/gdb-multi-mcp@6e8048b8e933bbbae79b6da16fe69249f56fe30d gdb-multi-mcp
uvx --from git+https://github.com/Mistyovo/gdb-multi-mcp@6e8048b8e933bbbae79b6da16fe69249f56fe30d gdb-multi-mcp --version
```

运行任务时使用已缓存的固定提交，不会临时升级 MCP。默认不启用上游
`--unsafe`，灵枢也不会向 Agent 暴露 attach、任意远程目标或未校验的会话入口。

Web API 启动时会自动启动 AntSword 及其 SSE MCP 服务
`http://127.0.0.1:30080/sse`。若本机已有服务则直接复用且关闭 API 时不会误杀；
否则 API 取得该进程的所有权，并在关闭时清理整个 AntSword/Xvfb 进程组。
Attack 创建时会连接该 SSE 服务，将 37 个 AntSword 工具注册到攻击
智能体；任务结束时只关闭本任务的 MCP 会话。逆向智能体则独立连接
GDB MCP，任务结束时关闭其 GDB 会话和 MCP 进程。
无桌面环境会自动使用 `xvfb-run`。如需禁用自动启动，可设置：

```bash
export LINGSHU_ANTSWORD_AUTOSTART=false
```

### 基本用法

```bash
# 网络目标 — 默认 DeepSeek Flash
python main.py -t 10.8.21.128

# 指定端口
python main.py -t 10.8.21.128:49152 -g "获取 Web Shell"

# 本地 CTF 文件 — 自动解压 + 分类
python main.py -t challenge.zip -g "ROP 二进制利用"

# 使用 Qwen 模型（端点 10.8.128.108:8200/v1）
python main.py -t 10.8.21.128 -p qwen -m Min
```

### 命令行参数

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--target` | `-t` | 必填 | 授权目标（IP / IP:端口 / 主机名 / 文件路径） |
| `--goal` | `-g` | `获取 Flag` | 任务目标描述 |
| `--provider` | `-p` | `deepseek` | 模型提供商（`deepseek` / `qwen`） |
| `--model` | `-m` | `Min` | 思考级别：`Low`(快速) / `Min`(默认) / `Max`(深度) |

---

## 使用方法

### 场景一：网络渗透测试

```bash
# 基础侦察 + 攻击（DeepSeek Flash）
python main.py -t 192.168.1.100 -g "获取服务器权限"

# 深度推理模式（Pro 模型）
python main.py -t 192.168.1.100 -m Max

# Qwen 快速模式
python main.py -t 192.168.1.100 -p qwen -m Low
```

系统自动完成端口扫描→服务识别→漏洞分析→利用验证→Flag 收集。

### 场景二：CTF 文件题目

```bash
# Pwn 题 — 系统自动解压并识别题型
python main.py -t pwn-challenge.zip -g "ROP 利用获取 flag"

# Reverse 题
python main.py -t crackme.apk -g "逆向分析获取密钥"

# Crypto 题
python main.py -t cipher.txt -g "RSA 弱密钥攻击"

# Forensics 题
python main.py -t capture.pcapng -g "网络包取证"
```

文件目标自动触发 `safe_extract()`（防路径穿越/压缩炸弹），解压后根据文件类型（ELF/PCAP/图片等）自动分类题型、加载对应 Skill。

### 场景三：指定思考深度

```bash
# 简单扫描 — Low 足以胜任
python main.py -t 10.0.0.1 -g "仅做端口扫描" -m Low

# 复杂分析 — Max 深度推理
python main.py -t 10.0.0.1 -g "分析多层反序列化利用链" -m Max

# 日常任务 — Min 默认
python main.py -t 10.0.0.1 -m Min
```

| 级别 | DeepSeek | Qwen | 适用场景 |
|------|----------|------|---------|
| `Low` | v4-flash, thinking=off | thinking=false, 2K tokens | 端口扫描、简单信息收集 |
| `Min` | v4-flash, thinking=on | thinking=true, 4K tokens | 漏洞分析、日常渗透 |
| `Max` | v4-pro, thinking=on | thinking=true, 8K tokens | 复杂利用链、深度推理 |

### 查看帮助

```bash
python main.py -h
```

---

## 项目结构

```
Lingshu/
├── main.py                 # CLI 入口 · 数据流编排
├── AgenticMemory.py        # 长期经验记忆（最近 50 条任务）
├── requirements.txt        # agentscope==2.0.4.post1
├── .env.example            # API Key 模板
│
├── core/                   # 基础共享模块（配置/认证/状态/会话/工作区）
│   ├── config.py           # 环境变量加载 · RuntimeConfig
│   ├── TaskState.py        # MissionState · Phase 状态机 · 审计日志 · MissionStore
│   ├── auth.py             # 注册/登录/JWT/密码重置
│   ├── session_store.py    # 会话/消息/流式快照 PostgreSQL
│   ├── model_registry.py   # Provider 注册表（加密存储、运行时覆盖）
│   └── workspace_service.py # Workspace v2 生命周期
│
├── LLM/
│   └── model.py            # DeepSeek + Qwen 模型工厂（create_model 统一入口）
│
├── agent/
│   ├── target.py           # TargetSpec · normalize_target()（支持 IP:端口/文件）
│   ├── archive.py          # safe_extract()（防 Zip Slip/压缩炸弹）
│   ├── categorize.py       # CategoryDecision · classify()（评分制题型检测）
│   ├── tooling.py          # scoped_shell · AllowedFunctionTool · 权限校验
│   ├── Brain.py            # 战略规划 Agent
│   ├── Orchestrator.py     # 战术调度 Agent（唯一决策者）
│   ├── Recon.py            # NetworkReconAgent + ArtifactTriageAgent
│   ├── Attack.py           # 攻击验证 Agent（动态 Skill 加载）
│   ├── Analysis.py         # 漏洞研判 Agent（纯推理，不执行命令）
│   └── CVE_Search.py       # CVE 情报查询工具 · create_cve_search_tool()
│
├── Skills/
│   ├── ctf-skills/         # 9 个 CTF 题型知识库 + writeup（150+ 技术文件）
│   │   ├── ctf-web/        # Web 渗透（SQLi/XSS/SSRF/SSTI/JWT/反序列化…）
│   │   ├── ctf-pwn/        # 二进制利用（栈溢出/ROP/堆/FORMAT/内核…）
│   │   ├── ctf-reverse/    # 逆向工程（反编译/脱壳/混淆/多平台…）
│   │   ├── ctf-crypto/     # 密码学（RSA/AES/ECC/格/LWE/PRNG…）
│   │   ├── ctf-forensics/  # 取证分析（磁盘/内存/网络/隐写…）
│   │   ├── ctf-malware/    # 恶意软件分析（C2/PE/混淆…）
│   │   ├── ctf-misc/       # 杂项（Bash Jail/Python Jail/Linux 提权/RF…）
│   │   ├── ctf-osint/      # 开源情报（地理定位/社交媒体…）
│   │   ├── ctf-ai-ml/      # AI/ML 安全（对抗样本/LLM 攻击…）
│   │   └── ctf-writeup/    # 报告撰写（所有题型共享）
│   ├── cve-search/         # CVE 情报查询脚本
│   └── agentscope-tutorial/ # AgentScope 2.0 开发教程
```

---

## 智能体团队

### Brain（战略总参谋）

- **职责**：理解任务目标，制定四阶段作战计划
- **权限**：不调用工具，不执行扫描或攻击
- **输入**：授权目标 + 任务目标 + 系统分类结果（题型/置信度/证据）
- **输出**：阶段性计划 + 题型修正建议（若需要）
- **特殊规则**：不得擅自修改正式题型，修正需由 Orchestrator 审批

### Orchestrator（行动总指挥）

- **职责**：**唯一**可以推进阶段、修改状态、宣布任务结束的 Agent
- **工具**：
  - `dispatch_recon(focus)` — 派遣侦察兵收集证据
  - `dispatch_attack(target_info, objective)` — 派遣攻击手分析/利用
  - `view_mission_state()` — 查看结构化任务状态
  - `complete_mission(success, summary, flag)` — 结束任务并保存长期记忆
- **决策规则**：先侦察→再分析→后利用→收集 Flag，证据不足时回退补充侦察

### Recon（侦察兵）

**NetworkReconAgent**（网络目标）：
- 端口扫描、服务识别、Banner 获取、Web 指纹、目录扫描
- 只使用 `scoped_shell`，命令通过网络范围校验

**ArtifactTriageAgent**（文件目标）：
- 文件列表、类型识别（ELF/PE/PCAP/镜像）、静态分析
- 禁止联网、禁止执行不可信二进制

### Attack（攻击手）

- 调用 `analysis` 获取漏洞研判 → 调用 `cve_search` 核验 CVE → 调用 `scoped_shell` 验证/利用
- **Skill 动态加载**：根据题型分类自动加载对应知识库（web/pwn/reverse/crypto…）
- 不得在没有证据的情况下宣布利用成功

### Analysis（分析专家）

- 纯推理 Agent，不执行任何命令
- 根据侦察证据推理漏洞可能性和攻击路径
- 区分"已确认事实、合理推测、仍需验证"

### CVE_Search（CVE 情报）

- 查询 MITRE 等公开源的 CVE 情报
- 返回漏洞描述、严重程度、已知利用信息
- 只读工具，并发安全

---

## 数据流详解

```
1. parse_target()
   输入: "10.8.21.128:49152" → TargetSpec(kind=network, host=10.8.21.128, port=49152)
   输入: "challenge.zip"     → TargetSpec(kind=archive, sha256=abc123...)

2. prepare_workspace()
   网络目标 → 直接使用 host:port
   归档文件 → safe_extract() 安全解压到 WorkDir/{name}_{sha256}

3. initial_classify()
   评分制分类: 关键词(+1) + 文件名(+5) + 文件类型信号(+10)
   网络目标无关键词 → primary=unknown (不默认 web!)

4. Brain 战略规划
   收到: 目标类型 + 初步分类(题型/置信度/证据) + 任务目标
   输出: 阶段性计划 + 可选题型修正建议
   注意: Brain 不修改正式题型，修正需 Orchestrator 审批

5. Recon/Triage 路由
   kind=network    → NetworkReconAgent(scoped_shell target=host:port)
   kind=archive    → ArtifactTriageAgent(scoped_shell cwd=workdir)

6. 后侦察二次分类 (post_recon_classify)
   用 Recon 证据修正: 发现 HTTP 服务 → web 得分上升
   stage 从 initial 变为 post_recon

7. Attack 创建 (延迟)
   此时才创建 Attack Agent，根据最终分类加载对应 Skill
   题型已确定但 Skill 缺失 → 直接报错，不降级

8. Orchestrator 主循环
   dispatch_recon → 收集证据 → dispatch_attack → 分析/利用
   → 成功 → dispatch_attack(post_exploit) → complete_mission
   → 失败 → dispatch_recon(补充侦察) 或 换攻击路径

9. complete_mission()
   保存成功/失败结论 → 写入 AgenticMemory 长期经验
   下次类似目标，Brain 可参考历史攻击链
```

---

## 题型自动检测

灵枢支持 **9 个 CTF 题型** 的自动检测，不依赖用户手动指定：

| 题型 | 典型目标 | 检测信号 |
|------|---------|---------|
| `web` | HTTP/HTTPS 服务 | SQLi/XSS/SSRF 关键词，HTTP 服务侦察证据 |
| `pwn` | ELF 可执行文件 | ROP/overflow 关键词，ELF 文件信号 |
| `reverse` | 二进制/APK/DEX | 逆向/反编译关键词，Mach-O/DEX 信号 |
| `crypto` | 密文/密钥文件 | RSA/AES/cipher 关键词 |
| `forensics` | PCAP/镜像文件 | 取证/PCAP 关键词，PCAPNG 信号 |
| `malware` | PE 文件 | malware/病毒 关键词，PE32 信号 |
| `misc` | 脚本/杂项 | 编码/DNS/沙箱逃逸 关键词 |
| `osint` | 图片/元数据 | OSINT/定位 关键词 |
| `ai-ml` | 模型文件 | AI/对抗样本 关键词 |

**分类特征**：
- 关键词作为**弱证据**（每命中 +1 分）
- 文件内容信号**权重更高**（+10 分）
- 网络目标首次分类为 `unknown`（不默认 web）
- 侦察后可用 `reclassify()` 修正（自动提升置信度）
- 分类演变记录在 `category_history` 中，全程可追溯

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DEEPSEEK_API_KEY` | — | DeepSeek API 密钥（使用 DeepSeek 时必填） |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek API 地址 |
| `DEEPSEEK_MODEL_LOW` | `deepseek-v4-flash` | Low 级别模型 |
| `DEEPSEEK_MODEL_MIN` | `deepseek-v4-flash` | Min 级别模型 |
| `DEEPSEEK_MODEL_MAX` | `deepseek-v4-pro` | Max 级别模型 |
| `QWEN_API_KEY` | `sk-placeholder` | Qwen API 密钥 |
| `QWEN_BASE_URL` | `http://10.8.128.108:8200/v1` | Qwen API 地址 |
| `QWEN_MODEL` | `…Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf` | Qwen 模型名称 |
| `QWEN_REPEAT_PENALTY` | `1.08` | llama.cpp 重复惩罚；显式超过 1.2 时告警但保留原值 |
| `LINGSHU_COMMAND_TIMEOUT` | `300` | Shell 命令超时秒数（10-600） |
| `LINGSHU_WORKSPACE_BASE_IMAGE` | `kali-full:latest` | Docker 工作区基础镜像（须含 `python3`；首次启动构建派生镜像） |
| `LINGSHU_WORKSPACE_GATEWAY_PORT` | 自动 | 容器内 MCP 网关节选端口 |
| `LINGSHU_WORKSPACE_DOCKER_EXTRA_PIP` | — | 打进派生镜像的额外 pip 包（逗号分隔） |
| `LINGSHU_IDA_MCP_URL` | `http://127.0.0.1:8745` | 容器化 IDA MCP 根地址（MCP 端点为 `<URL>/sse`） |
| `LINGSHU_ANTSWORD_MCP_URL` | `http://127.0.0.1:30080/sse` | AntSword MCP SSE 端点 |

---

## 安全声明

灵枢**仅用于授权安全测试**。使用前必须确保：

1. 已获得目标所有者的**明确书面授权**
2. 理解并接受所有操作的**法律责任**
3. 在隔离环境中运行，**不得**用于未授权访问

系统内置的多层拦截机制是**纵深防御**，不能替代操作人员的合规审查。

---

## 技术栈

| 组件 | 技术 |
|------|------|
| Agent 框架 | AgentScope 2.0.4.post1 |
| LLM | DeepSeek V4 Flash/Pro + Qwen 3.6 35B (llama.cpp) |
| 异步运行时 | Python asyncio |
| 持久化 | JSON 原子写入（临时文件 + fsync + replace） |
| 状态机 | 7 阶段有限状态机 + 合法迁移验证 |
| 工具系统 | AgentScope Toolkit + 自研 AllowedFunctionTool |
| 安全隔离 | scoped_shell 多层校验 + safe_extract 文件安全 |

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v0.2.0 | 2025-01 | 多题型自动检测 · 结构化目标模型 · 安全解压 · 评分制分类 · 双模式 Recon |
| v0.1.0 | 2025-01 | 初始版本，Web 题型多智能体安全测试 |

---

## 许可证

内部项目，未公开发布。
