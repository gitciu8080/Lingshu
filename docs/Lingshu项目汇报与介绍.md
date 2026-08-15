# 灵枢（Lingshu）多智能体授权安全测试系统

> 项目汇报、技术介绍与评比材料

## 一、项目概述

灵枢（Lingshu）是一套基于 AgentScope 2.0.6 构建的多智能体授权安全测试与 CTF 自动分析平台。系统将复杂任务拆分为战略规划、战术调度、信息侦察、漏洞研判、安全验证、逆向分析、授权审计和总结归档等专业环节，通过状态机、人工审批、范围控制和审计哈希链约束智能体行为。

项目的核心目标不是让单个大模型“自由执行命令”，而是构建一支职责明确、权限受控、过程可回放、结果有证据的智能体专家团队。

系统支持两类主要任务：

- 网络目标：IP、主机名和端口形式的授权安全测试目标。
- 文件目标：压缩包、ELF、PE、APK、PCAP、镜像、脚本、密码学材料等 CTF 或安全分析附件。

系统同时提供 CLI 与 Web 两种使用方式，并具备多用户会话、实时流式消息、知识库检索、文件上传、人工审批、任务中断、PDF 报告、长期记忆和超级管理员模型配置等平台能力。

## 二、项目定位

灵枢的技术定位可以概括为：

> 面向授权安全测试与 CTF 场景的“可治理多智能体作战平台”。

与普通对话机器人或单智能体脚本相比，灵枢重点解决以下问题：

1. 如何把复杂安全任务拆分给不同专业角色。
2. 如何防止模型越权扫描、访问非授权目标或执行破坏性操作。
3. 如何在攻击阶段引入真实的人机协同审批。
4. 如何保存推理、消息、工具调用、证据与状态迁移。
5. 如何让任务在刷新、进程退出或服务重启后继续恢复。
6. 如何将历史经验、Markdown 知识库和专业 Skills 动态注入任务。
7. 如何让最终结果从聊天记录转化为可归档的正式报告。

## 三、总体技术架构

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         用户交互层                                  │
│  React 19 + Vite 7 WebUI / CLI / AgentScope Agent Service          │
│  会话、上传、流式消息、插话队列、审批、知识库、报告、超级管理        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ FastAPI + SSE/HTTP
┌──────────────────────────────▼──────────────────────────────────────┐
│                         应用服务层                                  │
│  身份认证 │ 多用户会话 │ 任务生命周期 │ 消息持久化 │ PDF │ RAG      │
│  AntSword 生命周期 │ 模型注册表 │ Agent Service 兼容层              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ run_mission()
┌──────────────────────────────▼──────────────────────────────────────┐
│                         多智能体决策层                              │
│                                                                     │
│  Brain ──计划──▶ Orchestrator ──调度──┬──▶ Recon / Triage          │
│                                       ├──▶ Analysis                 │
│                                       ├──▶ Attack                   │
│                                       ├──▶ Reverse                  │
│                                       └──▶ ScopeAuditor             │
│                                               │                     │
│  Summary ◀──────────── 完整会话、状态与证据 ──┘                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Toolkit / MCP / Skills
┌──────────────────────────────▼──────────────────────────────────────┐
│                         能力与工具层                                │
│ scoped_shell │ CVE │ OCR │ TonyEnc │ IntelPwn │ Plan │ Memory      │
│ IDA MCP │ GDB MCP │ AntSword MCP（37 工具）│ RAG │ Workspace      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                         数据与治理层                                │
│ MissionState │ 原子持久化 │ 检查点 │ 审计哈希链 │ SQLite          │
│ Milvus Lite │ 长期记忆 │ Artifacts │ PDF Reports │ Blob Store       │
└─────────────────────────────────────────────────────────────────────┘
```

## 四、核心设计原则

### 4.1 唯一状态决策者

只有 Orchestrator 可以推进任务阶段、修改任务状态和宣布任务结束。Recon、Analysis、Attack、Reverse 等专业 Agent 只负责产生报告或证据，不直接修改全局状态。

这一设计避免多个 Agent 并行修改任务状态造成竞争、越权或结果不一致。

### 4.2 证据驱动

系统要求区分：

- 已验证事实
- 合理推测
- 未验证事项
- 失败尝试
- 可复核证据

HTTP 200、工具无报错或模型推测不能直接被视为成功。计划项标记为 `completed` 时必须提交 evidence。

### 4.3 人工审批优先

首次进入 EXPLOITATION 阶段前，Orchestrator 必须调用人工审批工具。系统生成 2～3 个候选方案，允许用户选择方案并调整优先级。

审批结果持久化到 `MissionState.exploitation_approved` 和 `approved_attack_plan`，服务恢复后不会重复询问已经完成的审批。

### 4.4 范围最小化

所有网络命令必须指向授权目标。动态发现的新 IP 或网段不能自动加入范围，需要 ScopeAuditor 根据证据进行独立审核。

### 4.5 可恢复与可回放

任务状态、Agent 上下文、工具输出、审批、计划、推理消息和检查点均持久化。刷新页面不会改变后台任务，服务异常退出后可从安全检查点判断是否允许继续。

## 五、任务状态机

```text
PLANNING
   │
   ▼
RECON ◀──────────────┐
   │                 │ 证据不足，补充侦察
   ▼                 │
ANALYSIS ────────────┘
   │
   │ 人工审批通过
   ▼
EXPLOITATION
   │
   ▼
POST_EXPLOITATION
   │
   ▼
COMPLETED

任意非终态 ──异常/确定性失败──▶ FAILED
任意非终态 ──用户终止────────▶ CANCELLED
```

状态机拒绝非法迁移，每次合法迁移都会记录前一阶段、当前阶段、原因、行为者、时间和审计哈希。

## 六、智能体团队与分工

系统当前包含 9 类业务 Agent。NetworkRecon 与 ArtifactTriage 根据目标类型二选一；Attack 会根据题型切换专家人格。

| Agent | 专家名称 | 主要职责 | 主要能力 | 权限边界 |
|---|---|---|---|---|
| Brain | Sophia－战略规划专家 | 理解目标、制定阶段计划 | RAG、SubmitPlan/AddPlan | 不扫描、不攻击、不修改任务阶段 |
| Orchestrator | Alex－行动指挥专家 | 调度全队、推进状态、审批与收尾 | 调度工具、Plan、Memory、NSS 提交 | 唯一任务状态修改者 |
| NetworkRecon | Ethan－网络侦察专家 | 对授权网络目标进行低影响侦察 | scoped_shell、CVE 查询 | 禁止验证漏洞、写入目标或越界扫描 |
| ArtifactTriage | Iris－文件分析专家 | 对上传附件做静态分流和基线分析 | file/checksec/readelf、OCR、TonyDec | 不联网、不执行不可信二进制 |
| Analysis | Nora－漏洞研判专家 | 根据真实证据判断漏洞与误报风险 | CVE 查询、纯推理 | 不执行系统命令，不改变状态 |
| Attack | 动态专家人格 | 执行题型对应的验证、利用和目标达成 | scoped_shell、AntSword、OCR、CVE、Skills | 攻击性动作受人工审批与目标范围限制 |
| Reverse | Ryan－逆向程序专家 | 静态逆向、动态调试和算法恢复 | IDA MCP、GDB MCP、IntelPwn | 只允许任务工作区内的二进制入口 |
| ScopeAuditor | Grace－授权范围审计专家 | 审核新增 IP/网段是否可纳入范围 | 纯推理、证据匹配 | 公网、无证据或证据不匹配一律拒绝 |
| Summary | Mia－对话总结与报告专家 | 汇总完整任务并生成报告正文 | 会话、状态、审批与证据汇总 | 不调用外部工具，不补写不存在的结论 |

### 6.1 Attack 动态专家人格

Attack 不是固定名称，而是根据题型自动选择专业身份：

| 题型 | 专家人格 |
|---|---|
| Web | Mike－WEB 渗透专家 |
| Pwn | Victor－二进制利用专家 |
| Reverse | Ryan－逆向利用专家 |
| Crypto | Alice－密码学安全专家 |
| Forensics | Iris－数字取证专家 |
| Malware | Morgan－恶意代码分析专家 |
| Misc | Taylor－综合安全专家 |
| OSINT | Olivia－开源情报专家 |
| AI/ML | Ada－AI 安全专家 |
| 未知网络题型 | Mike－网络渗透专家 |
| 未知文件题型 | Taylor－安全验证专家 |

## 七、Agent 之间的协作流程

### 7.1 标准流程

1. 系统规范化用户目标，建立任务会话与独立工作区。
2. 文件目标先安全解压，并根据扩展名、Magic、目录结构和任务描述进行题型分类。
3. Brain 查询知识库与历史经验，提交 4～8 条结构化计划。
4. Orchestrator 接管计划并派遣 Recon 或 ArtifactTriage。
5. Analysis 根据侦察证据研判漏洞、利用条件和误报风险。
6. 若需要验证或利用，Orchestrator 生成候选方案并请求人工审批。
7. 审批通过后，Attack 或 Reverse 执行受控验证。
8. 工具证据写入 Artifacts，结果写入 findings 或 attack_chain。
9. Orchestrator 完成状态收尾、Flag 提交和长期记忆归档。
10. Summary 汇总完整对话，生成格式化中文 PDF 报告。

### 7.2 用户插话与中断

用户可以在任意 Agent 工作期间补充新情报。系统使用 AgentScope 官方异步取消机制中断当前模型调用，并将用户消息放入待发送队列：

- 已发送消息显示为用户气泡并持久化。
- 尚未发送的内容显示在输入框上方队列。
- 当前 Agent 被中断后，Orchestrator 在下一轮读取新情报。
- Shell 子进程和嵌套 Agent task 被统一登记并清理。

## 八、安全治理与审计体系

### 8.1 多层防护

| 层级 | 防护机制 |
|---|---|
| 目标层 | `TargetSpec` 规范化 IP、主机名、端口和文件目标 |
| 范围层 | `ScopeRegistry` 维护授权 IP、主机和网段 |
| 命令层 | `scoped_shell` 检测非授权 IP、网络命令目标和破坏性命令 |
| 阶段层 | EXPLOITATION 前强制人工审批 |
| Agent 层 | 专业角色权限隔离，只有 Orchestrator 修改状态 |
| 工具层 | `AllowedFunctionTool` 仅用于内部已经完成范围校验的函数 |
| 参数层 | `StrictJSONToolkit` 对工具参数执行严格 JSON Schema 校验 |
| 文件层 | 安全解压、防 Zip Slip、防压缩炸弹、拒绝危险 Tar 成员 |
| 进程层 | 任务级 ProcessTracker，取消或结束时终止整个进程组 |
| 持久化层 | 临时文件、`fsync`、`os.replace` 原子写入 |
| 审计层 | SHA-256 前向哈希链防止历史事件被静默修改 |

### 8.2 严格工具 JSON

模型生成的工具参数必须满足：

- 顶层必须是 JSON Object。
- 不允许重复字段。
- 不允许 NaN、Infinity 等非标准数值。
- 必须通过工具 JSON Schema 校验。
- 首次错误只允许一次短提示重试。
- 第二次仍失败则阻止工具执行，记录参数摘要、哈希和错误证据，并进入安全收尾。

### 8.3 重试熔断

系统基于“工具名＋目标＋规范化参数＋目标描述＋证据版本”生成动作指纹。相同动作在没有新证据时重复失败会触发熔断，避免 Agent 陷入无限循环或只改写自然语言后重复执行。

## 九、工具体系

### 9.1 自研基础工具

| 工具 | 功能 |
|---|---|
| scoped_shell | 在授权范围内执行命令，支持超时、中断、输出落盘和进程组清理 |
| SubmitPlan | Brain 一次性原子提交结构化计划 |
| AddPlan | 添加作战计划项 |
| UpdatePlan | 更新内容、阶段、状态和证据 |
| DeletePlan | 删除失效计划项 |
| ListPlan | 查询当前计划快照 |
| QueryMemory | 查询历史成功攻击链和长期经验 |
| cve_search | 调用本地 CVE Skill 脚本查询公开漏洞情报 |
| ocr_image | 使用 Tesseract OCR 提取图片文字 |
| tonydec | 识别并解码 TonyEnc 固定文件头格式 |
| intelpwn_analyze | ELF 保护、ROP、溢出、格式化字符串等静态分析 |
| safe_extract | ZIP/TAR 安全解压与内容清单生成 |
| workspace_read/glob/grep | 受工作区边界约束的文件读取、匹配和检索 |
| request_exploitation_approval | 请求攻击阶段人工审批和方案选择 |
| request_scope_expansion | 请求新增 IP 或网段授权 |
| complete_mission | 确定性完成任务并收尾计划项 |
| submit_nss_flag | 向 NSSCTF Agent Arena 提交 Flag 并保存结果 |

### 9.2 AntSword MCP：Attack 专属 WebShell 工具集

Attack 连接 `http://127.0.0.1:30080/sse`，注册全部 37 个 AntSword MCP 工具。

| 分类 | 工具 |
|---|---|
| Shell 管理 | `shell_list`、`shell_get`、`shell_add`、`shell_edit`、`shell_del`、`shell_capabilities` |
| 基础信息 | `base_info`、`base_probedb` |
| 命令执行 | `cmd_exec`、`cmd_list`、`cmd_quote` |
| 文件管理 | `file_dir`、`file_read`、`file_write`、`file_delete`、`file_copy`、`file_rename`、`file_retime`、`file_chmod`、`file_mkdir`、`file_wget`、`file_hash`、`file_upload`、`file_download` |
| 数据库 | `db_list_confs`、`db_get_conf`、`db_add_conf`、`db_del_conf`、`db_show_databases`、`db_show_tables`、`db_show_columns`、`db_query` |
| 通用接口 | `raw_request` |
| 系统管理 | `mcp_status`、`mcp_logs`、`mcp_config_get`、`mcp_config_set` |

推荐调用链：

```text
shell_list → shell_capabilities → base_info → cmd_exec / file_dir / db_query
```

权限策略：

- 信息读取与能力探测可以在分析阶段使用。
- 命令执行、文件写入、数据库变更和配置修改与人工审批状态实时联动。
- 只能选择 URL 与当前授权目标一致的 `shell_id`。
- API 启动时自动启动 AntSword；已有服务则复用，API 关闭时只清理由自身启动的进程组。

### 9.3 IDA MCP：Reverse 静态逆向工具集

Reverse 通过 `idalib-mcp` 使用 IDA Pro 9.1，提供以下能力：

- 自动生成并缓存 `.i64` 数据库。
- 二进制概览、函数枚举、反编译和反汇编。
- 调用关系、交叉引用、基本块和数据流分析。
- 字符串、全局变量、结构体、栈帧和字节检索。
- 批量分析、函数画像和签名生成。
- 会话数据库的打开、查询和关闭。

原始 `idb_open` 不直接暴露给模型，必须通过 `ida_open_binary` 对任务文件路径进行校验后创建会话。

### 9.4 GDB MCP：Reverse 动态调试工具集

Reverse 同时接入固定提交版本的 `gdb-multi-mcp`，支持：

- 创建和关闭多 GDB 会话。
- 加载 Core Dump。
- 设置、列举和删除断点/观察点。
- run、continue、step、next、finish 和 interrupt。
- 查看线程、调用栈、寄存器、变量和表达式。
- 读取内存、反汇编和符号解析。
- Heap、内存映射、上下文面板和动态行为分析。
- 超时中断和结构化 JSON 返回。

安全限制：

- 默认不启用上游 `--unsafe`。
- 不直接暴露 attach、任意远程目标、rr record/replay 等绕过工作区的入口。
- `gdb_create_session` 和 `gdb_load_core` 强制校验文件位于当前任务工作区。

## 十、Skills 能力体系

### 10.1 核心 CTF Skills

项目包含 11 组核心题型 Skills：

- `ctf-web`
- `ctf-pwn`
- `ctf-reverse`
- `ctf-crypto`
- `ctf-forensics`
- `ctf-malware`
- `ctf-misc`
- `ctf-osint`
- `ctf-ai-ml`
- `ctf-writeup`
- `solve-challenge`

Attack 根据 `category_decision.primary` 和 `secondary` 动态加载相关 Skill，`ctf-writeup` 始终加载。

### 10.2 CyberPenda 扩展 Skills

项目引入了 121 个 CyberPenda Skill 包，覆盖以下能力域：

| 能力域 | 代表 Skills |
|---|---|
| 通用攻击链 | `attack-chain`、`pentest-tools`、`ctf-sandbox-orchestrator` |
| Web/API | `api-security`、`code-audit`、`database-security`、`protocols-graphql` |
| 漏洞专项 | SQL 注入、NoSQL 注入、XSS、CSRF、SSRF、SSTI、XXE、RCE、JWT、IDOR、文件上传、路径穿越、请求走私、业务逻辑、竞态条件等 |
| 工具方法 | nmap、httpx、ffuf、katana、naabu、nuclei、semgrep、sqlmap、subfinder |
| Pwn/Reverse | `pwn-chain`、`reverse-engineering`、`reverse-skill-router`、`ida-reverse`、`ghidra-reverse`、`radare2` |
| 语言与平台逆向 | Android/APK、iOS、.NET、Go/Rust、JavaScript、macOS、浏览器扩展、固件、内核驱动 |
| 取证与恶意代码 | `digital-forensics`、`malware-analysis`、`threat-hunting`、`edr-bypass-re` |
| 云与身份 | Kubernetes、容器、AD、Kerberos、OAuth/OIDC、身份联合、云元数据 |
| 专用环境 | OT/ICS、无线、SDR、硬件安全、邮件安全、供应链安全 |
| 竞赛场景 | NSSCTF、协议逆向、隐写、DPAPI、LSASS、PCAP、模板路径、运行时路由、Prompt Injection 等 |
| 交付材料 | `docs-generator`、`diagram-generator`、CTF writeup 与证据报告方法 |

运行时不会把 121 个 Skill 全部一次性塞入上下文，而是按题型路由加载：

| 分类 | 默认追加 CyberPenda Skills |
|---|---|
| 所有题型 | `attack-chain` |
| Web | `api-security`、`pentest-tools` |
| Pwn | `pwn-chain` |
| Reverse | `reverse-skill-router`、`reverse-engineering` |
| Crypto | `ctf-sandbox-orchestrator` |
| Forensics | `digital-forensics` |
| Malware | `malware-analysis` |
| Misc | `ctf-sandbox-orchestrator` |
| OSINT | `pentest-tools` |
| AI/ML | `llm-security` |

这种“全量能力入库、按需加载”的方式兼顾了专业覆盖面与上下文效率。

## 十一、知识库与长期记忆

### 11.1 本地 Markdown 知识库

知识文件保存在 `.RAG/`，当前按 CVE、Crypto、CTF 和长期任务记忆等目录组织。

RAGService 提供：

- Markdown 文档扫描、切片与索引同步。
- OpenAI-compatible Embedding API。
- Milvus Lite 本地向量存储。
- UI 中的知识库状态、重建索引和 Top-K 搜索。
- AgentScope RAG Middleware，将检索结果注入 Brain/Attack。
- Collection 被 release 后搜索前自动恢复加载。
- Embedding 维度配置和知识库状态诊断。

### 11.2 AgenticMemory 长期经验

任务完成后，成功攻击链和任务摘要写入长期经验库，同时归档为 Markdown，供后续任务检索。

长期记忆主要保存：

- 目标与任务目标。
- 服务、CVE 和利用路径。
- 成功/失败步骤。
- Flag 或目标达成信息。
- 可复用策略与注意事项。

Brain 和 Orchestrator 可以通过 `QueryMemory` 查询相似历史经验，但历史内容只能作为候选策略，必须由当前任务证据再次验证。

## 十二、Workspace v2 与持久化

每个用户、每个会话拥有独立工作区：

```text
WorkDir/v2/
├── blobs/{sha256}/source
└── sessions/
    ├── u{user_id}/{session_id}/
    └── cli/{session_id}/
        ├── input/
        ├── artifacts/{role}/
        ├── reports/
        ├── mission/checkpoint.json
        ├── sessions/{role}/context.jsonl
        ├── .mcp/
        ├── skills/
        └── data/
```

主要特色：

- 用户与会话级物理隔离。
- 上传文件使用 SHA-256 内容寻址 Blob Store，重复文件可复用。
- 工具完整 stdout/stderr 流式写入 Artifacts，模型只接收摘要和尾部。
- 不同 Agent 的上下文按角色分区持久化。
- TTL 只关闭空闲 Workspace 对象，不删除磁盘数据。
- 用户删除会话时先原子移动到内部 Trash，降低误删除风险。
- 安全检查点保存任务阶段、计划项、审批、动作指纹和恢复状态。

## 十三、模型与 API 管理

### 13.1 模型能力

系统支持：

- DeepSeek Chat API。
- DeepSeek Responses API。
- Qwen / llama.cpp OpenAI-compatible API。
- Superadmin 自定义 OpenAI-compatible Provider。
- Chat 与 Responses 两种 API 风格。
- Low、Min、Max 三档推理强度。
- 启动时通过 `/v1/models` 核验 Qwen 实际加载模型并解析唯一别名。

### 13.2 Web 模型管理

超级管理员可以通过 Web 页面统一维护：

- 模型提供商名称与类型。
- Chat 或 Responses API 风格。
- Base URL、API Key 和模型名称。
- Low/Min/Max 对应模型。
- 温度、Top-P、最大 Token、上下文长度和重试次数。
- Embedding Provider、模型、API 地址和向量维度。
- 启用、禁用、添加、修改和删除模型配置。

模型配置由本地注册表统一读取，普通任务页面会同步使用已启用的 Provider。

## 十四、WebUI 与平台功能

### 14.1 技术栈

- React 19
- TypeScript 5.9
- Vite 7
- React Router
- React Markdown + Remark GFM
- Radix UI Dialog
- Lucide React Icons
- Sonner 通知
- FastAPI + SSE

### 14.2 核心页面功能

- 登录、注册和 JWT 会话。
- 多用户任务隔离。
- 新建任务、可调整目标文本框和多文件上传。
- 会话列表分页与懒加载。
- SSE 实时展示消息、推理、工具调用和状态事件。
- Markdown 边流式输出边格式化。
- 用户消息气泡和未发送消息队列。
- 自动滚动总开关与工具历史自动滚动。
- 任务停止、再次攻击、历史会话恢复和会话删除。
- 人工审批弹窗、攻击方案选择和优先级调整。
- 本地知识库搜索与索引重建。
- 任务态势、智能体活动、工具调用历史、作战计划四宫格。
- PDF 报告下载。
- 深色、亮色和液态玻璃三种主题。
- 桌面、平板和移动端响应式布局。

### 14.3 信息可视化

前端不会把所有数据混成单一文本，而是按事件类型展示：

- Agent 消息卡片。
- 用户输入气泡。
- 可折叠推理过程。
- 居中的工具调用提示。
- 工具名称、参数、结果、耗时和状态历史。
- 专家接入提示与动态专家名册。
- 阶段迁移、审批完成和系统文本提示。
- 作战计划状态与完成证据。
- 当前模型名称与 Low/Min/Max 强度。

## 十五、报告与交付

Summary Agent 在任务结束后读取完整会话和 MissionState，生成中文 Markdown 总结，再由 ReportLab 转换为 PDF。

PDF 支持：

- Markdown 标题、段落、粗体、斜体和行内代码。
- 有序/无序列表。
- Markdown 表格。
- 引用块和代码块。
- 中文自动换行。
- 微软雅黑常规/粗体字体；字体不可用时回退中文 CID 字体。
- 红、黑、白项目视觉风格。
- 页眉、页脚和页码。
- 临时文件＋原子替换，避免生成半份报告。

报告内容包括执行摘要、阶段时间线、Agent 活动、审批方案、工具调用、已验证事实、失败尝试、证据、攻击链、风险和建议。

## 十六、NSSCTF Agent Arena 集成

项目包含 NSSCTF Agent Arena Skill 与自动化工作台，能够：

- 使用 Agent Token 领取随机题目。
- 读取题面、附件和容器信息。
- 将附件上传到灵枢会话。
- 启动智能体自动分析。
- 提交 Flag 并记录正确性与剩余错误次数。
- Flag 正确时确定性完成任务，不依赖模型再次调用结束工具。
- 记录冷却时间、rating 和任务结果。

## 十七、项目优势与特色

### 17.1 多智能体不是简单角色扮演

每个 Agent 都有独立的工具、提示词、上下文、状态和权限，Agent 之间通过真实异步调用传递报告，而不是在同一段 Prompt 中模拟多人对话。

### 17.2 “安全治理”与“自动执行”并重

灵枢没有把安全性仅交给提示词，而是通过状态机、范围注册表、审批闸门、工具权限、JSON Schema、路径校验、进程清理和审计哈希链形成确定性约束。

### 17.3 端到端闭环

系统覆盖任务创建、文件上传、自动分类、计划、执行、插话、审批、证据、恢复、总结、PDF 和长期记忆，不只是一个命令执行 Demo。

### 17.4 专业工具链融合

同一任务中可以根据证据在 WebShell 管理、CVE 情报、OCR、密码学解码、ELF 静态分析、IDA 反编译和 GDB 动态调试之间切换。

### 17.5 动态技能路由

121 个扩展 Skill 不会一次性污染上下文。系统先分类，再加载最相关的专业知识，使模型既有广度又保持上下文聚焦。

### 17.6 可解释、可审计、可复现

评审者可以从 UI 或持久化文件中查看：为什么选择某条路径、谁发起了工具调用、用户批准了哪个方案、证据是什么、状态如何迁移、失败是否触发熔断。

### 17.7 面向真实长任务优化

项目针对长会话做了 SSE 流式聚合、前端批量渲染、会话懒加载、Agent 上下文卸载、工具输出 Artifact 化、用户插话取消和安全检查点恢复。

## 十八、适合评比展示的演示流程

建议用一个包含网络目标或附件的综合任务进行演示：

1. 登录 WebUI，新建任务并上传多个附件。
2. 展示自动题型分类和 Sophia 的结构化作战计划。
3. 展示 Ethan/Iris 的侦察证据以及右侧四宫格态势。
4. 在 Agent 工作时发送一条补充情报，展示取消与队列响应。
5. 展示 Alex 生成 2～3 个攻击方案和人工审批弹窗。
6. Web 任务展示 Mike 调用 AntSword；逆向任务展示 Ryan 调用 IDA/GDB。
7. 展开工具历史，查看格式化参数、结果和审计状态。
8. 展示计划项根据证据从 pending 变为 completed。
9. 完成任务后下载微软雅黑排版的 PDF 报告。
10. 打开知识库，检索本次任务沉淀的长期经验。
11. 进入 Superadmin，展示用户和模型 Provider 的统一管理。
12. 切换深色、亮色和液态玻璃主题，展示移动端响应式布局。

## 十九、量化指标摘要

| 指标 | 当前规模 |
|---|---:|
| 业务 Agent 类型 | 9 类 |
| Attack 专家人格 | 9 种以上 |
| 核心 CTF Skills | 11 组 |
| CyberPenda 扩展 Skills | 121 个 |
| AntSword MCP 工具 | 37 个 |
| GDB MCP | 多会话动态调试工具集 |
| IDA MCP | 静态逆向与反编译工具集 |
| 状态阶段 | 7 个终/非终态阶段 |
| Web 主题 | 深色、亮色、液态玻璃 3 种 |
| 使用入口 | CLI、WebUI、Agent Service |
| 持久化层 | SQLite、JSON、Milvus Lite、Workspace Artifacts |

## 二十、当前工程状态与后续路线

### 20.1 已完成

- AgentScope 2.0.6 多智能体主链路。
- React/Vite WebUI 与多用户系统。
- Workspace v2 会话隔离和检查点恢复。
- 人工审批、多方案选择与动态范围审核。
- RAG、长期记忆和本地知识库 UI。
- Summary Agent 与格式化 PDF。
- AntSword MCP 接入 Attack。
- IDA/GDB MCP 接入 Reverse。
- OCR、TonyEnc、IntelPwn 和 CVE 工具。
- 超级管理员用户与模型 Provider 管理。

### 20.2 当前需要优先修复的已知回归

团队最近修改 `LLM/model.py` 时移除了 Qwen 专用模型适配层，导致以下契约暂时失效：

- `chat_template_kwargs.enable_thinking` 未按 Low/Min/Max 正确传递。
- 工具调用未强制关闭 thinking。
- 工具调用温度未固定为 0.1。
- llama.cpp `repeat_penalty` 未接通。
- Qwen 专项测试目前有 4 项失败。

该问题不影响项目整体架构介绍，但在正式演示 Qwen 前应恢复 `QwenChatModel` 适配层并重新执行完整测试。

### 20.3 建议演进方向

1. 恢复并稳定 Qwen/llama.cpp 工具调用契约。
2. 为 AntSword 的 shell_id 与授权目标增加更强的服务端确定性绑定。
3. 建立 CI，自动执行 Python、WebUI、MCP 和 Qwen 契约测试。
4. 为所有外部 MCP 增加健康检查、熔断和可观测指标。
5. 将长期记忆引入质量评分、去重和人工确认流程。
6. 增加任务回放页面和审计哈希链验证入口。
7. 建立标准评测集，统计成功率、平均步骤、Token 成本和误报率。

## 二十一、总结

灵枢的核心价值不只在于“让 AI 自动做安全测试”，而在于建立了一套可治理的多智能体协作范式：

- 用专业 Agent 分工替代单模型包办。
- 用 Orchestrator 和状态机统一决策。
- 用人工审批和范围审核控制风险。
- 用工具、MCP 和 Skills 扩展专业能力。
- 用 Workspace、检查点和长期记忆支持长任务。
- 用审计哈希链、Artifacts 和 PDF 形成完整证据闭环。
- 用 React WebUI 将复杂智能体过程转化为可理解、可操作、可展示的系统。

因此，灵枢既是一个授权安全测试智能体项目，也是一套可以扩展到数字取证、代码审计、CTF 竞赛、应急响应和安全研究场景的多智能体工程平台。

