# 04 · 技术特点与 TOOLS / SKILLS

> 本文覆盖：项目创新点、特色、特长、技术要点、完整工具清单（含 MCP）、技能库清单、模型与运行配置。
> 概述性论述另见 `docs/Lingshu项目汇报与介绍.md` 与 `docs/专题/核心技术特点.md`；本文以清单 + 代码落点为主。

## 1. 项目创新点（Top 5）

1. **把"攻击决策"压缩进受控工具调用**：Orchestrator 的 `dispatch_*`、审批、扩容、计划、收尾全部是工具函数，攻击的关键决策点（何时进 EXPLOITATION、能否重复执行、能否打未授权 IP）由**确定性代码**裁决而非模型自由文本（`agent/Orchestrator.py:652-666`；[03-幻觉抑制方案](03-幻觉抑制方案.md)）。
2. **动作指纹 + 熔断的循环收敛**：以 `SHA-256(工具|目标|规范化参数|目标描述|证据版本)` 识别"换措辞重试"，相同动作+相同错误累计 2 次自动熔断并封禁计划项（`Tools/fingerprint.py:33-48, 59-87`）——这是安全任务中防止 Agent 无限空转/谎报进展的独创机制。
3. **题型驱动的动态专家路由**：一次任务只产生一个正式题型决策（`agent/categorize.py` 评分制、单一事实来源），据此动态选择 Attack 人设（`agent/experts.py:14-24`）与 Skill 目录（`agent/Attack.py:173-226`），让通用 LLM 变成"本次任务的领域专家"。
4. **外部专业工具的受控接入**：AntSword（WebShell）/ IDA（静态逆向）/ GDB（动态调试）三个 MCP 全部以"包装器 + 只读白名单 + 危险入口封禁 + 审批实时联动"方式接入（`agent/Attack.py:148-169`、`agent/Reserve.py:66-88, 271-362`），既获得专业能力又不放开安全边界。
5. **崩溃恢复与确定性终态**：checkpoint 序列 + 审计哈希链 + `resume_status`（fresh/running/resumable/uncertain/terminal）让任务可以在任意中断点恢复且**不重复询问审批、不重放终态、不确定动作禁止自动重放**（`main.py:658-692`、`TaskState.py:168-185`）。

## 2. 项目特色

| 特色 | 说明 | 代码落点 |
|------|------|----------|
| 全程中文人设与界面 | 系统提示词、日志、交互、报告均为中文，Agent 有人格名（Sophia/Alex/Ethan…） | `agent/experts.py:6-12` |
| 人机协同审批 | 首次攻击前三档方案人工选择 + 优先级可调，CLI 与 Web 双通道 | `main.py:320-444` |
| 动态授权范围 | 初始目标 + DNS 解析注册，内网 IP 扩容需 ScopeAuditor 证据审核 | `Tools/ScopeRegistry.py` |
| 双目标路由 | network（网络侦察）与 archive/file（安全解压+文件 triage）两条不同权限模型 | `agent/Recon.py`、`main.py:447-455` |
| NSSCTF 竞技场集成 | 在线提交 Flag、正确立即终态、剩余错误次数回传 | `agent/Orchestrator.py:568-649` |
| 用户插话（steering） | 运行中随时中断子 Agent、注入新指令，官方中断机制 | `Tools/tooling.py:234-245`、`main.py:821-838` |
| Workspace v2 会话隔离 | 用户/会话级物理隔离 + blob 去重 + 工具输出 artifact 化 | `workspace_service.py`、`Tools/tooling.py:625-690` |

## 3. 技术要点（速查）

### 3.1 多智能体框架层
- 基于 AgentScope 2.x：`Agent` + `ReActConfig(max_iters)` + `Toolkit` + `ContextConfig` + `AgentState` 角色分区 offload（`agent/context.py:83-85`）；
- 全异步：`asyncio` 贯穿，`run_interruptible_agent_reply` 把嵌套子 Agent 调用登记为可取消 task（`Tools/tooling.py:262-287`）；
- 官方中断机制：`task.cancel()` 承载 reply_stream，INTERRUPTED 还原为 `CancelledError` 向上传播（`Tools/tooling.py:431-456`）。

### 3.2 状态与持久化层
- 状态机 + 合法迁移白名单（`TaskState.py:66-106`）；
- 审计 SHA-256 前向哈希链（`TaskState.py:187-208`）；
- 原子写入（tempfile + fsync + os.replace）（`TaskState.py:298-315`）；
- schema 版本迁移 v1→v3，缺字段自动补齐（`TaskState.py:261-269, 352-360`）。

### 3.3 安全治理层
- scoped_shell 三重校验（破坏性黑名单 / IP 白名单 / 网络工具目标检查）（`Tools/tooling.py:497-503, 530-581`）；
- StrictJSONToolkit 严格 JSON + schema 双失败熔断（`Tools/tooling.py:71-152`）；
- 审批闸门双保险 + MCP 实时联动（`agent/Orchestrator.py:216-227`、`agent/Attack.py:148-169`）。

### 3.4 上下文与记忆层
- 统一 ContextConfig + 自定义 SUMMARY_SCHEMA 保恢复语义（`agent/context.py:18-70`）；
- AgenticMemory 热/冷两级记忆，冷记忆脱敏归档（`Tools/AgenticMemory.py:29-37, 55-87`）；
- RAG 只作线索、不作事实（`agent/Attack.py:79-81`）。

### 3.5 模型层（LLM/model.py）
- DeepSeek V4 Flash/Pro 走 **OpenAI Responses API**，`reasoning_effort` 映射思考级别（Low=low/Min=high/Max=max），`web_search` 服务端联网搜索开关（`LLM/model.py:119-204, 276-302`）；
- `DeepSeekResponseFormatter` 自动补 `reasoning_item_id` 防 Responses API 400（`LLM/model.py:93-116`）；
- Qwen 走 llama.cpp OpenAI 兼容接口，`/v1/models` 别名解析（零/多模型拒绝启动防不可审计路由）（`LLM/model.py:37-79`）；
- `RuntimeConfig` 支持 DeepSeek / Qwen / Superadmin 注册的自定义 Provider（`config.py:52-169`）。

---

## 4. TOOLS 清单

### 4.1 自研基础工具（Tools/ 目录）

| 工具 | 文件 | 说明 |
|------|------|------|
| `scoped_shell` | `Tools/tooling.py:583-767` | 范围约束命令执行（黑名单/IP 白名单/目标检查/超时进程组清理/artifacts 落盘） |
| `AddPlan` | `Tools/Plan.py:63-122` | 追加计划项（completed 强制 evidence） |
| `SubmitPlan` | `Tools/Plan.py:125-227` | Brain 批量原子提交 4~8 条计划 |
| `UpdatePlan` / `DeletePlan` / `ListPlan` | `Tools/Plan.py:230-322` | 计划维护/删除/查看 |
| `request_exploitation_approval` | `agent/Orchestrator.py:332-450` | 攻击阶段人工审批 |
| `request_scope_expansion` | `agent/Orchestrator.py:452-528` | 授权范围扩容（ScopeAuditor 审核） |
| `dispatch_recon/attack/reverse` | `agent/Orchestrator.py:114-330` | 派遣子 Agent |
| `complete_mission` | `agent/Orchestrator.py:534-566` | 终态收尾 + 写长期记忆 |
| `submit_nss_flag` | `agent/Orchestrator.py:568-649` | NSSCTF 在线校验 Flag |
| `QueryMemory` | `Tools/AgenticMemory.py:245-261` | 查询历史攻击经验 |
| `cve_search` | `Tools/CVE_Search.py` | CVE 情报查询（调 Skills/cve-search 脚本） |
| `ocr_image` | `Tools/OCR.py` | Tesseract 图片文字识别 |
| `tonydec` | `Tools/TonyDec.py` | TonyEnc 文件头（`6688ff4f...`）解码 |
| `intelpwn_analyze` | `Tools/IntelPwn.py` | 静态二进制漏洞分析 |
| `analysis` | `agent/Attack.py:259-271`、`agent/Reserve.py:131-143` | 委托 Analysis 研判（工具化） |
| `ida_open_binary` / `gdb_create_session` / `gdb_load_core` | `agent/Reserve.py:271-362` | IDA/GDB 会话受控包装器 |

### 4.2 MCP 工具集

| MCP | 接入方 | 工具数与权限模型 | 代码落点 |
|-----|--------|------------------|----------|
| AntSword_Tool（WebShell 管理） | Attack | 37 工具；只读集放行，写/执行逐次联动 `exploitation_approved` | `agent/Attack.py:30-49, 115-170` |
| IDA_Tool（静态逆向） | Reserve | 45 个只读白名单工具（含会话生命周期） | `agent/Reserve.py:66-77, 152-180` |
| GDB_Tool（动态调试） | Reserve | 会话工具暴露，危险入口（attach/connect_target/load_core/create_session/rr_record）封禁 | `agent/Reserve.py:79-88, 235-245` |

### 4.3 工具注册机制
- 自研工具统一经 `AllowedFunctionTool`（`Tools/tooling.py:468-475`）：`check_permissions` 恒 ALLOW——**因为校验已在函数内部完成**，绕过 AgentScope 默认 ASK 流程；
- MCP 工具单独设置 `is_read_only` 与 `check_permissions`（`agent/Attack.py:144-169`、`agent/Reserve.py:172-173, 244-245`）；
- 全部工具参数过 `StrictJSONToolkit` 严格闸门（[03 第 8.3 节](03-幻觉抑制方案.md)）。

---

## 5. SKILLS 清单（Skills/ 目录）

### 5.1 ctf-skills（题型技能库，运行时按分类动态加载）
`ctf-web / ctf-pwn / ctf-reverse / ctf-crypto / ctf-forensics / ctf-malware / ctf-misc / ctf-osint / ctf-ai-ml / ctf-writeup`（各含 `SKILL.md` + 知识库 md + scripts + tests）。映射见 `agent/Attack.py:88-99`。

### 5.2 cve-search
`SKILL.md` + `scripts/cve_search.py`（MITRE 查询，被 `Tools/CVE_Search.py` 以子进程方式调用）。

### 5.3 cyberpenda-bundles（120+ 扩展 bundle）
运行时**只加载与当前题型相关的目录**（`agent/Attack.py:101-111, 218-225`）。分类如下：

| 类别 | 示例 |
|------|------|
| 题型链 | `attack-chain`、`pwn-chain`、`reverse-skill-router`、`ctf-sandbox-orchestrator`、`reverse-engineering`、`digital-forensics`、`malware-analysis`、`llm-security`、`pentest-tools`、`api-security` |
| 漏洞专题 | `vulnerabilities-sql-injection`、`vulnerabilities-ssrf`、`vulnerabilities-ssti`、`vulnerabilities-rce`、`vulnerabilities-race-conditions`、`vulnerabilities-http-request-smuggling`、`vulnerabilities-authentication-jwt`、`vulnerabilities-insecure-file-uploads` 等 20+ |
| 工具手册 | `tooling-nmap`、`tooling-ffuf`、`tooling-sqlmap`、`tooling-nuclei`、`tooling-httpx`、`tooling-subfinder`、`tooling-semgrep` 等 10+ |
| 竞赛技巧 | `competition-*` 系列（pivot/凭证链/云元数据/内核容器逃逸/SSRF 跳板/OAuth 链等 40+） |
| 逆向专项 | `ida-reverse`、`ghidra-reverse`、`radare2`、`js-reverse`、`go-rust-reverse`、`apk-reverse`、`mobile-reverse`、`patch-diff-exploit`、`edr-bypass-re` 等 |
| 技术栈/框架 | `frameworks-fastapi/nestjs/nextjs`、`technologies-firebase-firestore/supabase`、`protocols-graphql`、`cloud-k8s`、`windows-ad`、`wifi-wireless`、`ot-ics`、`radio-sdr`、`thick-client` 等 |
| 辅助 | `browser-automation`、`diagram-generator`、`docs-generator`、`scoreboard-driven-web-challenge`、`coordination-source-aware-whitebox`、`custom-source-aware-sast`、`nssctf-agent-arena` |

### 5.4 agentscope-tutorial
AgentScope 2.0 多智能体框架完整教程（`Skills/agentscope-tutorial/SKILL.md`）。

---

## 6. 运行配置速查

| 项 | 默认 | 说明 |
|----|------|------|
| `DEEPSEEK_API_KEY` | —（必填） | DeepSeek API Key |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | 可换私有网关 |
| `DEEPSEEK_MODEL_LOW/MIN/MAX` | `deepseek-v4-flash/flash/pro` | 思考级别对应模型 |
| `DEEPSEEK_WEB_SEARCH` | `0` | Responses API 服务端联网搜索 |
| `QWEN_BASE_URL` / `QWEN_MODEL` | llama.cpp 本地地址 | Qwen OpenAI 兼容接口 |
| `QWEN_TOOL_CALL_MODE` | `simple` | simple=扁平逐条 / standard=批量嵌套 |
| `QWEN_REPEAT_PENALTY` | `1.08` | llama.cpp 重复惩罚（>1.2 仅告警不篡改） |
| `LINGSHU_COMMAND_TIMEOUT` | `300` | scoped_shell 命令超时（10~600s） |
| `LINGSHU_WORKSPACE_MODE` | `local` | local=Workspace v2 隔离 / legacy=全局 WorkDir |
| `LINGSHU_ANTSWORD_MCP_URL` | `http://127.0.0.1:30080/sse` | AntSword MCP 地址 |
| `LINGSHU_GDB_MCP_COMMAND` | `uvx` | GDB MCP 启动器 |
| `LINGSHU_EMBEDDING_*` | 空 | RAG embedding（未配置时知识库降级） |

CLI：`python main.py -t <IP/文件> -g "获取 Flag" -m Min -p deepseek`（参数见 `main.py:1329-1364`）。

## 7. 测试资产

`tests/` 下 24 个测试文件覆盖：状态机 v3、审计链、checkpoints、resume、scoped_shell v2、workspace 隔离/模式/工具、Agent 上下文、AgenticMemory 归档、AntSword MCP 契约、GDB MCP 配置、模型注册表、Qwen 契约、TonyDec、会话存储等（`tests/`）。当前无自动化测试框架集成命令，直接以 `pytest`/`python -m pytest tests/` 运行。
