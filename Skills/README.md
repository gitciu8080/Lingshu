# Skills 技能库索引

灵枢的安全技能库。本文件是全库唯一索引：结构、运行时挂载、重复与去重记录。
**新增技能前先读本文**——确认主题未被覆盖、入口不与现有路由冲突。

## 顶级结构

| 目录 | 体积 | 内容 |
|------|------|------|
| ctf-skills/ | ~2.7M | 10 个 CTF 题型技能（web/pwn/reverse/crypto/forensics/misc/osint/ai-ml/malware/writeup）+ 工具安装脚本 |
| cyberpenda-bundles/ | ~7M | 121 个上游 bundle（逆向族/pentest 方法论/CTF 工作流/单工具速查），完整快照见 UPSTREAM.md |
| pentest-report-template/ | 52K | 渗透报告模板（Summary Agent 消费） |
| cve-search/ | 44K | CVE 多源聚合查询（包装为 Agent 工具） |
| beautiful-mermaid/ | ~2M | Mermaid 渲染器（报告链路运行时依赖，**恢复见 INSTALL.md**） |

## 运行时挂载（agent/Attack.py 两张映射表，改动需同步此处）

- **ctf-skills（按题型主挂载）**：web→ctf-web、pwn→ctf-pwn、reverse→ctf-reverse、
  crypto→ctf-crypto、forensics→ctf-forensics、malware→ctf-malware、misc→ctf-misc、
  osint→ctf-osint、ai-ml→ctf-ai-ml、writeup→ctf-writeup
- **cyberpenda（按题型附加）**：web→[api-security, pentest-tools]、pwn→[pwn-chain]、
  reverse→[reverse-skill-router, ~~reverse-engineering~~]（2026-10-29 移除，与 ctf-reverse
  逐字级重复）、crypto/misc→[ctf-sandbox-orchestrator]、forensics→[digital-forensics]、
  malware→[malware-analysis]、osint→[pentest-tools]、ai-ml→[llm-security]；
  attack-chain 无条件附加
- **未挂载的 bundle（约 110 个）**：完整快照保留备用。其中 vulnerabilities-\*（22 个
  pentest 方法论）、tooling-\*（9 个单工具速查）、competition-\*（40 个，被
  ctf-sandbox-orchestrator 文档引用）为主题互补资料，需要时在映射表加一行即可挂载。
  注意：技能内部路由文档引用的 bundle 若未挂载，运行时 LLM 读不到（悬空引用）。

## 去重记录（2026-10-29）

- **精确重复：0**（580 个 md 全量 md5 比对）
- **删除**：ctf-skills 上游社区残留（CONTRIBUTING/CODE_OF_CONDUCT/SECURITY/pyproject/
  上游 tests/生成器）、solve-challenge（幽灵入口，与 ctf-sandbox-orchestrator 冲突且
  代码按题型直接路由不消费）、reverse-skill-router/{field-journal,ops,CONTRIBUTING}
  （上游作者个人笔记）、diagram-generator/README.md（冗余）、beautiful-mermaid 的
  node_modules 与 .git（110M，恢复见 INSTALL.md）
- **移出**：agentscope-tutorial → docs/（非安全技能）
- **触发词消歧**：docs-generator 移除 "writeup" 触发词（归 ctf-writeup）；
  diagram-generator 标注 Mermaid 渲染交由 beautiful-mermaid

## 已知主题重叠（保留理由）

SQLi/XSS/SSRF/JWT 等主题在 ctf-web（CTF 实战案例）、vulnerabilities-\*（pentest
方法论）、pentest-tools/src-hunter（payload+工具速查）各有 2-5 份覆盖——**角度互补
非重复**：解题找 ctf-web，渗透评估找 vulnerabilities-\*，要 payload 查 src-hunter。
逆向族注意：ida-reverse/ghidra-reverse/radare2 为三套工具入口（按可用工具选择），
apk-reverse 与 mobile-reverse 的 Android 面有重叠。

## 入口约定（唯一）

- CTF 题型：系统按分类直接挂载对应 ctf-\*（无总分发入口；原 solve-challenge 已删）
- cyberpenda 族：ctf-sandbox-orchestrator；逆向族：reverse-skill-router
- 报告：pentest-report-template（Summary Agent）；图形：beautiful-mermaid
