# 漏洞与框架知识(导入自 SecAtlas)

> 关键词:漏洞知识库,漏洞分类,SQL注入,XSS,SSRF,反序列化,命令注入,请求走私,JWT,OAuth,SSTI,XXE,IDOR,文件包含,国产CMS,OA,ERP,RuoYi,若依,发卡系统,漏洞全集
> 本模块内容由多 Agent 协作维护的 [SecAtlas 中文渗透知识库](https://github.com/shuaiqideyu/SecAtlas)(仓库 `knowledge/` 目录)导入适配而来,供 RAG 检索与实战参考。

## 来源与许可

- **原始仓库**:`https://github.com/shuaiqideyu/SecAtlas`(多 Agent 协作的中文渗透知识库,47 Skills · 38 技术卡 · 框架漏洞全集)
- **导入路径**:原仓库 `knowledge/categories/` 与 `knowledge/frameworks/`
- **适配说明**:为每个文件补充了 `> 关键词:` RAG 检索行;正文内容、条目编号(KB-*)与来源标注保持原样
- **免责声明**:内容含漏洞利用手法与 payload,仅限授权测试与 CTF 场景使用

## 文件导航

### categories/ — 漏洞分类知识(18 篇)

| 文件 | 主题 | 关键词 |
| --- | --- | --- |
| `sqli.md` | SQL 注入技术(UNION/报错/布尔盲注/时间盲注/OOB/二阶/WAF 绕过) | SQL注入、盲注、WAF绕过 |
| `xss.md` | 跨站脚本(反射/存储/DOM/绕过) | XSS、跨站脚本 |
| `ssrf.md` | 服务端请求伪造与 URL 操纵 | SSRF、内网探测 |
| `ssti.md` | 模板注入(Jinja2/Twig/Freemarker 等) | SSTI、模板注入 |
| `command-injection.md` | 命令注入与 OS 命令执行 | 命令注入、RCE |
| `deserialization.md` | 反序列化攻击(Java/PHP 等利用链) | 反序列化、利用链 |
| `file-inclusion.md` | 文件包含与路径穿越(LFI/RFI) | 文件包含、路径穿越 |
| `request-smuggling.md` | HTTP 请求走私与缓存投毒(CL.TE/TE.CL) | 请求走私、缓存投毒 |
| `jwt.md` | JWT 与 Token 攻击(签名伪造/alg 混淆) | JWT、Token攻击 |
| `oauth.md` | OAuth 2.0 / OIDC 攻击技术 | OAuth、OIDC |
| `acl.md` | 访问控制与权限绕过 | ACL、越权 |
| `idor.md` | 不安全的直接对象引用(水平/垂直越权) | IDOR、越权 |
| `xxe.md` | XXE XML 外部实体注入 | XXE、XML |
| `pwn.md` | 二进制漏洞与利用(栈/堆/格式化字符串) | PWN、二进制漏洞 |
| `blockchain.md` | 区块链充值对账安全 | 区块链、充值对账 |
| `agentic-ai.md` | AI Agent 与 MCP 安全控制闭环 | AI Agent、MCP、提示注入 |
| `misc.md` | 渗透技巧杂项(JS 逆向/万能密码等) | 渗透技巧、MISC |
| `tool-checklist-9phase.md` | 渗透测试九阶段工具速查 | 渗透工具、九阶段 |

### frameworks/ — 国产框架漏洞全集(4 篇)

| 文件 | 主题 |
| --- | --- |
| `chinese-cms-vulnerabilities.md` | 国产 CMS/Web 框架漏洞全集(含指纹与检测) |
| `chinese-oa-erp-vulnerabilities.md` | 国产 OA/ERP 框架漏洞全集(致远/泛微/用友等) |
| `faka-frameworks-vulnerabilities.md` | 国产发卡(卡密售卖)框架漏洞全集 |
| `ruoyi-vulnerabilities-full.md` | RuoYi(若依)框架漏洞全集(Shiro 反序列化/文件上传等,CVE 收录) |

## 与现有模块的关联

- 漏洞分类(categories/)与 `01-渗透测试/Web渗透测试.md`、`01-渗透测试/主机与系统渗透.md` 互补:前者是**技术卡式条目**(信号/原理/最小PoC/绕过/修复),后者是流程化测试方法
- 框架漏洞(frameworks/)可与 `01-渗透测试/信息收集.md`(指纹识别)、`03-安全运维/漏洞管理.md`(CVE 处置)联动
- 修复建议部分可对照 `04-安全维护与加固/` 落地加固措施
- CTF 场景可对照 `09-CTF竞赛/` 相关技巧文档

## 使用建议(RAG)

- 检索"某漏洞如何检测/绕过/修复" → 直接命中对应 `categories/*.md` 条目(KB-* 编号)
- 检索"某某国产系统漏洞" → 命中 `frameworks/*.md`
- 条目中的"最小PoC/绕过与变体/修复"为高价值字段,可作为结构化元数据提取
