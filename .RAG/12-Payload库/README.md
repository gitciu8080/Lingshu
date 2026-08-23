# Payload 库(导入自旧智能体知识库)

> 关键词:Payload,攻击载荷,反弹shell,reverse-shell,SQL注入,sqli,XSS,SSRF,XXE,LFI,RCE,上传,格式混淆,提示注入,prompt injection,CORS,HPP,Access-Bypass
> 本模块内容整合自旧智能体知识库 `G:\WorkDir\.RAG.old\Payload\`,保留原始目录结构与文件。

## 来源说明

- 原目录:旧知识库 `Payload/`(88 个文件)
- 文件类型:以 `.txt` 为主(可直接用于 Burp/脚本的载荷清单),另有 `.md` 说明、`.html` PoC、`.yaml` 元数据等
- 适配:原样复制,未改动内容;`.md` 文件为技术说明,`.txt` 为载荷列表

## 目录导航

| 目录 | 内容 |
| --- | --- |
| `access-bypass/` | 403/访问控制绕过载荷(`xff-403.txt` 等) |
| `cors/` | CORS 配置错误检测 PoC(HTML + 说明) |
| `email/` | 邮件相关载荷 |
| `format/` | 格式混淆:hex/int/json/nullbyte/string 变体 |
| `hpp/` | HTTP 参数污染(HPP)载荷 |
| `lfi/` | 本地文件包含:Linux/Windows 路径、Java properties、日志投毒 |
| `prompt-injection/` | **提示注入(Prompt Injection)载荷全集**(AI 安全场景) |
| `rce/` | 命令执行:Java/PHP/PowerShell/Unix/Windows |
| `reverse-shell/` | 反弹 Shell 大全:bash/nc/socat/python/powershell 等 |
| `sqli/` | SQL 注入载荷 |
| `ssi/` | SSI(Server Side Include)注入 |
| `ssrf/` | SSRF 载荷 |
| `upload/` | 上传绕过:后缀/MIME/.htaccess |
| `xss/` | XSS 载荷 |
| `xxe/` | XXE 载荷 |

## 使用建议(RAG)

- 检索"反弹 shell 怎么写" → `reverse-shell/`
- 检索"某类注入的 payload" → 对应目录
- 每个目录内 `_meta.yaml` 为元数据描述,`*.md` 为用法说明,`*.txt` 为可直接复制的载荷
- 与 `01-渗透测试/`、`10-漏洞与框架知识/`、`11-CVE漏洞库/` 联动使用

## 合规声明

载荷仅用于授权渗透测试、CTF 与靶场;未授权使用属违法行为。
