# Web安全加固

> 关键词:Web安全,Nginx加固,Apache加固,Tomcat加固,安全响应头,HSTS,CSP,X-Frame-Options,HTTPS,TLS配置,禁用弱协议,WAF,SQL注入,XSS,CSRF,文件上传,越权,输入校验,参数化查询,组件版本管理,运维安全

## 加固范围

Web 安全加固覆盖四层:Web 服务器(Nginx/Apache/Tomcat)、传输层(TLS/HTTPS)、应用层(WAF+代码防护)、运维层(后台/错误页/备份文件)。四层缺一不可——服务器配置再安全,应用存在 SQL 注入同样会被攻破。

## Web 服务器加固

### Nginx 配置安全

`/etc/nginx/nginx.conf` 关键配置:

```nginx
http {
    server_tokens off;                          # 隐藏版本号
    # 安全响应头(见下文"安全响应头"节)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    # 请求体与超时限制
    client_max_body_size 10m;                   # 上传大小上限
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 65;
}

server {
    listen 443 ssl;
    server_name www.example.com;
    autoindex off;                              # 关闭目录列表
    # 限制请求方法(仅 GET/POST/HEAD/OPTIONS)
    if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }
    # 禁止访问隐藏文件与敏感目录
    location ~ /\. { deny all; }                # .git/.svn/.env 等
    location ~* \.(bak|conf|sql|sh|log|old|swp|~)$ { deny all; }
    # 管理后台按来源限制
    location /admin/ { allow 10.0.0.0/8; deny all; }
    # 静态资源目录:只读、不执行
    location /static/ { expires 7d; }
}
```

要点:`server_tokens off` 隐藏 Nginx 版本;`autoindex off` 关闭目录列表;屏蔽 `.git/.svn/.env/backup` 等敏感路径;静态目录禁执行(`fastcgi` 不指向静态 location)。

### Apache 配置安全

`httpd.conf` / 虚拟主机:

```apache
ServerTokens Prod
ServerSignature Off
# 目录列表关闭
<Directory /var/www/html>
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
# 限制请求方法
<LimitExcept GET POST HEAD OPTIONS>
    Require all denied
</LimitExcept>
# 隐藏文件与备份文件禁止访问
<DirectoryMatch "^/.*/\.(?!well-known)">
    Require all denied
</DirectoryMatch>
<FilesMatch "\.(bak|conf|sql|sh|log|old|~)$">
    Require all denied
</FilesMatch>
# 上传大小与超时
LimitRequestBody 10485760
Timeout 60
```

危险/非必要模块:mod_status、mod_info、mod_userdir、mod_autoindex(如无需列表)、CGI(如无需)应注释加载;必须开启 status/info 时用 `Require ip 10.0.0.0/8` 限来源。

### Tomcat 配置安全

`conf/server.xml` 与 `conf/web.xml`:

```xml
<!-- 1) 移除默认示例应用:webapps/examples、docs、默认 ROOT -->
<!-- 2) 管理应用 /manager /host-manager 删除或强认证+IP 限制 -->
<!-- 3) Connector 限制 -->
<Connector port="8080" protocol="HTTP/1.1"
           maxThreads="200" minSpareThreads="25"
           connectionTimeout="20000"
           maxPostSize="10485760"
           disableUploadTimeout="true" />
<!-- 4) AJP 8089:非必要禁用,或限定来源(防 Ghostcat) -->
<!-- 5) web.xml:关闭目录列表、自定义错误页 -->
<init-param>
    <param-name>listings</param-name>
    <param-value>false</param-value>
</init-param>
<error-page>
    <error-code>404</error-code>
    <location>/error/404.html</location>
</error-page>
```

- 修改默认端口;AJP 8009 非必要禁用或限来源(历史 Ghostcat CVE-2020-1938)。
- tomcat 以专用低权限用户运行,禁止 root。
- 高安全场景可在 `CATALINA_OPTS` 启用 `-Djava.security.manager`。

## 安全响应头

在 Web 服务器或网关统一注入(配置示例见 Nginx 节):

| 响应头 | 作用 | 建议值 |
| --- | --- | --- |
| `Strict-Transport-Security` | HSTS,强制浏览器仅用 HTTPS,防降级与中间人 | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | CSP,限制脚本/资源来源,缓解 XSS | `default-src 'self'; script-src 'self'` |
| `X-Frame-Options` | 防点击劫持/iframe 嵌套 | `SAMEORIGIN`(新标准用 CSP frame-ancestors) |
| `X-Content-Type-Options` | 禁止 MIME 嗅探 | `nosniff` |
| `Referrer-Policy` | 控制 Referer 泄露 | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | 限制浏览器 API(摄像头/麦克风/定位) | `camera=(), microphone=(), geolocation=()` |
| `X-XSS-Protection` | 旧浏览器 XSS 过滤器(新标准由 CSP 取代) | `1; mode=block`(兼容旧浏览器) |

CSP 上线建议:先用 `Content-Security-Policy-Report-Only` 模式收集违规再切换 enforce,避免误伤业务脚本。

## HTTPS 强制与 TLS 配置

### 强制 HTTPS

- 全站 301 跳转 HTTP→HTTPS;HSTS 设置 `max-age` 并逐步加 `includeSubDomains`。
- 证书:使用受信任 CA(Let's Encrypt 或商业证书),配置自动续期(certbot / acme.sh);内网可部署私有 CA,但客户端需信任根证书。

### 禁用弱协议与弱套件

原则:**仅 TLS 1.2/1.3**,禁用 SSLv2/SSLv3/TLS 1.0/1.1;禁用 RC4、DES、3DES、MD5、SHA1 签名;启用前向保密(ECDHE)。

Nginx 示例:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_stapling on;
ssl_stapling_verify on;
ssl_dhparam /etc/nginx/dhparam.pem;   # 2048 位以上 DH 参数
```

Apache 示例:

```apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder off
```

验证工具:

```
openssl s_client -connect www.example.com:443 -tls1_2
nmap --script ssl-enum-ciphers -p 443 www.example.com
# 在线检测:SSL Labs、myssl.com
```

## WAF 部署与规则

- **部署形态**:云 WAF(阿里云/腾讯云等)、硬件 WAF(绿盟/安恒等)、开源 WAF(ModSecurity+OWASP CRS、NAXSI)、软件 WAF(OpenResty/nginx + lua)。
- **核心防护**:SQL 注入、XSS、命令注入、路径遍历、恶意爬虫、CC 攻击、扫描器识别。
- **规则管理流程**:

```
1) 先"观察/日志"模式运行 1~2 周,收集误报与业务基线;
2) 再切换"拦截"模式,对注入类高危规则直接拦截;
3) 业务接口加白名单,但白名单须精确到 URI+参数,避免整站绕过;
4) 定期更新规则库(CRS 版本、云 WAF 规则),与补丁节奏同步;
5) 旁路(镜像流量分析)与串联(阻断)部署按业务容忍度选择,关键系统用串联。
```

- ModSecurity 接入示例(Nginx):

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
# main.conf 中加载 OWASP CRS
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
```

- 注意:WAF 不是万能,绕过根因通常是应用自身缺陷;WAF 只能兜底,必须与代码修复并行。

## 应用层防护要点

| 风险 | 防护措施 |
| --- | --- |
| SQL 注入 | 参数化查询/预编译(PreparedStatement、ORM);禁止拼接 SQL;应用账号最小数据库权限(无 DDL);WAF 兜底 |
| XSS | 按输出上下文(HTML/JS/URL/JSON)正确编码;CSP;HttpOnly Cookie;富文本白名单过滤 |
| CSRF | 会话绑定的 CSRF Token/双重提交 Cookie;SameSite Cookie;敏感操作二次校验 |
| 文件上传 | 扩展名+MIME 双白名单;随机重命名存储;存储目录不可执行;病毒扫描;限制大小与并发 |
| 越权(IDOR) | 服务端校验资源归属(当前用户与资源 owner 比对);覆盖水平/垂直越权测试用例 |
| 命令注入 | 禁止拼接系统命令;参数白名单;最小化 shell 权限 |
| SSRF | 服务端 URL 白名单;禁止访问内网地址段;限制重定向跟随 |
| 敏感信息泄露 | 错误页脱敏;接口不返回堆栈/版本;去掉 Server 版本头 |

## 框架与组件版本管理

- 建立组件清单(SBOM):记录框架、依赖库、运行时版本,并与 CVE 数据库比对。
- 依赖扫描:SAST/SCA 工具(Dependency-Check、Trivy、Snyk、OWASP Dependency-Track)集成 CI,高危依赖阻断上线。
- 升级策略:语言框架(Spring/Struts、ThinkPHP、Laravel、Django、Express)与中间件(Nginx/Apache/Tomcat/OpenResty)保持最新稳定版;高危 CVE 走紧急补丁流程(见《补丁与配置管理.md》)。
- 重点关注历史高危组件:Struts2、Fastjson、Log4j2、WebLogic、Shiro、Confluence 等,上线前必须核对版本与已知漏洞。

## 开发安全(DevSecOps)

- **输入校验**:所有外部输入(参数、Header、Cookie、文件)在服务端校验类型、长度、格式、取值范围;白名单优先。
- **参数化查询**:所有数据库操作使用预编译/ORM,严禁字符串拼接 SQL。
- **CSRF Token**:状态变更请求(登录、改密、转账、删除)必须携带 Token 并服务端校验。
- **输出编码**:按输出上下文(HTML 属性、JS、URL、JSON)选择正确编码函数,防止 XSS。
- **认证与会话**:密码加盐哈希(Argon2/bcrypt);会话 ID 随机且 Cookie 设 HttpOnly+Secure+SameSite;登录失败限速;会话超时与失效。
- **安全测试**:上线前执行 SAST(静态)、DAST(动态)、依赖扫描与人工渗透;高风险系统上线前必须渗透测试。
- 参考 OWASP Top 10 与 OWASP ASVS 建立开发安全规范,纳入代码评审。

## 运维安全

- **后台保护**:管理后台与生产站分离(独立域名/独立服务器);后台入口限制来源 IP 或 VPN;启用双因素认证;后台路径不公开暴露。
- **错误页面**:自定义 404/500 页面,不输出堆栈、SQL 语句、文件路径、版本号;生产环境关闭调试模式(`APP_DEBUG=false`、`DEBUG=False`)。
- **备份文件防护**:禁止 .bak/.sql/.tar.gz/编辑器临时文件(index.php~、.swp)留在 Web 目录;Web 根目录不存放备份与源码包;备份下载需认证且限来源。
- **目录与文件权限**:Web 目录属主为专用运行账号;上传目录无执行权限;含数据库口令的配置文件权限 600 且不在 Web 根内。
- **日志与监控**:access log 记录完整(含 Referer、UA);服务器/WAF 日志集中收集;对 404 突增、登录爆破、异常上传做告警。
- **发布管理**:走 CI/CD 流水线发布,禁止手工改服务器文件后遗留调试代码;发布后立即清理临时文件与旧版本残留。

## Web 安全加固清单(自查表)

| # | 检查项 | 期望 | 验证方式 |
| --- | --- | --- | --- |
| 1 | 版本隐藏 | 响应无版本号 | curl -I 查看 Server 头 |
| 2 | 目录列表 | 关闭 | curl 访问目录返回 403 |
| 3 | 请求方法 | 仅 GET/POST/HEAD/OPTIONS | curl -X DELETE 应被拒绝 |
| 4 | 危险模块/示例应用 | 已移除 | 检查模块加载与 webapps |
| 5 | 安全响应头 | HSTS/CSP/XFO/XCTO 齐全 | curl -I 核对 |
| 6 | TLS | 仅 1.2/1.3,无弱套件 | openssl s_client / nmap 扫描 |
| 7 | HTTPS 强制 | HTTP 301 跳转+HSTS | curl -I http:// 站点 |
| 8 | WAF | 已启用拦截规则 | 注入测试样本验证 |
| 9 | 组件版本 | 无已知高危 CVE | 依赖扫描报告 |
| 10 | 错误页 | 无堆栈/版本泄露 | 触发 500 观察响应体 |
| 11 | 备份/临时文件 | Web 目录无敏感文件 | 目录扫描 |
| 12 | 上传目录 | 不可执行 | 上传目录权限检查 |
