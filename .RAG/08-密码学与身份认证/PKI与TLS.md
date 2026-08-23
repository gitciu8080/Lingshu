# PKI与TLS

> 关键词:PKI,公钥基础设施,CA,证书颁发机构,RA,证书库,证书吊销,CRL,OCSP,X.509,证书链,信任模型,根证书,中间CA,DV,OV,EV,CSR,证书生命周期,ACME,Let's Encrypt,TLS,HTTPS,握手,密码套件,证书验证,TLS1.2,TLS1.3,前向保密,mTLS,双向认证,国密,SM2,SM3,SM4,SSL,中间人,证书伪造,降级攻击,POODLE,SSL剥离,sslstrip,openssl

## PKI 概述

**公钥基础设施(PKI,Public Key Infrastructure)**解决"公钥到底属于谁"的问题:通过可信第三方(CA)对公钥及其所有者身份做认证并签发证书,使任何人都能验证"这把公钥确实属于 example.com / 张三"。

### PKI 组成

| 组件 | 作用 |
| --- | --- |
| **CA(Certificate Authority,证书颁发机构)** | PKI 信任根,负责签发、吊销证书;根 CA 私钥是最高机密(通常离线保存于 HSM) |
| **RA(Registration Authority,注册机构)** | 负责受理申请、审核申请人身份,审核通过后转交 CA 签发(RA 不持签发私钥) |
| **证书库(Repository)** | 存放已签发证书与吊销信息的公开存储(如目录服务、CRL/OCSP 端点) |
| **证书与密钥** | 证书=公钥+身份信息+CA 签名;私钥由申请方保管,绝不出示给任何人 |
| **吊销机制** | CRL(证书吊销列表)与 OCSP(在线证书状态协议) |
| **终端实体** | 使用证书的服务器/客户端/用户 |

### 证书吊销(核心机制)

- **CRL(CRL Distribution Point)**:CA 定期发布的已吊销证书序列号列表,客户端拉取后比对;缺点:列表有周期延迟、体积大。
- **OCSP(RFC 6960)**:客户端实时查询"某证书是否吊销",返回 good/revoked/unknown;缺点:查询本身可被拦截、有隐私问题、端点可能故障。
- **OCSP Stapling**:服务器定期向 OCSP 端点取回"本次响应"并在 TLS 握手中附带,客户端免去额外查询,同时防篡改;推荐启用。
- **吊销原因**:私钥泄露、域名变更、证书信息错误、员工离职等。吊销≠即时生效——浏览器对 OCSP 失败默认"软失败"(继续连接),所以**吊销不能替代短有效期**。

## X.509 证书

### 证书结构(X.509 v3 主要字段)

| 字段 | 含义 |
| --- | --- |
| Version / Serial Number | 版本(v3)、唯一序列号(由 CA 分配) |
| Signature Algorithm | 签名算法(如 sha256WithRSAEncryption、ECDSA with SHA-256) |
| Issuer | 颁发者 DN(谁签发的) |
| Validity | 有效期(notBefore ~ notAfter) |
| Subject | 主体 DN(证书属于谁) |
| Subject Public Key Info | 公钥算法与公钥值 |
| **Extensions(扩展)** | SAN(主体备用名称,域名/IP 列表,现代浏览器只看 SAN)、Key Usage、**Extended Key Usage**(serverAuth/clientAuth)、Basic Constraints(是否 CA)、CRL Distribution Points、Authority Information Access(OCSP 地址) |
| Signature | CA 对以上内容的签名值 |

> 常见错误认知:浏览器校验"证书 CommonName(CN)"——实际现代浏览器只认 **SAN(Subject Alternative Name)**,CN 已被废弃用于域名匹配。

### 证书链与信任模型

- **信任链**:`叶子证书(服务器) ← 中间 CA ← 根 CA(信任锚)`,逐级由上级签名。
- 验证过程:客户端用**本地信任库中的根证书**验证根签名 → 用根公钥验证中间 CA 签名 → 用中间 CA 公钥验证叶子证书签名 → 校验有效期、SAN 与主机名、吊销状态、用途扩展。
- 中间 CA 的价值:根私钥可离线保存,泄露时只需吊销一个中间 CA;现代 CA 普遍"根 CA 离线 + 中间 CA 在线签发"。
- 信任模型:层次化模型(CA 树)、Web of Trust(PGP)、分布式账本等;浏览器/操作系统内置的根证书库(如 Mozilla、Microsoft)是 Web PKI 的信任锚。
- 证书格式:PEM(Base64 文本,常见)、DER(二进制)、PKCS#12(.pfx/.p12,含私钥,常用于 Windows/IIS 导入)、PKCS#7(.p7b,仅证书链)。

### 证书类型:DV / OV / EV

| 类型 | 验证强度 | 审核内容 | 颁发时间 | 使用场景 |
| --- | --- | --- | --- | --- |
| **DV(Domain Validation)** | 仅验证域名控制权 | 邮箱/HTTP/DNS 验证 | 分钟~小时级,可自动化 | 绝大多数网站(Let's Encrypt 即 DV) |
| **OV(Organization Validation)** | 验证组织真实存在 | 营业执照、域名控制权 | 数天 | 企业官网、对组织身份有要求的业务 |
| **EV(Extended Validation)** | 最严格 | 法律实体、授权人面审 | 数天~数周 | 高价值金融/政务;Chrome 83(2020)起已取消 EV 绿条 UI,仅保留 OID 标识 |

> 安全提示:EV 不代表"网站更安全",只代表"组织身份经过更严格核实";DV 证书在加密强度上与 EV 完全一致。证书类型影响"信任度",不影响"加密强度"。

## 证书生命周期

### 申请 → 签发 → 部署 → 续期 → 吊销

1. **生成密钥与 CSR**:服务端生成私钥 + 证书签名请求(CSR,含公钥与主体信息)。
2. **提交与验证**:提交 CSR 给 CA(或经 RA),CA 按 DV/OV/EV 级别验证控制权/身份。
3. **签发**:CA 签名生成证书,返回给申请方。
4. **部署**:将证书与私钥部署到服务器/负载均衡/网关。
5. **监控与续期**:证书过期是 TLS 故障第一大原因;提前续期(Let's Encrypt 为 90 天有效期,倒逼自动化)。
6. **吊销与更换**:私钥泄露或域名变更时吊销并重新签发。

### ACME 与 Let's Encrypt

- **ACME 协议(RFC 8555)**:自动化证书签发/续期的标准协议,挑战方式:`http-01`(在域名根路径放验证文件)、`dns-01`(DNS TXT 记录)、`tls-alpn-01`(TLS 握手内验证)。
- **Let's Encrypt**:免费 DV 证书 CA,证书有效期 **90 天**,通过 ACME 自动续期(如 certbot、acme.sh),是目前互联网 HTTPS 普及的主力。
- 自动化流程(以 certbot 为例):`certbot certonly --standalone -d example.com` → 证书写入 `/etc/letsencrypt/live/example.com/` → 定时任务自动续期并 reload Web 服务。

### openssl 常用命令速查

```bash
# 生成 CA 私钥与自签名根证书
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -days 3650 -out ca.crt -subj "/CN=My Root CA"

# 生成服务器私钥与 CSR
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com,DNS:www.example.com"

# 用 CA 签发服务器证书(带 SAN)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -copy_extensions copy

# 查看证书内容
openssl x509 -in server.crt -text -noout
# 验证证书链
openssl verify -CAfile ca.crt server.crt
# 测试远端 TLS(查看证书、套件、是否支持 TLS1.3)
openssl s_client -connect example.com:443 -servername example.com
# 生成 DH 参数(自定义场景;现代建议用 RFC 7919 命名组)
openssl dhparam -out dhparam.pem 2048
```

## TLS / HTTPS 工作原理

### 基本概念

- TLS 位于 TCP 与应用层之间,提供**机密性、完整性、身份认证**(HTTP + TLS = HTTPS,默认 443 端口)。
- 安全目标:① 服务器身份由证书验证;② 协商对称会话密钥(ECDHE);③ 流量用 AEAD(如 AES-256-GCM)加密并防篡改。

### 握手流程(TLS 1.2 完整握手)

1. **ClientHello**:客户端发送支持的 TLS 版本、密码套件列表、随机数 client_random。
2. **ServerHello**:服务器选定版本与套件,返回 server_random;随后发送**证书链**。
3. **密钥交换**:双方通过 ECDHE 交换临时公钥,各自计算**预主密钥(Pre-Master Secret)** → 结合两个随机数派生会话密钥。
4. **完成**:双方交换 Finished 消息(含全部握手消息的哈希,防篡改);随后开始加密数据传输。
5. **会话恢复**:TLS 1.2 用 Session ID / Session Ticket 缩短后续握手;TLS 1.3 用 PSK 实现 0-RTT(首次连接仍 1-RTT)。

### 证书验证(客户端视角)

- 信任链:逐级验证签名直到信任锚(根证书)。
- 有效期:当前时间在 notBefore~notAfter 内。
- 域名匹配:证书 SAN 含访问的主机名(通配符 `*.example.com` 不匹配 `example.com` 本身)。
- 吊销状态:OCSP Stapling / OCSP / CRL。
- 用途:Extended Key Usage 含 serverAuth(服务器证书)。
- **任何一步失败都不应放行**——尤其"证书验证关闭"是生产环境事故高发点。

### TLS 1.2 vs TLS 1.3

| 对比项 | TLS 1.2(RFC 5246,2008) | TLS 1.3(RFC 8446,2018) |
| --- | --- | --- |
| 握手往返 | 完整握手 2-RTT(恢复 1-RTT) | 1-RTT(恢复 0-RTT/PSK) |
| 密钥交换 | RSA、DHE、ECDHE(含静态 RSA) | 仅 ECDHE(+PSK),**移除 RSA 密钥交换** |
| 密码套件 | 算法组合五花八门,含 CBC/RC4/3DES | 固定 AEAD 套件(如 TLS_AES_256_GCM_SHA384、TLS_CHACHA20_POLY1305_SHA256) |
| 安全特性 | 需人工禁用旧算法 | 移除压缩、移除 CBC 与 RC4/3DES、移除重协商漏洞面;签名算法与握手参数全部混入密钥派生 |
| 兼容性 | 存量系统广泛支持 | 现代浏览器/系统默认支持,建议作为唯一启用版本 |

## 常见 TLS 配置错误

| 错误 | 后果 | 正确做法 |
| --- | --- | --- |
| 启用 SSLv3 / TLS 1.0 / TLS 1.1 | POODLE、BEAST 等攻击;合规不达标 | 仅启用 TLS 1.2 + 1.3 |
| 弱密码套件(RC4、3DES、DES、CBC) | 可被破解/降级利用 | 仅用 AEAD 套件(GCM/ChaCha20) |
| **证书过期未续** | 浏览器报错、服务不可用 | 监控到期 + ACME 自动续期 |
| **关闭证书验证(verify=False)** | 中间人直接解密全部流量 | 永远开启验证;测试环境也不得带病上线 |
| 证书与域名不匹配/缺 SAN | 主机名校验失败 | 证书含全部域名 SAN;通配符注意边界 |
| 私钥泄露/权限过大 | 可冒充服务器 | 私钥 600 权限、存 HSM/KMS、定期轮换 |
| 自定义弱 DH 参数 | Logjam 攻击 | 使用 RFC 7919 标准命名组(ffdhe2048+)或 ECDHE |
| 中间证书未部署(链不完整) | 部分客户端验证失败 | 部署 fullchain(叶子+中间 CA) |
| HTTP 明文未跳转/混用 | SSL 剥离、嗅探 | 全站 HSTS + 301 跳转 |

## TLS 配置检查清单

- [ ] 仅启用 **TLS 1.2 与 TLS 1.3**,禁用 SSLv2/SSLv3/TLS 1.0/1.1
- [ ] 密码套件仅保留 AEAD:TLS_AES_256_GCM_SHA384、TLS_AES_128_GCM_SHA256、TLS_CHACHA20_POLY1305_SHA256(禁用 CBC/RC4/3DES/DES)
- [ ] 密钥交换使用 ECDHE(X25519/P-256),保证**前向保密**
- [ ] 证书未过期、SAN 覆盖全部访问域名、证书链完整(fullchain)
- [ ] 应用层**开启证书验证**(不设 verify=False、不忽略主机名)
- [ ] 启用 **HSTS** 与 HTTP→HTTPS 跳转,防 SSL 剥离
- [ ] 启用 **OCSP Stapling**;吊销机制可查询
- [ ] 私钥权限收紧、非明文存放、定期轮换;高价值场景用 HSM/KMS
- [ ] 使用 `openssl s_client` / `sslscan` / SSLLabs 定期审计
- [ ] 证书续期自动化(ACME)并配置到期告警
- [ ] 内部服务证书纳入统一 CA 管理,不用裸自签名证书裸奔

## mTLS 双向认证

- **mTLS(Mutual TLS)**:除客户端验证服务器证书外,**服务器也验证客户端证书**,双向身份认证。
- 流程:握手时服务器请求客户端证书(ClientCertificateRequest)→ 客户端发送证书 → 服务器验证其签名与信任链 → 双向通过后建立加密连接。
- 用途:API 网关间通信、微服务集群内部、设备/物联网认证、零信任内部访问、金融行业接口互调。
- 落地:统一签发客户端证书并做吊销管理;替代方案是 SPIFFE/SPIRE(云原生身份)。

## 国密 SSL(商用密码)

- 国密算法:签名/密钥交换 **SM2**(GB/T 32918)、哈希 **SM3**(GB/T 32905)、分组加密 **SM4**(GB/T 32907)。
- 国密 SSL 依据 **GM/T 0024《SSL VPN 技术规范》**,密码套件形如 `ECC_SM4_CBC_SM3`、`ECC_SM4_GCM_SM3`(密钥交换与签名用 SM2、批量加密用 SM4、哈希用 SM3)。
- 典型部署:国密 TLS 网关/服务器 + 国密浏览器/客户端(或经合规改造的浏览器插件),用于政务、金融、关键信息基础设施的密评与等保合规。
- 注意:国密证书由持牌的国内 CA 签发;通用系统通常同时支持国际 TLS(供普通浏览器)与国密 TLS(供合规通道),由客户端协商选择。

## 证书与 TLS 的常见攻击

| 攻击 | 原理 | 防御 |
| --- | --- | --- |
| **中间人(MITM)** | 攻击者截获连接,冒充服务器与客户端通信 | 证书验证、HSTS、证书固定(pinning) |
| **证书伪造** | 签发假证书(CA 被入侵、私钥泄露、错误签发) | 严格 CA 运营、CT 日志监控(如 crt.sh)、短有效期 |
| **协议降级** | 强制客户端使用旧协议/弱套件(POODLE 即降级到 SSLv3) | 仅启用 TLS 1.2+/AEAD;禁用降级协商 |
| **SSL 剥离(sslstrip)** | 把 HTTPS 链接改写为 HTTP,在明文段窃取 | HSTS、全站 HTTPS、浏览器预加载 HSTS |
| BEAST(CVE-2011-3389) | 针对 TLS 1.0 CBC 的边信道 | 升级 TLS 1.2+;已基本失效 |
| Heartbleed(CVE-2014-0160) | OpenSSL 内存越界读,泄露私钥与内存 | 升级 OpenSSL、密钥轮换 |
| DROWN(CVE-2016-0800) | 借 SSLv2 服务破解 TLS 会话 | 禁用 SSLv2、升级 OpenSSL |
| Logjam(CVE-2015-4000) | 512 bit 导出级 DH 降级攻击 | 禁用导出套件、用 ≥2048 bit DH 或 ECDHE |
| CRIME/BREACH | 利用压缩泄露秘密(HTTP 压缩) | 禁用压缩、随机化响应、拆分敏感内容 |

## 最佳实践小结

- 对外 HTTPS:Let's Encrypt/商业 DV 证书 + ACME 自动续期 + TLS 1.2/1.3 + AEAD 套件 + HSTS + OCSP Stapling。
- 对内服务:统一内部 CA(如 OpenSSL 自建根 + 中间 CA,或 Vault/CFSSL),证书自动化签发,杜绝裸自签名与 verify=False。
- 高合规场景:按密评要求启用国密 SSL(SM2/SM3/SM4);关键私钥入 HSM。
- 持续审计:SSLLabs、sslscan、`openssl s_client` 巡检;证书到期与私钥泄露纳入监控告警。
