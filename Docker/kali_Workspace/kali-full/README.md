# kali-full:latest — 完整版 Kali 智能体工作区镜像

基于 `kalilinux/kali-rolling:latest` 构建，包含 **kali-linux-headless 完整工具集** + 补充常用工具 + PWN/逆向/取证增强工具。
所有软件包已持久化在镜像层中，容器删除后重新拉起工具不会丢失。

- 镜像: `kali-full:latest` (约 33GB)
- 构建目录: `/home/gitciu/kali_Workspace/kali-full/` (Dockerfile + build.log)
- 工作目录: 容器内 `/root/workspace`
- apt 源已固定为 `mirrors.ustc.edu.cn` (避免默认镜像池 DNS 抖动)
- pip/uv 源: `pypi.tuna.tsinghua.edu.cn` (已全局配置, 容器内 `pip install` 直接可用)
- GitHub 加速前缀: `https://gh-proxy.org/` (如 `git clone https://gh-proxy.org/https://github.com/xxx/yyy.git`)

## 包含的工具集

| 类别 | 代表工具 |
|---|---|
| 信息收集 | nmap, masscan, amass, subfinder, theHarvester, dnsrecon, feroxbuster |
| Web 渗透 | sqlmap, nikto, gobuster, wfuzz, dirb, wpscan, joomscan, commix, hydra |
| 渗透框架 | Metasploit Framework (msfconsole), Empire, Covenant, Cradle |
| AD 攻击 | crackmapexec, impacket 全家桶, evil-winrm, certipy, bloodhound.py, responder |
| 密码学/爆破 | hashcat, john, crunch, cewl, hashid, medusa, pycryptodome, sage, sympy |
| 无线 | aircrack-ng, kismet, wifite, reaver |
| 嗅探/流量 | tcpdump, tshark (Wireshark CLI), mitmproxy, bettercap, dnschef |
| 取证 | bulk-extractor, binwalk, foremost, **volatility v2.6.1** (命令 `volatility`) |
| 逆向/PWN | Ghidra 12.1, radare2, **checksec**, **ropper**, **pwntools** (pwn 命令), **distorm3**, angr |
| Android | **apktool** |
| 隐写 | **steghide** |
| OCR | **tesseract-ocr** (含中文语言包), **pytesseract** |
| 数学 | **sage 10.9** (conda-forge 环境), python3-sympy |
| Windows | **wine 10.0** (wine64 + wine32, 已启用 i386) |
| 扫码 | **zbar-tools** (zbarimg) |
| 后渗透 | mimikatz, metasploit post, laudanum, hotpatch |
| 其他 | git, curl, wget, vim, socat, netcat, strace, python3 + pip |

## 启动命令

```bash
# 普通使用
docker run -it --name kali-ws --net=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  -v /home/gitciu/kali_Workspace/kali-full/data:/root/workspace \
  kali-full:latest

# 需要完整权限时 (部分工具如 aircrack-ng 注入、某些 DoS 工具)
docker run -it --privileged --net=host \
  -v /home/gitciu/kali_Workspace/kali-full/data:/root/workspace \
  kali-full:latest

# 长期后台运行 (智能体工作区)
docker run -d --name kali-ws --net=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v kali-ws-data:/root/workspace \
  kali-full:latest sleep infinity
```

## 工具速查 (详细用法见 skills/kali-full-tools/SKILL.md)

```bash
checksec file /bin/ls              # 二进制安全特性 (PIE/RELRO/Canary/NX)
ropper --file ./pwn --searchable   # ROP gadgets
pwn template                       # pwntools 模板
volatility -f mem.img --profile=Win7SP1x64 pslist   # 内存取证 (v2.6.1)
steghide extract -sf img.jpg -p pw # 隐写提取
pytesseract image.png                # OCR 文字识别 (Python)
apktool d app.apk -o out           # APK 反编译
sage                               # SageMath 10.9 REPL
zbarimg photo.jpg                  # 扫码
wine ./prog.exe                    # 运行 Windows 程序
python3 -c "from distorm3 import Decode64Bits"   # 反汇编
```

## 说明

- `--net=host` 或 `--privileged` 是 kali 工具正常工作的关键 (nmap 需要 NET_RAW, 嗅探需要 NET_ADMIN)
- 挂载 `/root/workspace` 卷可让工作区文件也持久化 (镜像只持久化软件包)
- apt lists 已保留在镜像中, 后续 `apt install` 新包很快; 需要时也可直接 `pip install` (已配清华源 + break-system-packages)
- **volatility v2** (按用户要求): 运行在 Miniconda2 自带 Python 2.7.18 环境 (`/opt/miniconda2`, 源码 `/opt/volatility2`), 命令 `volatility` / `vol.py`, 需手动 `--profile=`; 同时保留官方现行维护版 **volatility3** (命令 `vol` / `volatility3`, 自动识别 profile)
- **SageMath**: 官方二进制源 (ftp.sagemath.org) 不可达且 kali 仓库无 sagemath 包, 故通过 **conda-forge** (Miniforge3, 位于 `/opt/miniforge3/envs/sage`) 安装 10.9 版, 已软链到 `/usr/local/bin/sage`
- **Tesseract OCR**: 引擎由 apt 安装 (`tesseract-ocr` + 中文语言包), Python 包装器 `pytesseract` 已通过 pip 安装
- `seclists` 字典包 (1.9GB) 未预装, rockyou 已含; 需要时: `apt install -y seclists`
- 重新构建: `cd /home/gitciu/kali_Workspace/kali-full && docker build -t kali-full:latest .`
