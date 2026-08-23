---
name: kali-full-tools
description: kali-full:latest Docker 镜像的完整工具清单与使用方法。包含 Kali 全套渗透工具 + PWN/逆向 (checksec, gdb+pwndbg, ropper, pwntools, distorm3)、内存取证 (volatility v2 命令 volatility, v3 命令 vol)、隐写 (steghide)、Android (apktool)、数学 (sage, sympy)、Windows (wine)、扫码 (zbar) 等。在 kali-full 容器内执行渗透/CTF/逆向/取证任务, 或需要确认某工具是否已预装、如何调用时使用。
---

# kali-full 镜像工具清单与使用

## 重点工具 (本次新增)

| 工具 | 版本/来源 | 用途 |
|---|---|---|
| `checksec` | 3.2.0 (slimm609, 官方 .deb) | 检查二进制安全特性 (PIE/RELRO/Canary/NX) |
| `gdb` + `pwndbg` | gdb 17.2 + pwndbg (git dev) | 调试 + PWN 增强 |
| `ropper` | 1.13.8 (sashs/Ropper) | ROP gadgets 搜索 |
| `ROPGadget` | pip (Nick D'Andrea/ROPGadget) | ROP gadgets 搜索 (带 Web UI) |
| `pwntools` | pip 最新 (Gallopsled) | CTF 开发框架 |
| `volatility` | **2.6.1 (volatilityfoundation v2, 按需提供)** | 内存取证 (Python 2.7 环境) |
| `vol` | volatility3 (同一官方项目现行维护版) | 内存取证 (Python 3, 自动识别 profile) |
| `steghide` | 0.6.0 (StegHigh fork) | JPEG/音频隐写 |
| `apktool` | 2.7.0 (iBotPeaches) | APK 反编译/重打包 |
| `sage` | 10.7 (conda-forge, /opt/miniconda3 env `sage`) | 数学/密码学符号计算 |
| `python3-sympy` | 1.14 (apt) | 符号计算 (轻量) |
| `pycryptodome` | pip 最新 (Legrandin) | 密码学库 |
| `distorm3` | 3.5.2 (pip 源码编译) | 高性能反汇编 |
| `zbar-tools` | 0.23 (ZBar) | 条码/二维码扫描 |
| `wine` | 10.0 (含 wine32) | 运行 Windows 程序 |

### checksec — 二进制安全特性检查

```bash
checksec file /bin/ls                  # 单个文件
checksec dir .                         # 当前目录全部 ELF
checksec file ./pwn --format=json      # JSON 输出 (yaml/xml 亦可)
```

### gdb + pwndbg — 调试

pwndbg 已通过 `~/.gdbinit` 自动加载, 直接 `gdb` 即可使用。

```bash
gdb ./pwn                              # 启动, pwndbg 自动加载
# pwndbg 常用命令 (gdb 内):
#   vmmap        内存映射        #   context      完整上下文
#   pie          PIE 基址        #   search     内存搜索
#   psearch      进程搜索        #   teardown   分析退出
```

### ropper — ROP 搜索

```bash
ropper --file ./pwn --searchable       # 可搜索的 gadgets 列表
ropper --file ./pwn --only pop,rsp     # 只找 pop rsp
ropper --file ./pwn --depth 3          # 组合链深度

### ROPGadget — ROP 搜索 (带 Web UI)

```bash
ROPGadget --file ./pwn --searchable     # 可搜索的 gadgets 列表
ROPGadget --file ./pwn --only pop,rsp   # 只找 pop rsp
ROPGadget --file ./pwn --idx 5          # 只看第 5 类 gadget
ROPGadget --file ./pwn --web 8080       # 启动 Web UI (浏览器访问 http://localhost:8080)

```

### pwntools — CTF 框架

```bash
pwn template                           # 生成 exp 模板
python3 - <<'EOF'
from pwn import *
p = process('./pwn')
p.interactive()
EOF
```

### volatility (v2.6.1) — 内存取证 ★按用户要求预装 v2

命令 `volatility` (另有 `vol.py` 软链)。运行环境: Miniconda2 Python 2.7.18 (`/opt/miniconda2`), 源码在 `/opt/volatility2`。v2 **必须手动指定 profile**, 用 `imageinfo`/`kdbgscan` 识别。

```bash
volatility -f mem.img imageinfo        # 识别镜像 → 得到建议 profile
volatility --info | grep -i profile    # 列出全部可用 profile (Win/Linux/Mac)
volatility --info                      # 列出全部 349 个插件

# Windows 内存 (profile 示例: WinXPSP2x86 / Win7SP1x64 / Win10x64_10586)
volatility -f mem.img --profile=Win7SP1x64 pslist      # 进程列表
volatility -f mem.img --profile=Win7SP1x64 cmdline     # 进程命令行
volatility -f mem.img --profile=Win7SP1x64 hashdump    # 密码哈希 (SAM)
volatility -f mem.img --profile=Win7SP1x64 lsadump     # LSA 秘密
volatility -f mem.img --profile=Win7SP1x64 hivelist    # 注册表 hive
volatility -f mem.img --profile=Win7SP1x64 filescan    # 文件扫描
volatility -f mem.img --profile=Win7SP1x64 netscan     # 网络连接
volatility -f mem.img --profile=Win7SP1x64 malfind     # 恶意代码检测
volatility -f mem.img --profile=Win7SP1x64 dumpfiles -Q 0x... -D out/   # 提取文件
volatility -f mem.img --profile=Win7SP1x64 memdump -p 1234 -D out/      # dump 进程内存

# Linux 内存 (profile 示例: LinuxUbuntu1604x64 / LinuxDebian8x64)
volatility -f mem.img --profile=LinuxUbuntu1604x64 linux_pslist   # 进程
volatility -f mem.img --profile=LinuxUbuntu1604x64 linux_bash     # bash 历史
volatility -f mem.img --profile=LinuxUbuntu1604x64 linux_ifconfig # 网卡配置
```

与 v3 的差异: v3 (命令 `vol`) 自动识别 profile, 插件名变为 `windows.pslist` 等; v2 必须 `--profile=` 且插件名为 `pslist`。

### volatility3 (vol) — 内存取证 (Python 3)

```bash
vol -f mem.img windows.pslist          # 进程列表
vol -f mem.img windows.malfind         # 恶意代码检测
vol -f mem.img linux.pslist            # Linux 内存
vol -f mem.img windows.netconn         # 网络连接
vol --help                             # 全部插件
```

### steghide — 隐写

```bash
steghide extract -sf secret.jpg -p pass      # 从图片提取
steghide extract -sf secret.jpg              # 无密码
steghide embed -cf secret.jpg -ef flag.txt -p pass   # 嵌入
```

### apktool — APK 反编译

```bash
apktool d app.apk -o app_src      # 反编译
apktool b app_src -o new.apk     # 重新打包 (需先装 zipalign/apksigner)
```

### sage — 数学 (conda-forge 环境)

入口: `/usr/local/bin/sage` → `/opt/miniconda3/envs/sage/bin/sage` (conda 环境, 自带 Python 3.11)。`sage-py` / `python-sage` 为同环境软链。

```bash
sage                                 # 进入 REPL
sage -python script.py               # 用 sage 的 python 跑脚本
sage -v                             # 版本 (SageMath 10.7)
```

REPL 示例: `solve(x^2 == 4, x)`、`Factorization(1024)`、椭圆曲线/格密码等。

### python3-sympy — 轻量符号计算

```bash
python3 -c "import sympy as s; x=s.symbols('x'); print(s.solve(x**2-4, x))"
```

### pycryptodome — 密码学库

```python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
```

### distorm3 — 反汇编

```python
from distorm3 import Decode32Bits, Decode64Bits
code = bytes.fromhex('554889e5')
print([hex(a.offset) + ' ' + a.mnemonic + ' ' + a.opers for a in Decode64Bits(code, 0)])
```

### zbar-tools — 扫码

```bash
zbarimg --quiet -S filename /dev/video0   # 摄像头识别
zbarimg photo.jpg                        # 图片识别 (二维码/条码)
```

### wine — Windows 程序

```bash
wine ./crackme.exe               # 64 位
wine32 ./crackme32.exe           # 32 位 (wine32 已装)
wine cmd /c dir
WINEPREFIX=/root/.wine32 wine ./x.exe   # 隔离环境
```

## 基础工具集 (kali-linux-headless, 全部预装)

| 类别 | 代表工具 |
|---|---|
| 信息收集 | nmap, masscan, amass, subfinder, theHarvester, dnsrecon, feroxbuster |
| Web 渗透 | sqlmap, nikto, gobuster, wfuzz, dirb, wpscan, joomscan, commix, hydra |
| 渗透框架 | Metasploit (msfconsole), Empire, Covenant, Cradle |
| AD 攻击 | crackmapexec, impacket 全家桶, evil-winrm, certipy, responder |
| 密码学/爆破 | hashcat, john, crunch, cewl, hashid, medusa |
| 无线 | aircrack-ng, kismet, wifite, reaver |
| 嗅探/流量 | tcpdump, tshark, mitmproxy, bettercap, dnschef |
| 取证 | bulk-extractor, binwalk, foremost, volatility (v2) + vol (v3) |
| 逆向 | Ghidra, radare2, gdb+pwndbg, ropper, pwntools, angr, checksec |
| 后渗透 | mimikatz, metasploit post, laudanum, hotpatch |
| 其他 | git, curl, wget, vim, socat, netcat, strace, python3+pip, wine |

## 备注 / 坑

- `--net=host` 或 `--privileged` 是 nmap 嗅探、无线工具正常工作的关键
- **volatility v2** 跑在独立 Python 2.7.18 环境 (`/opt/miniconda2/bin/python`), 不要用系统 python3 跑 `/opt/volatility2/vol.py`; 需要 py2 环境时也可直接 `/opt/miniconda2/bin/python`
- volatility v2 的 `--profile` 必须与内存镜像操作系统/架构匹配, 选错 profile 会报 "No suitable address space mapping found"
- pwndbg 通过 `pip install` 装进**系统 Python 3.14**, `gdb` 内置同版本 Python 自动加载; 若加载失败, 用 `python3 -c "import pwndbg"` 确认模块存在
- ROPGadget 控制台脚本为 `ropgadget` (`pip install` 安装); 另 `ropper` 是 apt 版, 两者都可用
- sage 是独立 conda 环境, 不要与系统 python 混用 (`/opt/miniconda3/envs/sage/bin/python` 自带全部依赖); `sage-py` 已指向该环境 python
- `seclists` 字典包 (1.9GB) 未预装, rockyou 已含; 需要时 `apt install -y seclists`
- 容器内新增工具: `apt install` (USTC 源) 或 `pip install` (清华源, 已配好) 或 `git clone https://gh-proxy.org/https://github.com/...`
- 重新构建: `cd /home/gitciu/Lingshu/Docker/kali_Workspace/kali-full && docker build -t kali-full:latest .`
