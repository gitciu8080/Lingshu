FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

# 固定单一稳定镜像源, 避免默认镜像池 (http.kali.org) 随机跳到 DNS 解析失败的镜像
RUN printf 'Types: deb\nURIs: http://mirrors.ustc.edu.cn/kali\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources && \
    echo 'Acquire::http::Retry "5";' > /etc/apt/apt.conf.d/99retry

# 启用 i386 架构 (wine32 运行 32 位 Windows 程序需要)
RUN dpkg --add-architecture i386 && apt-get update

# 安装完整版 Kali 工具集 (headless, 无桌面)
# kali-linux-headless 包含: web 渗透、无线、取证、嗅探、逆向、密码学、DoS 等全套工具
RUN apt-get update && \
    apt-get -y install kali-linux-headless git curl wget vim less \
        gdb-multiarch && \
    apt-get clean

# ============================================================
# 必装补充：Agent / CTF / PWN / RE / Forensics / Android
# ============================================================

RUN apt-get update && \
    apt-get -y install \
        jq \
        ripgrep \
        fd-find \
        file \
        xxd \
        sqlite3 \
        socat \
        netcat-openbsd \
        lsof \
        gdbserver \
        gcc-multilib \
        g++-multilib \
        libc6-dev-i386 \
        binutils \
        nasm \
        patchelf \
        qemu-user \
        qemu-user-static \
        jadx \
        dex2jar \
        adb \
        binwalk3 \
        foremost \
        sleuthkit \
        testdisk \
        bulk-extractor \
        yara \
        libimage-exiftool-perl \
        pdfid \
        pdf-parser \
        ewf-tools \
        hashdeep \
        ssdeep \
        && apt-get clean && \
        rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get -y install gef && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


# 补充常用工具 (kali-linux-headless 未包含的):
# AD 攻击(cme)、逆向分析(ghidra)、Web 枚举(feroxbuster/subfinder)、CMS 审计(joomscan)、调试(strace)
# 新增 (PWN/逆向/取证/杂项):
#   build-essential python3-dev python3-venv python3-setuptools  编译 Python C 扩展 (distorm3 等)
#   steghide (StegHigh/steghide)  隐写
#   apktool (iBotPeaches/Apktool) Android 反编译
#   zbar-tools (ZBar/ZBar)        条码/二维码扫描 (zbarimg)
#   python3-sympy                 符号计算
#   ropper (sashs/Ropper)         ROPgadget
#   wine (含 wine64/wine32)       Windows 程序执行
#   tesseract-ocr                 OCR 引擎 (含中文语言包)
RUN apt-get update && \
    apt-get -y install crackmapexec ghidra feroxbuster subfinder joomscan strace \
        build-essential python3-dev python3-venv python3-setuptools \
        steghide apktool zbar-tools python3-sympy ropper \
        wine tesseract-ocr tesseract-ocr-chi-sim tesseract-ocr-chi-tra && \
    apt-get clean



# pip 全局配置: 清华源 + 允许安装到系统 Python (Kali 标记了 EXTERNALLY-MANAGED)
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip config set global.break-system-packages true

# Python 工具 (pip, 清华源):
#   pytesseract                  Tesseract OCR Python 包装器
#   pwntools     (Gallopsled/pwntools) CTF 开发框架 (pwn 命令)
#   pycryptodome (Legrandin/pycryptodome)  密码学库
#   distorm3     反汇编 (pip 无 Linux wheel, 源码编译; 失败则回退 apt python3-distorm3)
# 注: unicorn 2.1.4 只有 sdist (源码编译易失败), 2.1.3 有 cp313 wheel, 先固定版本
RUN set -e; \
    apt-get update && apt-get -y install cmake ninja-build pkg-config; \
    pip install "unicorn==2.1.3"; \
    pip install pwntools pycryptodome pytesseract


RUN pip install distorm3

RUN git clone https://gh-proxy.org/https://github.com/pwndbg/pwndbg.git /opt/pwndbg && \
    cd /opt/pwndbg && \
    ./setup.sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir \
        capstone \
        keystone-engine \
        z3-solver \
        lief \
        pefile \
        yara-python \
        construct

# volatility 2 (volatilityfoundation/volatility v2.6.1): 按用户要求提供 v2
# Kali rolling 已无 Python 2, 通过 Miniconda2 (清华镜像, 自带 Python 2.7.18) 提供运行环境
# 依赖全部走清华 pypi: distorm3 3.5.2 (反汇编) / pycryptodome 3.10.1 (最后一个支持 py2 的版本,
# 以 Crypto 命名空间兼容 volatility 的 pycrypto 调用) / ujson / openpyxl / pytz / Pillow
RUN set -e; \
    apt-get update && \
    apt-get -y install libcrypt-dev && \
    mkdir -p /lib64 && \
    rm -f /lib64/ld-linux-x86-64.so.2.new && \
    cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
       /lib64/ld-linux-x86-64.so.2.new && \
    mv -f /lib64/ld-linux-x86-64.so.2.new \
       /lib64/ld-linux-x86-64.so.2 && \
    \
    curl -fsSL -o /tmp/miniconda2.sh \
        https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda2-latest-Linux-x86_64.sh && \
    bash /tmp/miniconda2.sh -b -p /opt/miniconda2 && \
    rm -f /tmp/miniconda2.sh && \
    \
    cp /usr/bin/ld /opt/miniconda2/compiler_compat/ld && \
    \
    /opt/miniconda2/bin/pip install \
        -i https://pypi.tuna.tsinghua.edu.cn/simple \
        --no-cache-dir \
        "pip==20.3.4" && \
    \
    /opt/miniconda2/bin/pip install \
        -i https://pypi.tuna.tsinghua.edu.cn/simple \
        --no-cache-dir \
        distorm3 \
        "pycryptodome==3.10.1" \
        "ujson==1.35" \
        "openpyxl==2.6.4" \
        pytz \
        "Pillow==6.2.2" && \
    \
    curl -fsSL -o /tmp/vol2.tar.gz \
        https://gh-proxy.org/https://github.com/volatilityfoundation/volatility/archive/refs/tags/2.6.1.tar.gz && \
    tar -xzf /tmp/vol2.tar.gz -C /tmp && \
    mv /tmp/volatility-2.6.1 /opt/volatility2 && \
    rm -f /tmp/vol2.tar.gz && \
    printf '#!/bin/bash\nexec /opt/miniconda2/bin/python /opt/volatility2/vol.py "$@"\n' \
        > /usr/local/bin/volatility && \
    chmod +x /usr/local/bin/volatility && \
    \
    printf '#!/bin/bash\nexec /opt/miniconda2/bin/python /opt/volatility2/vol.py "$@"\n' \
        > /usr/local/bin/vol.py && \
    chmod +x /usr/local/bin/vol.py && \
    \
    ln -sf /opt/miniconda2/bin/python /usr/local/bin/python-vol2 && \
    ln -sf /opt/miniconda2/bin/pip /usr/local/bin/pip-vol2 && \
    \
    /opt/miniconda2/bin/python /opt/volatility2/vol.py --info >/dev/null && \
    apt-get clean

# checksec (slimm609/checksec): 官方 .deb 发布包, 经 GitHub 加速前缀下载
RUN curl -fsSL -o /tmp/checksec.deb \
        https://gh-proxy.org/https://github.com/slimm609/checksec/releases/download/3.2.0/checksec_3.2.0_amd64.deb && \
    dpkg -i /tmp/checksec.deb && \
    rm -f /tmp/checksec.deb

# SageMath (sagemath/sage): 官方二进制源 (ftp.sagemath.org) 不可达且 kali 仓库无此包,
# 改用 conda-forge 的 sage 包。环境在宿主机预构建为 conda-pack 自包含包
# (sage-env.tar.gz, 生成方法见 build-sage-env.sh), 镜像内直接解压即用, 不依赖构建期网络
#COPY sage-env.tar.gz /tmp/sage-env.tar.gz
#RUN mkdir -p /opt/sage && \
#    tar -xzf /tmp/sage-env.tar.gz -C /opt/sage && \
#    rm -f /tmp/sage-env.tar.gz && \
#    python3 /opt/sage/bin/conda-unpack >/dev/null 2>&1 || true && \
#    ln -sf /opt/sage/bin/sage /usr/local/bin/sage && \
#    ln -sf /opt/sage/bin/sage-py /usr/local/bin/sage-py
# 安装 Miniconda
RUN curl -fsSL -o /tmp/miniconda.sh https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda3-latest-Linux-x86_64.sh && \
    bash /tmp/miniconda.sh -b -p /opt/miniconda3 && \
    rm -f /tmp/miniconda.sh

# 将 miniconda3 纳入 PATH: 容器内可直接使用 conda 命令
# (Tools.SageMath 已改为优先直接调用 /usr/local/bin/sage, 不再依赖 conda,
#  但保留 PATH 便于智能体按需调用 conda run 或 pip-sage 等)
ENV PATH=/opt/miniconda3/bin:/opt/miniconda3/condabin:$PATH

# 配置 Conda（注意：最后一行没有 && \）
RUN /opt/miniconda3/bin/conda config --add channels conda-forge && \
    /opt/miniconda3/bin/conda config --set channel_priority strict && \
    /opt/miniconda3/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main && \
    /opt/miniconda3/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

# 创建 sage 环境（注意：最后一行没有 && \，且没有空行）
RUN /opt/miniconda3/bin/conda create -n sage sage python=3.11 -y && \
    ln -sf /opt/miniconda3/envs/sage/bin/sage /usr/local/bin/sage && \
    ln -sf /opt/miniconda3/envs/sage/bin/python /usr/local/bin/python-sage && \
    ln -sf /opt/miniconda3/envs/sage/bin/pip /usr/local/bin/pip-sage && \
    ln -sf /opt/miniconda3/envs/sage/bin/python /usr/local/bin/sage-py

# 创建 volatility3 环境并清理
RUN /opt/miniconda3/bin/conda create -y -n volatility3 python=3.11 pip && \
    /opt/miniconda3/envs/volatility3/bin/pip install --no-cache-dir volatility3 && \
    ln -sf /opt/miniconda3/envs/volatility3/bin/vol /usr/local/bin/vol && \
    ln -sf /opt/miniconda3/envs/volatility3/bin/python /usr/local/bin/python-vol3 && \
    ln -sf /opt/miniconda3/envs/volatility3/bin/pip /usr/local/bin/pip-vol3 && \
    /usr/local/bin/vol --help >/dev/null && \
    /opt/miniconda3/bin/conda clean -afy

# 保留 apt lists, 方便智能体后续快速安装新软件包
# 移除 pwntools 安装的 /usr/local/bin/checksec (Python 脚本), 避免遮蔽 slimm609 的 Go 版 checksec
# (pwntools 版本仍可通过 `pwn checksec` 使用)
# 注意: 新版 checksec (slimm609) 为子命令式语法: `checksec file <bin>` / `checksec dir <dir>`
RUN apt-get update && rm -f /usr/local/bin/checksec && \
    apt-get clean
RUN set -e; \
    python3 --version && \
    python-vol2 --version && \
    python-vol3 --version && \
    python-sage --version && \
    volatility --info >/dev/null && \
    vol --help >/dev/null && \
    sage --version && \
    gdb-multiarch --version | head -n 1 && \
    qemu-aarch64 --version | head -n 1 && \
    patchelf --version && \
    jadx --version && \
    yara --version && \
    ropgadget --version | head -n 1 && \
    python-sage -c "print('sage-py-ok')" && \
    gdb -batch -ex "python import pwndbg" -ex "quit" 2>&1 | grep -q "No module named 'pwndbg'" && echo "ERROR: pwndbg not loaded" && exit 1 || true



# 基本工作区目录
RUN mkdir -p /root/workspace

WORKDIR /root/workspace

CMD ["/bin/bash"]
