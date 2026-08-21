# antSword + AntSwordMCP 一体化镜像
#
# - debian:bullseye 基础，内置 Xvfb 无头显示，运行 antSword 2.1.16 (Electron 4.0.3)
# - 内置 AntSwordMCP 插件并自动启动 MCP SSE 服务（容器启动即可用）
# - 对外暴露 30080 端口: http://localhost:30080/sse
#
# 构建:  docker build -t antsword-mcp -f docker/Dockerfile .
# 运行:  docker run -d --name antsword -p 30080:30080 antsword-mcp

FROM debian:bullseye

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai

# apt 使用阿里云镜像加速
RUN echo "deb http://mirrors.aliyun.com/debian/ bullseye main" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        unzip \
        xvfb \
        libgtk-3-0 \
        libnss3 \
        libasound2 \
        libxss1 \
        libxtst6 \
        libnotify4 \
        libgbm1 \
        libexpat1 \
        libdbus-1-3 \
        libcups2 \
        libx11-xcb1 \
    && rm -rf /var/lib/apt/lists/*

# Electron 4.0.3（antSword 2.1.16 对应的开发版本，随镜像内置，构建无需联网下载）
COPY docker/electron-v4.0.3-linux-x64.zip /tmp/electron.zip
RUN unzip -q /tmp/electron.zip -d /opt/electron \
    && chmod +x /opt/electron/electron \
    && rm /tmp/electron.zip

# antSword 源码（仓库自带 node_modules，无需 npm install）
# 注意：AS_WORKDIR 必须指向应用目录本身（antSword 通过 $AS_WORKDIR/source 解析模块，
#       数据存于 $AS_WORKDIR/antData，与官方部署布局一致）
COPY antSword/ /opt/antsword/

# AntSwordMCP 插件（暂存区；entrypoint 会幂等安装到数据卷的 plugins 目录）
# 将监听地址改为 0.0.0.0 以便通过 docker 端口映射对外暴露（容器内 127.0.0.1 无法被映射到）。
# 插件内置的 Host 头白名单（localhost/127.0.0.1/[::1]）仍然生效，非本地 Host 访问会被 403 拒绝。
COPY AntSwordMCP/ /opt/mcp-plugin/
RUN rm -rf /opt/mcp-plugin/.git \
    && sed -i 's/"host": "127\.0\.0\.1"/"host": "0.0.0.0"/' /opt/mcp-plugin/config.default.json

# MCP 自启动：在 source/app.entry.js 末尾追加载入语句
# （对应 AntSwordMCP README「方式 B：自启动」，antSword 加载完成后自动拉起 SSE 服务）
RUN printf '\n' >> /opt/antsword/source/app.entry.js \
    && cat >> /opt/antsword/source/app.entry.js <<'EOF'

// ---- AntSwordMCP autoload (Docker image) ----
try {
  const mcpPlugPath = path.join(remote.process.env.AS_WORKDIR, 'antData/plugins/AntSwordMCP');
  if (fs.existsSync(path.join(mcpPlugPath, 'package.json'))) {
    require(path.join(mcpPlugPath, 'index.js'));
  }
} catch (e) { console.error('[AntSwordMCP] autoload failed:', e); }
EOF

# 工作目录：antData 数据目录（shell 列表、编码器、插件等）
ENV AS_WORKDIR=/opt/antsword
RUN mkdir -p "$AS_WORKDIR/antData/plugins"

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# MCP SSE 服务端口
EXPOSE 30080

# 数据持久化（shell 列表等），首次启动为空卷，entrypoint 自动装入 MCP 插件
VOLUME ["/opt/antsword/antData"]

ENTRYPOINT ["/entrypoint.sh"]
