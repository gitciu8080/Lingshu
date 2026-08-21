# antSword + AntSwordMCP Docker 部署

将 [antSword](https://github.com/AntSwordProject/antSword)（v2.1.16，Electron 4.0.3）与
[AntSwordMCP](https://github.com/p3ngtop/AntSwordMCP) 打包为一个 Docker 镜像：

- 容器内以 Xvfb 无头方式运行蚁剑
- 内置 AntSwordMCP 插件并**自动启动**（已按插件 README「方式 B」追加自启动代码）
- 对外暴露 MCP SSE 服务：`http://localhost:30080/sse`
- 数据（shell 列表、编码器、插件）持久化在 `/opt/antsword/antData` 卷中

## 目录结构

```
.
├── antSword/          # 蚁剑源码（克隆）
├── AntSwordMCP/       # MCP 插件（克隆）
├── docker/
│   ├── Dockerfile               # 镜像定义
│   ├── entrypoint.sh            # 入口：装插件 + Xvfb + 启动蚁剑
│   ├── electron-v4.0.3-linux-x64.zip  # Electron 4.0.3 二进制（内置，构建免下载）
│   └── test-mcp.js              # MCP 连通性验证脚本
├── mcp.json           # MCP 客户端配置文件
└── .dockerignore
```

## 构建

```bash
docker build -t antsword-mcp -f docker/Dockerfile .
```

## 运行

```bash
docker run -d --name antsword -p 30080:30080 antsword-mcp
```

约 15~20 秒后 MCP 服务就绪。查看日志：

```bash
docker logs -f antsword
```

## MCP 客户端配置

客户端配置见 [`mcp.json`](./mcp.json)（适用于 Claude Desktop / Cursor / Trae 等
支持 SSE 的 MCP 客户端）：

```json
{
  "mcpServers": {
    "antsword": {
      "url": "http://localhost:30080/sse"
    }
  }
}
```

> 注意 URL 必须使用 `localhost`（或 `127.0.0.1`）：插件内置 Host 头白名单
> （防 DNS Rebinding），其它 Host 的访问会被 403 拒绝。

## 验证

```bash
node docker/test-mcp.js            # 默认 http://localhost:30080/sse
node docker/test-mcp.js <url>      # 指定其它地址
```

输出应包含 `initialize`、`tools/list -> 37 个工具`、`shell_list` 等。

## 常用操作

```bash
# 停止 / 启动
docker stop antsword
docker start antsword

# 进入容器（查看数据、调试）
docker exec -it antsword sh

# 升级镜像后保留数据：数据卷自动沿用（匿名卷）
# 若重建容器，可用命名卷显式持久化：
docker run -d --name antsword -p 30080:30080 \
  -v antsword-data:/opt/antsword/antData antsword-mcp
```

## 安全说明

- MCP 服务监听 `0.0.0.0`（容器内，为配合 docker 端口映射），但 Host 头白名单
  仅放行 `localhost:30080` / `127.0.0.1:30080` / `[::1]:30080`，
  非本地 Host 访问一律 403。
- 如需从其它机器访问，请使用 SSH 隧道：
  `ssh -L 30080:localhost:30080 user@host`，然后本地连 `http://localhost:30080/sse`。
- 请仅在授权范围内使用本工具。
