# docker 工作区三会话并发容量结论

> 状态：脚本已就绪（`scripts/docker_capacity_check.py`），本页为静态结论与运行指引。
> 实际压测数据需在部署机（有 docker daemon + `kali-full:latest`）执行脚本后回填。

## 容量模型（静态推导）

- 每会话 = 1 个 `as_ws_<workspace_id>` 容器，共享同一派生镜像（在 `kali-full:latest`
  33GB 基础镜像上构建带网关 venv 的子镜像）。
- 镜像 33GB 为只读共享层：3 个容器只各自 Cow 增量，镜像层不重复占用磁盘。
- 每容器运行一份网关 venv（agentscope 在 `/workspace` 之外自举），内存基线
  约为网关进程 + `sleep infinity`，量级为数十 MB～百 MB；重工具（volatility/sage/wine）
  按需加载。

## IDA 单实例切库影响

- IDA MCP（`127.0.0.1:8745`）一个实例同一时间只绑定一个二进制；
  3 个逆向会话并发 `POST /upload` 会互相切库，语义是「最后上传生效」。
- 建议：宿主侧加 asyncio 锁串行化 IDA 分析（同一时刻只有一个会话占用 8745），
  或多实例分端口（8745/8746/...）。当前尚未加锁，属于集成阶段的已知限制。

## 运行方式

```bash
python scripts/docker_capacity_check.py --sessions 3 --report docs/docker_capacity.md
```

输出项：并发初始化耗时、并发 `nmap`(syn) 冒烟、`docker stats` 的 CPU%/内存、
IDA 单实例结论；脚本运行后自动清理测试容器。

## 建议并发上限

- 以部署机实测为准；默认建议单机 ≤ 3 并发会话，超过时观测 `docker stats`
  的 CPU 峰值与内存增量，必要时加 `LINGSHU_WORKSPACE_MAX_CONCURRENT` 限流
  （当前未实现，见后续项）。
