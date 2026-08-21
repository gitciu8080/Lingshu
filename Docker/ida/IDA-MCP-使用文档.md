# IDA Pro MCP Docker 部署与使用文档

> 基于 2026-08-18 在本机（Linux + Docker）上的实际部署与验证结果整理。
> 测试目标: `c809d6f2590b8f72c2191c7fd222c7529af451a813bbf067c0fc2c1ed675e879.exe`（PE32 i386 控制台程序，184 KB）
>
> 本文档包含两部分：
> - 第 1~3 章：原镜像 `junegelency/ida-pro-mcp` 的部署与 IDA 启动方式分析
> - 第 4~9 章：**升级版镜像 `ida-mcp-up`（本次开发）**——增加 HTTP 上传 API，供远程 Agent 使用

---

## 1. 镜像概览

| 项目 | 原镜像 | 升级版（本次构建） |
|---|---|---|
| 镜像名 | `swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/junegelency/ida-pro-mcp:latest` | `ida-mcp-up:latest`（FROM 原镜像，本地构建） |
| 核心组件 | IDA Professional 9.1（Linux，`/opt/idapro`）+ `ida-pro-mcp` v1.4.0（mrexodia）+ uv + Python 3.12 | 同左 + `idalib-mcp-upload.py`（升级分叉） |
| 入口 | `uv run idalib-mcp --host 0.0.0.0 --port 8745 <binary>` | `python3 /opt/ida-mcp/idalib-mcp-upload.py [--host/--port/--unsafe] [binary]` |
| 二进制参数 | **必填**（缺省 Cmd 是 `--help`，不传会打印帮助退出） | **可选**（不传 = idle 启动，等待 `/upload`） |
| MCP 端点 | `:8745/sse` | `:8745/sse`（不变） |
| 管理 API | 无 | `:8745/upload` `/status` `/ready` `/close` `/`（新增，同端口） |
| 空闲内存 | ~125 MiB | ~150 MiB |

镜像内置 `ida-pro-mcp` 的两种工作模式（都随 PyPI 包装在里面）：

- **idalib 模式（两种镜像的入口均采用）**：`idalib_server.py` / 升级版 `idalib-mcp-upload.py`
- **plugin 模式（旧方式，保留可用）**：`server.py`（stdio MCP 桥）+ `mcp-plugin.py`（IDA 进程内插件，RPC 端口 13337）

## 2. IDA 启动方式分析：有没有做优化？

**结论：原镜像已经采用了优化后的启动方式，无需再做适配。**

### 旧方式（plugin 模式，需要 shell 启动 IDA）

1. 先用 shell 启动 IDA 本体（GUI 或 `idat -A xxx.exe`）；
2. IDA 进程内加载 `mcp-plugin.py`，插件起本地 HTTP JSON-RPC（默认 `127.0.0.1:13337`）；
3. MCP 客户端连一个独立的 stdio 桥进程，桥把请求转发到 13337。

缺点：shell 拉起 IDA、依赖 GUI/Qt 环境、两进程两条链路（MCP→桥→RPC→IDA）、13337 要通。

### 原镜像方式（idalib 模式，单进程直接进 MCP）

```text
uv run idalib-mcp --host 0.0.0.0 --port 8745 <binary>
  └─ import idapro                      # 进程内加载 libidalib.so (headless IDA, 无 shell/GUI)
  └─ idapro.open_database(binary, run_auto_analysis=True)
  └─ ida_auto.auto_wait()               # 等自动分析完成
  └─ ida_hexrays.init_hexrays_plugin()  # 初始化 Hex-Rays
  └─ 注册 47 个 MCP 工具
  └─ FastMCP.run(transport="sse")       # 直接对外提供 MCP SSE @ :8745/sse
```

优点：**不再通过 shell 启动 IDA**、无 GUI 依赖（容器里没有 X）、单进程单链路、启动即分析。
所以原镜像不需要适配；它唯一的"约定"是把二进制路径作为容器命令传入。

## 3. 原镜像部署（简述）

```bash
docker run -d --name ida-mcp \
  -v /home/gitciu/ida:/analysis \
  -p 8745:8745 \
  swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/junegelency/ida-pro-mcp:latest \
  /analysis/c809....exe
```

要点：`/analysis` 挂载目录即分析目录（IDB 文件 `.id0/.id1/.id2/.nam/.til` 持久化在宿主机）；
**一个 server 实例只绑定一个二进制**（v1.4.0 无运行时切库能力，源码里是 TODO）——这正是做上传 API 的动机。

## 4. 升级版：HTTP 上传 API（远程 Agent 工作流）

### 4.1 Agent 工作流

```
Agent ──POST /upload (二进制)──▶  服务端: 落盘 → 关旧库 → 开新库 → 自动分析 → 初始化 Hex-Rays
Agent ◀──200 {"ok":true, "status":"ready", md5/sha256/base/functions...}──
Agent ──连接 /sse 调 MCP 工具──▶  get_metadata / list_functions / decompile_function / ...
```

- **`POST /upload` 是阻塞式**：请求挂起直到分析完成才返回（返回即"加载完成"信号）。
  大文件分析可能几分钟，客户端超时要留足（另开连接轮询 `/status`，见第 9 章 FAQ 1）。
- 上传成功即完成切换，Agent **无需重连/重启任何东西**，直接在现有（或新建）SSE 会话上调工具。
- 支持反复上传不同文件（运行时切库），也支持重复上传同一文件（复用 IDB，~0.5s）。

### 4.2 API 一览（与原 MCP 同端口 8745）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/upload` | 上传二进制并切换分析目标。**阻塞至分析完成**。multipart 字段 `file`，或裸 body（`Content-Type: application/octet-stream`，文件名用 `?filename=` 或 `X-Filename` 头，缺省 `upload_<ts>.bin`）。`?fresh=1` 强制全量重新分析（跳过 IDB 复用）。成功返回 200 + 元数据；失败 400/413/500 |
| GET | `/status` | 状态机快照：`status`(starting\|idle\|loading\|ready\|error) + binary/module/base/size/md5/sha256/crc32/functions/analysis_ms/error/uploads |
| GET | `/ready` | ready 返回 200，否则 503（健康检查/重试轮询用） |
| POST | `/close` | 保存并关闭当前库，回到 idle |
| GET | `/` | 服务信息与端点自描述 |
| GET/POST | `/sse` `/messages/` | 原 MCP SSE 端点（不变） |

### 4.3 使用示例

**推荐：直接用目录里的 `ida-client.py`（纯标准库，无第三方依赖，远程 Agent 可直接调用）：**

```bash
python3 ida-client.py status                                          # 服务状态
python3 ida-client.py upload /path/to/file.bin                        # 上传并等待解析完成
python3 ida-client.py upload /path/to/file.bin --filename x.bin --fresh  # 指定名 + 强制重分析
python3 ida-client.py call get_metadata                               # 调 MCP 工具
python3 ida-client.py call list_functions '{"offset":0,"count":20}'
python3 ida-client.py call decompile_function '{"address":"0x401050"}'
python3 ida-client.py tools                                           # 列出 47 个工具
python3 ida-client.py demo /path/to/file.bin                          # 上传+元数据+入口+函数+字符串一条龙
# 远程: python3 ida-client.py --url http://<host>:8745 ...
```

Agent 典型两步：`upload` 返回 `ok:true` 即"加载完成" → 随后任意 `call` 分析当前库。

**原生 HTTP（不用客户端脚本）：**

```bash
# 1) 上传 (multipart)
curl -F 'file=@/path/to/malware.bin' http://127.0.0.1:8745/upload
# 响应:
# {
#   "ok": true,
#   "next": "connect MCP at /sse and call tools",
#   "binary": "/analysis/uploads/malware.bin",
#   "module": "malware.bin",
#   "base": "0x400000",
#   "functions": 256,
#   "analysis_ms": 3330,
#   "size": 184408,
#   "md5": "...", "sha256": "...", "crc32": "0x...",
#   "server_status": "ready"
# }

# 2) 上传 (裸 body)
curl -X POST http://127.0.0.1:8745/upload -H 'X-Filename: a.exe' \
     -H 'Content-Type: application/octet-stream' --data-binary @a.exe

# 3) 状态/健康检查
curl http://127.0.0.1:8745/status
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8745/ready   # 200/503

# 4) 关闭当前库
curl -X POST http://127.0.0.1:8745/close
```

**Agent 侧伪代码**（任意语言，核心就两步）：

```python
import requests
HOST = "http://<host>:8745"

# 1) 上传并等待解析完成 (阻塞式, timeout 按文件大小组)
r = requests.post(f"{HOST}/upload", files={"file": open("sample.bin","rb")}, timeout=1800)
assert r.json()["ok"], r.text
print(r.json()["md5"], r.json()["functions"])

# 2) 解析完成 -> 连接 MCP 开始分析 (任意支持 SSE 的 MCP 客户端 / mcp-remote)
#    get_metadata / list_functions / decompile_function / ...
```

### 4.4 客户端接入 MCP（与原镜像相同）

```jsonc
// 支持 SSE 直连的客户端 (Cline 等)
{ "mcpServers": { "ida": { "url": "http://127.0.0.1:8745/sse" } } }

// 只支持 stdio 的客户端 (Claude Code 等): 用 mcp-remote 桥接
{ "mcpServers": { "ida": { "command": "npx",
    "args": ["-y", "mcp-remote", "http://127.0.0.1:8745/sse"] } } }
```

47 个工具（未开 `--unsafe`），分类：

| 分类 | 工具 |
|---|---|
| 基本信息 | `get_metadata`, `get_entry_points`, `get_current_address`, `get_current_function`, `convert_number` |
| 列表/查询 | `list_functions`, `list_globals`, `list_globals_filter`, `list_imports`, `list_strings`, `list_strings_filter`, `list_local_types`, `get_defined_structures` |
| 函数/反编译 | `get_function_by_name`, `get_function_by_address`, `decompile_function`, `disassemble_function`, `get_callees`, `get_callers`, `get_xrefs_to`, `get_xrefs_to_field`, `get_stack_frame_variables`, `get_stack_frame_variables_internal` |
| 类型/结构 | `set_global_variable_type`, `set_function_prototype`, `declare_c_type`, `set_local_variable_type`, `get_struct_at_address`, `get_struct_info_simple`, `search_structures`, `analyze_struct_detailed` |
| 改名/注释 | `set_comment`, `rename_function`, `rename_global_variable`, `rename_local_variable`, `rename_stack_frame_variable` |
| Patch/栈变量 | `patch_address_assembles`, `create_stack_frame_variable`, `delete_stack_frame_variable`, `set_stack_frame_variable_type` |
| 内存读取 | `read_memory_bytes`, `data_read_byte/word/dword/qword`, `data_read_string` |
| 全局变量取值 | `get_global_variable_value_by_name`, `get_global_variable_value_at_address`, `get_global_variable_value_internal` |

## 5. 升级实现要点（含踩坑记录，重要）

升级 = 对 `mrexodia/ida-pro-mcp` 的 `idalib_server.py` 做分叉（`build/idalib-mcp-upload.py`）+
Dockerfile 打两个补丁（上传 API + 上游 bug 修复）。开发中踩到两个**会直接挂死**的坑：

### 坑 1：`idapro.open_database` 只能在初始化线程（Python 主线程）调用

libida 是单线程库，官方文档明确："All library functions must be called from the same thread that
initialized the library"。从 HTTP 工作线程直接调用 → loader 报
`Thread-unsafe function 'loader_input_t...'` 并**挂死**（不是报错返回）。
→ 所有 `open/close_database` 都在主线程执行。

### 坑 2：`execute_sync` 的唤醒机制依赖主线程正在跑 uvicorn 事件循环

MCP 工具内部用 `idaapi.execute_sync` 把 Python callable 排到 IDA "主线程"执行
（反汇编确认 = `callui(0x56, ...)` + 调用者 `PyEval_SaveThread` 后 futex 等待）。
实测三种主线程形态：

| 主线程状态 | 工作线程调 execute_sync |
|---|---|
| 正在跑 **uvicorn/真实网络事件** 的 asyncio 循环（原镜像形态） | ✅ 正常（~ms 级） |
| 阻塞在 `queue.Queue().get()`（最初的"分发器"方案） | ❌ 挂死 |
| 跑空 asyncio 循环（无事件） | ❌ 挂死 |

→ **uvicorn 必须留在主线程**。`/upload`、`/close` 的处理协程本身就运行在主线程事件循环上，
直接**内联**执行阻塞的 IDA 调用即可。副作用：切换期间事件循环冻结（SSE 无心跳、其他请求排队），
但此时 Agent 只等 upload 响应、不需要 MCP，可接受。

### 其他工程点

- **IDB 自愈**：`open_database` 失败（rc≠0，常见于上次异常退出留下损坏库）→ 自动清理该文件的
  IDB 伴随文件（`.i64/.id0~4/.nam/.til/.idw/.idp`）重试一次。实测修复了 rc=4 挂库问题。
- **IDB 复用**：上传落盘后比对 sha256 侧车文件（`<name>.sha256`）：内容相同 → 复用旧库
  （重传同一文件 ~0.5s 就绪）；内容变化 → 清旧库全新分析。
  若怀疑旧库异常（如容器被强杀后分析不完整、函数/名称缺失），用 `/upload?fresh=1`
  （客户端 `--fresh`）强制清库重分析。实测：损坏旧库重开后函数 211 且名称缺失，
  强制重分析后恢复正常（256 函数、名称完整）。
- **上游 bug 修复**（Dockerfile 内 sed 补丁）：v1.4.0 的 `get_function()` 对未命名函数返回
  `name=None`，违反 pydantic 输出 schema，导致 `list_functions` 等工具整体 500。
  补丁：`name=name or ""`。
- **并发上传**：事件循环冻结天然串行化；`SWITCH_LOCK` 兜底。并发时"最后一个生效"，
  upload 响应报告的是**本次请求**的加载结果（`server_status` 字段指示当前实况）。
- **文件名安全**：去目录成分、非 `[\w.\-]` 字符替换、长度截断保留扩展名。
- 上传大小上限默认 512MB（`IDA_MCP_MAX_UPLOAD_MB` 可调）；落盘目录默认 `/analysis/uploads`
  （`IDA_MCP_UPLOAD_DIR` 可调，随挂载卷持久化）。

## 6. 部署步骤

### 6.1 构建升级版镜像（一次性）

```bash
cd /home/gitciu/ida/build
docker build -t ida-mcp-up:latest .
```

### 6.2 启动（两种方式）

```bash
cd /home/gitciu/ida
chmod +x run-ida-mcp.sh test-upload.sh

# A) idle 启动, 等待 Agent 上传 (推荐)
./run-ida-mcp.sh
#    => 挂载 /home/gitciu/ida -> /analysis, 端口 8745
#    => GET http://127.0.0.1:8745/status 看到 "status":"idle" 即就绪

# B) 兼容旧用法: 启动即分析指定文件
./run-ida-mcp.sh ./c809....exe

# 多实例/改端口:  PORT=8746 ./run-ida-mcp.sh /path/to/x.bin ida-mcp-2
```

### 6.3 验证

```bash
# 全链路回归 (上传 -> ready -> MCP 47 工具 -> close -> 重传):
./test-upload.sh
# 期望结尾: ALL PASSED

# 单点检查:
curl -N -m 3 http://127.0.0.1:8745/sse        # 应有 event: endpoint
curl http://127.0.0.1:8745/status             # 状态 JSON
node test-mcp.mjs                              # MCP 握手+工具回归
```

## 7. 实测记录（本目录 exe）

升级版全量回归（`test-upload.sh`）通过，关键数据：

- **上传耗时**：小文件首次（全新建库+自动分析）~3.3s；IDB 复用时 ~0.5s；
  并发两个上传串行完成 ~7s。
- **get_metadata**：`base=0x400000, size=0x2f000, md5=3c771401ec09596a6933ccc1d89ab9a9, sha256=20cc0eb2a922090dde00e0420fb798361bd1bc76b52602659c34f7d50fde316d, crc32=0x52514cee`
- **list_functions**：`_main @0x401005, _main_0 @0x401050, _scanf @0x401120, _printf @0x401180, start @0x401240, __input @0x4013d0 ...`（全新分析共 256 函数）
- **ida-client.py 实测**：status/upload/call/tools 全通过；`decompile_function(0x401050)` 输出 `main_0` 伪代码（含 flag 字符串）；`--fresh` 重分析 3.3s。
- **list_strings**：`DBAPP{49d3c93df25caad81232130f3d2ebfad}`（该样本为 DBAPP CTF 题面程序）
- **decompile_function(0x401050)**：Hex-Rays 反编译正常：

```c
int main_0(int argc, const char **argv, const char **envp)
{
  char v4[4];
  const char *v5 = "DBAPP{49d3c93df25caad81232130f3d2ebfad}";
  int v6 = 5;
  while ( v6 >= 0 ) { printf(&byte_4250EC, v6); sub_40100A(); --v6; }  // 倒计时
  printf(asc_425088);            // 提问
  scanf("%c", v4);
  if (v4[0] == 'Y')      printf(aOd);
  else if (v4[0] == 'N') printf(&byte_425034);
  else                   printf(&byte_42501C);
  return sub_40100A();
}
```

- **运行时切库验证**：上传 `sample2.exe` 后 MCP `get_metadata.module == "sample2.exe"`；
  `/close` 后 `/ready` 返回 503；重传同文件 468ms 就绪（IDB 复用）。

## 8. 日常运维

```bash
docker logs -f ida-mcp           # 日志 (上传/切换/分析进度)
docker stats ida-mcp --no-stream
docker restart ida-mcp           # 重启 (已分析的 IDB 在挂载目录, 秒级恢复)

# 切换/更换目标 = 直接再上传 (运行时); 或重建容器:
./run-ida-mcp.sh /path/to/new.bin

docker rm -f ida-mcp             # 停止
```

## 9. 常见问题与注意事项

1. **`/upload` 长时间无响应**：大文件自动分析中，属正常（阻塞式设计）；用 `/status` 另开连接
   轮询（注意：切换期间事件循环冻结，`/status` 也要等切换结束才响应；若需实时进度看
   `docker logs -f`）。
2. **分析结果异常（函数/名称缺失、数量偏少）**：多半是旧 IDB 残留（容器强杀/早期异常退出）。
   用 `--fresh`/`?fresh=1` 重分析；或手动删 `/analysis/uploads/<name>.*` 后重新上传。
3. **SSE 客户端在切换期间断开**：切换期间无心跳，个别客户端会超时重连——重连即可，
   会话无状态（MCP 会话每次 `GET /sse` 新建）。
4. **一个实例一个二进制**：多目标并行分析 = 多实例多端口（8745/8746/...）。
5. **无认证**：`/upload` 可写盘 + 触发分析，**不要直接暴露公网**；内网使用加防火墙/VPN 限源 IP。
6. **`--unsafe` 慎开**：会注册危险工具（patch/执行类）；默认未开。
7. **上传目录持久化**：`/analysis/uploads/` 在挂载卷内，二进制 + IDB + sha256 侧车都持久保存，
   注意清理策略；IDB 可被 IDA 9 GUI 直接打开（IDA 9 新格式 `.i64` 为主，经典 `.id0/.id1/.nam/.til` 伴随）。
8. **架构**：镜像内 IDA 9.1 为 x86_64 Linux 版，可分析各架构目标（含 32 位 PE）；要求 x86_64 宿主机。
9. **PDB 下载**：分析 MSVC 二进制时 IDA 会尝试从 msdl.microsoft.com 拉 PDB（404 即跳过，无碍；
   内网无外网时同样跳过）。
10. **版本升级**：上游 `mrexodia/ida-pro-mcp` 迭代较快（本基线 v1.4.0；新版已自带运行时切库等
    能力）。升级时以新上游版本为基础重做第 5 章的分叉/补丁即可，线程模型两坑在 IDA 9 内应仍成立。
11. **自定义客户端读 SSE 注意**：Python `http.client` 的 `resp.read(amt)` 在 chunked 流上会
    读到满 amt 字节才返回，SSE 长连接上会永久阻塞——必须用 `readline()` 按行读。

## 10. 文件清单

| 文件 | 说明 |
|---|---|
| `build/Dockerfile` | 升级版镜像构建（FROM 原镜像 + 分叉脚本 + 上游 bug 补丁） |
| `build/idalib-mcp-upload.py` | 升级分叉：idalib MCP 服务器 + HTTP 上传/状态 API（含线程模型注释） |
| `ida-client.py` | 远程 Agent 客户端（纯标准库）：status/upload/call/tools/demo，支持 `--url/--timeout/--fresh` |
| `run-ida-mcp.sh` | 一键部署（idle 或启动即分析；等待就绪） |
| `test-upload.sh` | 上传 API + MCP 全链路回归（期望 `ALL PASSED`） |
| `test-mcp.mjs` | MCP 握手/工具/反编译回归（`node test-mcp.mjs`） |
| `c809....exe` | 测试样本（PE32 i386，DBAPP CTF 题面） |
| `c809....exe.i64` | IDA 数据库（启动即分析模式的产物；IDA 9 新格式） |
| `uploads/` | 上传 API 落盘目录（二进制 + IDB + `.sha256` 侧车，持久化） |
| `IDA-MCP-使用文档.md` | 本文档 |
