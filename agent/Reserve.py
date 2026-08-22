"""逆向分析 Agent — 通过 IDA MCP 对二进制文件执行反编译分析。

流程：
  1. idalib-mcp 通过 stdio 启动并连接
  2. 调用 idb_open 打开二进制并取得 database 会话 ID
  3. 所有分析工具携带 database，完成后调用 idb_close
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import MCPClient, StdioMCPConfig
from agentscope.message import UserMsg

from agent.Attack import _build_skill_list
from Tools.IntelPwn import create_intelpwn_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, StrictJSONToolkit, create_scoped_shell_tool, run_interruptible_agent_reply
from Tools.tool_catalog import append_capability_summary, create_tool_catalog_tools
from Tools.Vision import create_vision_analysis_tool
from agent.experts import REVERSE_EXPERT

RESERVE_SYS_PROMPT = """你是二进制逆向与动态调试专家（Reserve）。
你只能处理 Orchestrator 给出的单一授权目标，并且只使用提供的工具。

可用工具：
1. scoped_shell: 受限的本地命令执行工具。
2. ida_open_binary: 为原始二进制生成 IDA 数据库并打开，返回 database 会话 ID。
3. IDA_Tool: IDA 逆向工具集（survey_binary / decompile / list_funcs / xrefs_to 等）。
4. gdb_create_session / gdb_load_core: 在授权工作区内创建 GDB 动态调试或核心转储会话。
5. GDB_Tool: 多会话 GDB/MI 工具集（断点、运行、上下文、寄存器、内存、反汇编等）。
6. analysis: 委托 Analysis 专家独立研判。
7. intelpwn_analyze: IntelPwn 二进制静态漏洞分析工具。
8. analyze_image: 理解授权工作区内的程序截图、流程图、二维码、图形资源和视觉线索。

工作流程（严格遵守顺序）：
1. 先调用 analysis 获取独立研判，确定分析重点。
2. 对文件先调用 intelpwn_analyze 获取保护机制和潜在漏洞概览。
3. 严禁手动启动 idat，也不要直接调用 IDA_Tool.idb_open。必须先调用
   ida_open_binary(input_path=二进制绝对路径)，并保存返回的 database 会话 ID。
4. 先调用 survey_binary 获取概览，再按需调用 decompile / analyze_function / xrefs_to。
   idb_open 之外的每个 IDA 分析工具都必须传入同一个 database。
5. 分析结束后调用 idb_close(database=..., save=false) 释放会话。
6. 需要动态验证时先调用 gdb_create_session，保存 session_id；先设置断点再运行，
   每个 GDB 工具都传入同一个 session_id，结束后必须调用 close_session。
7. GDB 工具返回结构化 JSON，必须检查 ok 字段；执行超时后先调用 interrupt，
   不得把超时误判为程序退出。
8. 只有证据充分时才用 scoped_shell 做验证。
9. 禁止拒绝服务、破坏数据、植入持久化、清除日志或扩大目标范围。
10. 你只返回结果，不改变任务状态，也不宣布整个任务完成。

**关键：分析完成后必须立即输出结构化报告并停止。严禁反复验证或继续调用工具。**

报告结构：已验证事实、失败尝试、证据、当前权限、发现的 Flag（如有）和建议下一步。"""


_IDA_DIR = Path("/home/kali/ida-pro-9.1")
_IDALIB_MCP = Path("/home/kali/.local/bin/idalib-mcp")
_UVX_FALLBACK = Path("/home/kali/.local/bin/uvx")
_GDB_MCP_INSTALLED = Path("/home/kali/.local/bin/gdb-multi-mcp")
_GDB_MCP_SOURCE = (
    "git+https://github.com/Mistyovo/gdb-multi-mcp"
    "@6e8048b8e933bbbae79b6da16fe69249f56fe30d"
)
_IDA_READ_ONLY_TOOLS = [
    "server_health", "lookup_funcs", "int_convert", "list_funcs", "func_query",
    "list_globals", "entity_query", "imports", "imports_query", "find_regex",
    "search_text", "decompile", "disasm", "func_profile", "analyze_batch",
    "xrefs_to", "xref_query", "xrefs_to_field", "callees", "find_bytes",
    "basic_blocks", "find", "insn_query", "export_funcs", "callgraph",
    "get_bytes", "get_int", "get_string", "get_global_value", "read_struct",
    "search_structs", "type_query", "type_inspect", "stack_frame",
    "survey_binary", "analyze_function", "analyze_component", "trace_data_flow",
    "make_signature", "make_signature_for_function", "make_signature_for_range",
    "find_xref_signatures", "idb_open", "idb_list", "idb_close",
]

# 这些入口可以越过灵枢的文件/网络范围控制，因此不直接暴露。受支持的本地
# 会话入口由下方 gdb_create_session / gdb_load_core 包装并执行路径校验。
_GDB_RESTRICTED_ENTRY_TOOLS = frozenset({
    "create_session",
    "attach",
    "load_core",
    "connect_target",
    "rr_record",
    "start_replay_session",
})


def _resolve_gdb_mcp_command() -> str:
    """返回固定安装的 GDB MCP 启动器，支持环境变量覆盖。"""
    configured = os.getenv("LINGSHU_GDB_MCP_COMMAND", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        raise RuntimeError(f"GDB MCP 启动器不存在: {configured}")

    # 优先使用已安装并缓存依赖的固定可执行文件，避免 systemd 环境下
    # 通过 uvx --offline 重新解析依赖导致 MCP 子进程立即退出。
    if _GDB_MCP_INSTALLED.is_file():
        return str(_GDB_MCP_INSTALLED)

    resolved = shutil.which("uvx")
    if resolved:
        return resolved
    if _UVX_FALLBACK.is_file():
        return str(_UVX_FALLBACK)
    raise RuntimeError(
        "uvx 不存在；请先安装 uv，再运行: "
        "uv tool install --from git+https://github.com/Mistyovo/gdb-multi-mcp "
        "gdb-multi-mcp",
    )


async def create_reverse_agent(
    model,
    analysis_agent: Agent,
    target: str,
    project_dir: str | Path,
    timeout: int,
    category_decision: dict | None = None,
    scope_registry: ScopeRegistry | None = None,
    max_iters: int = 20,
    event_callback=None,
    *,
    offloader=None,
    context_config=None,
    state=None,
    artifact_root: str | Path | None = None,
    vision_model=None,
    vision_roots: tuple[str | Path, ...] = (),
) -> Agent:
    async def analysis(service_info: str) -> str:
        """委托 Analysis 专家研判真实证据。

        Args:
            service_info: Recon 得到的文件信息和初步结论。
        """
        result = await run_interruptible_agent_reply(
            analysis_agent,
            UserMsg(name="Reserve", content=service_info),
            prefix="[Analysis] ",
            on_event=event_callback,
        )
        return result.get_text_content() or "[Analysis] 未返回文本结果"

    skill_list = _build_skill_list(category_decision, project_dir)

    if not _IDALIB_MCP.is_file():
        raise RuntimeError(f"IDA MCP 启动器不存在: {_IDALIB_MCP}")
    if not _IDA_DIR.is_dir():
        raise RuntimeError(f"IDA 安装目录不存在: {_IDA_DIR}")

    ida_mcp = MCPClient(
        name="IDA_Tool",
        is_stateful=True,
        mcp_config=StdioMCPConfig(
            command=str(_IDALIB_MCP),
            args=["--stdio"],
            cwd=project_dir,
            env={**os.environ, "IDADIR": str(_IDA_DIR)},
        ),
        enable_tools=_IDA_READ_ONLY_TOOLS,
        execution_timeout=max(float(timeout), 120.0),
    )
    try:
        async with asyncio.timeout(30.0):
            await ida_mcp.connect()
        ida_tools = await ida_mcp.list_tools()
    except Exception as exc:
        await ida_mcp.close()
        raise RuntimeError(f"IDA MCP 连接失败: {exc}") from exc

    # AgentScope 默认要求逐次批准 MCP；这里只暴露只读分析和会话生命周期工具。
    for tool in ida_tools:
        tool.is_read_only = True

    idb_open_tool = next(
        tool for tool in ida_tools if tool.name.endswith("__idb_open")
    )
    exposed_ida_tools = [
        tool for tool in ida_tools if not tool.name.endswith("__idb_open")
    ]

    gdb_mcp_command = _resolve_gdb_mcp_command()
    gdb_mcp_args = [
        "--transport", "stdio",
        "--exec-timeout", str(max(1, int(timeout))),
    ]
    if Path(gdb_mcp_command).name == "uvx":
        gdb_mcp_args = [
            "--offline",
            "--from", _GDB_MCP_SOURCE,
            "gdb-multi-mcp",
            *gdb_mcp_args,
        ]

    gdb_mcp = MCPClient(
        name="GDB_Tool",
        is_stateful=True,
        mcp_config=StdioMCPConfig(
            command=gdb_mcp_command,
            args=gdb_mcp_args,
            cwd=project_dir,
            env={
                **os.environ,
                # FastMCP 的版本检查会在离线环境拖慢初始化；MCP 服务运行
                # 不需要它，也不需要在 stdio 日志中输出大幅 Banner。
                "FASTMCP_CHECK_FOR_UPDATES": "off",
                "FASTMCP_SHOW_SERVER_BANNER": "false",
            },
        ),
        execution_timeout=max(float(timeout), 120.0),
    )
    try:
        async with asyncio.timeout(45.0):
            await gdb_mcp.connect()
        gdb_tools = await gdb_mcp.list_tools()
    except Exception as exc:
        try:
            await gdb_mcp.close()
        except RuntimeError:
            pass
        await ida_mcp.close()
        raise RuntimeError(f"GDB MCP 连接失败: {exc}") from exc

    def _gdb_tool(short_name: str):
        tool = next(
            (
                candidate for candidate in gdb_tools
                if candidate.name.endswith(f"__{short_name}")
            ),
            None,
        )
        if tool is None:
            raise RuntimeError(f"GDB MCP 缺少必要工具: {short_name}")
        return tool

    gdb_create_session_tool = _gdb_tool("create_session")
    gdb_load_core_tool = _gdb_tool("load_core")
    exposed_gdb_tools = [
        tool for tool in gdb_tools
        if tool.name.rsplit("__", 1)[-1] not in _GDB_RESTRICTED_ENTRY_TOOLS
    ]
    # gdb-multi-mcp 未启用 --unsafe，且会话只能由下面经过授权路径校验的
    # 包装器创建。这里放行已建立会话上的 MCP 操作，避免 AgentScope 再触发
    # 一套与灵枢人工审批闸门不相通的 ASK 流程。
    for tool in exposed_gdb_tools:
        tool.is_read_only = True

    project_root = Path(project_dir).resolve()
    target_path = Path(target).expanduser().resolve()
    authorized_file_roots: list[Path] = []
    if target_path.exists():
        authorized_file_roots.append(
            target_path if target_path.is_dir() else target_path.parent,
        )
    if artifact_root is not None:
        authorized_file_roots.append(Path(artifact_root).expanduser().resolve())

    def _authorized_file(value: str, label: str) -> Path:
        source = Path(value).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"{label}不存在: {source}")
        if not any(source.is_relative_to(root) for root in authorized_file_roots):
            raise PermissionError(f"{label}不在本任务授权工作区内: {source}")
        return source

    def _tool_result_text(result) -> str:
        return "\n".join(
            str(getattr(block, "text", block))
            for block in result.content
        )

    async def gdb_create_session(
        program: str,
        args: list[str] | None = None,
        architecture: str | None = None,
    ) -> str:
        """为授权工作区内的本地二进制创建安全模式 GDB 会话。

        Args:
            program: 待调试二进制的绝对路径。
            args: 传给目标程序的参数列表。
            architecture: 可选 GDB 架构名，如 i386:x86-64。
        """
        source = _authorized_file(program, "待调试文件")
        result = await gdb_create_session_tool.call(
            program=str(source),
            args=args,
            architecture=architecture,
            cwd=str(source.parent),
        )
        return _tool_result_text(result)

    async def gdb_load_core(executable: str, core: str) -> str:
        """加载授权工作区内的二进制和核心转储进行只读事后分析。

        Args:
            executable: 与核心转储匹配的二进制绝对路径。
            core: 核心转储文件绝对路径。
        """
        executable_path = _authorized_file(executable, "可执行文件")
        core_path = _authorized_file(core, "核心转储")
        result = await gdb_load_core_tool.call(
            executable=str(executable_path),
            core=str(core_path),
        )
        return _tool_result_text(result)

    async def ida_open_binary(input_path: str) -> str:
        """生成并打开 IDA 数据库，返回包含 database 会话 ID 的 JSON。

        Args:
            input_path: 本任务工作区内待分析二进制的绝对路径。
        """
        try:
            source = _authorized_file(input_path, "待分析文件")
        except (FileNotFoundError, PermissionError) as exc:
            return f'{{"error":"{exc}"}}'

        database_path = source
        if source.suffix.lower() not in {".i64", ".idb"}:
            stat = source.stat()
            cache_key = hashlib.sha256(
                f"{source}:{stat.st_size}:{stat.st_mtime_ns}".encode(),
            ).hexdigest()[:16]
            cache_dir = project_root / "WorkDir" / "ida_databases"
            cache_dir.mkdir(parents=True, exist_ok=True)
            database_path = cache_dir / f"{source.stem}-{cache_key}.i64"
            if not database_path.is_file():
                process = await asyncio.create_subprocess_exec(
                    str(_IDA_DIR / "idat"),
                    "-A",
                    "-B",
                    f"-o{database_path}",
                    str(source),
                    cwd=str(cache_dir),
                    env={**os.environ, "IDADIR": str(_IDA_DIR)},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    _, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=max(float(timeout), 120.0),
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    return '{"error":"IDA 数据库生成超时"}'
                if process.returncode != 0 or not database_path.is_file():
                    error = stderr.decode("utf-8", errors="replace")[-1000:]
                    return f'{{"error":"IDA 数据库生成失败: {error}"}}'

        result = await idb_open_tool.call(
            input_path=str(database_path),
            mode="force_headless",
            run_auto_analysis=True,
            build_caches=True,
            init_hexrays=True,
        )
        return "\n".join(
            str(getattr(block, "text", block))
            for block in result.content
        )

    tools = [
            AllowedFunctionTool(analysis, is_read_only=True),
            create_intelpwn_tool(timeout),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="reserve", artifact_root=artifact_root),
            AllowedFunctionTool(ida_open_binary, is_read_only=True),
            AllowedFunctionTool(gdb_create_session, is_read_only=False),
            AllowedFunctionTool(gdb_load_core, is_read_only=True),
            *exposed_ida_tools,
            *exposed_gdb_tools,
            *create_tool_catalog_tools("reserve"),
        ]
    if vision_model is not None and vision_roots:
        tools.append(create_vision_analysis_tool(vision_model, vision_roots))
    toolkit = StrictJSONToolkit(
        tools=tools,
        skills_or_loaders=skill_list,
    )
    agent = Agent(
        name=REVERSE_EXPERT,
        system_prompt=append_capability_summary(RESERVE_SYS_PROMPT, "reserve"),
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
    agent._ida_mcp_client = ida_mcp
    agent._gdb_mcp_client = gdb_mcp
    return agent


async def close_reverse_agent(agent: Agent | None) -> None:
    """关闭任务持有的 IDA 与 GDB MCP 进程。"""
    if agent is None:
        return
    for attr in ("_gdb_mcp_client", "_ida_mcp_client"):
        client = getattr(agent, attr, None)
        if client is not None:
            try:
                await client.close()
            except RuntimeError:
                pass
