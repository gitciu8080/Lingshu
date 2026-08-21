"""逆向分析 Agent — 通过容器化 IDA MCP 对二进制文件执行反编译分析。

流程：
  1. 容器化 IDA MCP（HTTP/SSE，默认 127.0.0.1:8745）常驻运行
  2. 调用 ida_open_binary 上传二进制（POST /upload 阻塞至自动分析完成）
  3. IDA 分析工具直接作用于当前已加载的二进制（无 database 会话参数）
"""
from __future__ import annotations

from agent.prompt_loader import load_prompt
import asyncio
import hashlib
import os
import shutil
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import HttpMCPConfig, MCPClient, StdioMCPConfig
from agentscope.message import UserMsg

from agent.Attack import _build_skill_list
from Tools.IntelPwn import create_intelpwn_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, StrictJSONToolkit, create_scoped_shell_tool, run_interruptible_agent_reply
from agent.experts import REVERSE_EXPERT

RESERVE_SYS_PROMPT = load_prompt("RESERVE")


# IDA MCP 已容器化（见 /home/gitciu/ida/IDA-MCP-使用文档.md），宿主不再需要
# ida-pro 安装目录或 idalib-mcp 启动器；仅保留 GDB MCP 的宿主启动器探测。
_GDB_MCP_SOURCE = (
    "git+https://github.com/Mistyovo/gdb-multi-mcp"
    "@6e8048b8e933bbbae79b6da16fe69249f56fe30d"
)


def _find_gdb_mcp_executable() -> str | None:
    """跨平台探测 gdb-multi-mcp / uvx 可执行文件。

    搜索顺序（第一个命中即返回）：
      1. ``$LINGSHU_GDB_MCP_COMMAND`` 环境变量（绝对路径或命令名）
      2. ``gdb-multi-mcp`` 在 PATH 中（pip/uv tool/pipx 安装到系统）
      3. ``uvx`` 在 PATH 中
      4. 当前用户 ``~/.local/bin/`` 下的 gdb-multi-mcp / uvx
         （覆盖 ``uv tool install`` 在任意 Linux 用户下的默认位置）
      5. 常见备选路径（/home/kali, /opt 等历史部署位置）

    Returns:
        找到的可执行文件绝对路径，或 None。
    """
    # 1. 环境变量优先
    configured = os.getenv("LINGSHU_GDB_MCP_COMMAND", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        return None

    # 2-3. PATH 搜索
    for name in ("gdb-multi-mcp", "uvx"):
        resolved = shutil.which(name)
        if resolved:
            return resolved

    # 4. 当前用户 ~/.local/bin/
    user_bin = Path.home() / ".local" / "bin"
    for name in ("gdb-multi-mcp", "uvx"):
        candidate = user_bin / name
        if candidate.is_file():
            return str(candidate.resolve())

    # 5. conda 环境 bin/（CONDA_PREFIX 或 sys.executable 同级目录）
    import sys
    conda_dirs: list[Path] = []
    conda_prefix = os.getenv("CONDA_PREFIX")
    if conda_prefix:
        conda_dirs.append(Path(conda_prefix) / "bin")
    # sys.executable 同级 bin/（覆盖 conda run / systemd 指定解释器场景）
    py_bin = Path(sys.executable).parent
    if py_bin.name == "bin":
        conda_dirs.append(py_bin)
    # 常见 conda 环境名
    for env_name in ("agentscope", "lingshu", "base"):
        candidate = py_bin.parent.parent / "envs" / env_name / "bin"
        if candidate.is_dir():
            conda_dirs.append(candidate)
        # miniconda 默认路径
        candidate = Path.home() / "miniconda3" / "envs" / env_name / "bin"
        if candidate.is_dir():
            conda_dirs.append(candidate)
    for bin_dir in conda_dirs:
        for name in ("gdb-multi-mcp", "uvx"):
            candidate = bin_dir / name
            if candidate.is_file():
                return str(candidate.resolve())

    # 6. 历史部署路径（向后兼容）
    for base in ("/home/kali/.local/bin", "/opt/lingshu/bin"):
        for name in ("gdb-multi-mcp", "uvx"):
            candidate = Path(base) / name
            if candidate.is_file():
                return str(candidate.resolve())

    return None
# 只读分析工具白名单（运行时过滤 MCP 工具列表用，不含改名/改注释/打补丁等写操作）。
# 第一组为当前容器化镜像（ida-pro-mcp v1.4.0+upload）实际暴露的工具短名；
# 第二组为旧版 idalib-mcp 工具短名，镜像回滚旧版本时保持兼容。
_IDA_READ_ONLY_TOOLS = [
    # ── ida-pro-mcp v1.4.0（容器化部署实际暴露的工具名）──
    # 元信息 / 函数 / 全局 / 导入 / 字符串 / 类型
    "get_metadata", "get_function_by_name", "get_function_by_address",
    "get_current_address", "get_current_function", "convert_number",
    "list_functions", "list_globals_filter", "list_globals", "list_imports",
    "list_strings_filter", "list_strings", "list_local_types", "get_entry_points",
    # 反编译 / 反汇编 / 交叉引用
    "decompile_function", "disassemble_function",
    "get_xrefs_to", "get_xrefs_to_field", "get_callees", "get_callers",
    # 数据 / 内存 / 结构体 / 栈帧（只读）
    "get_global_variable_value_by_name", "get_global_variable_value_at_address",
    "get_stack_frame_variables", "get_defined_structures",
    "analyze_struct_detailed", "get_struct_at_address", "get_struct_info_simple",
    "search_structures", "read_memory_bytes",
    "data_read_byte", "data_read_word", "data_read_dword",
    "data_read_qword", "data_read_string",
    # ── 旧版 idalib-mcp 工具名（向后兼容）──
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


# 容器内工作区挂载点（与 workspace_service / docker_exec 保持一致）。
_CONTAINER_WORKDIR = "/workspace"


def _resolve_gdb_mcp_command() -> str:
    """返回 GDB MCP 启动器路径，支持多路径自动探测与环境变量覆盖。

    Raises:
        RuntimeError: 所有探测路径均未找到可执行文件时抛出，
            包含跨平台安装指引。
    """
    found = _find_gdb_mcp_executable()
    if found is not None:
        return found
    raise RuntimeError(
        "gdb-multi-mcp / uvx 均未找到。安装方式（任选其一）：\n"
        "  1. uv tool install --from "
        f'"{_GDB_MCP_SOURCE}" gdb-multi-mcp\n'
        "  2. pipx install --from "
        f'"{_GDB_MCP_SOURCE}" gdb-multi-mcp\n'
        "  3. 设置环境变量 LINGSHU_GDB_MCP_COMMAND 指向已安装路径\n"
        "  4. 安装 uv: curl -LsSf https://astral.sh/uv/install.sh | sh",
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
    executor: "Any | None" = None,
    session_dir: str | Path | None = None,
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

    # IDA MCP 已容器化部署：宿主直连 127.0.0.1:8745 的 SSE 端点，
    # 二进制经 /upload API 上传后自动分析（无需宿主 idat / idalib-mcp）。
    ida_base_url = os.getenv("LINGSHU_IDA_MCP_URL", "http://127.0.0.1:8745").rstrip("/")
    ida_mcp: MCPClient | None = None
    exposed_ida_tools: list = []
    _ida_allowed_tools = frozenset(_IDA_READ_ONLY_TOOLS)
    try:
        ida_mcp = MCPClient(
            name="IDA_Tool",
            is_stateful=False,
            mcp_config=HttpMCPConfig(url=f"{ida_base_url}/sse", timeout=30.0),
            # 服务器始终暴露完整工具集（47 个），但其中含改名/打补丁等写操作，
            # 且未加载二进制时调用会报错。不设 enable_tools，改由
            # _ida_allowed_tools 在运行时过滤出只读分析工具。
            execution_timeout=max(float(timeout), 120.0),
        )
        ida_tools = await ida_mcp.list_tools()
        for tool in ida_tools:
            tool.is_read_only = True
        exposed_ida_tools = [
            tool for tool in ida_tools
            if tool.name.rsplit("__", 1)[-1] in _ida_allowed_tools
            and not tool.name.endswith("__idb_open")
        ]
    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "IDA MCP 不可用（%s），Reserve 将在无 IDA 工具下降级运行: %s",
            ida_base_url, exc,
        )
        ida_mcp = None
        exposed_ida_tools = []

    # GDB MCP 连接：stdio 模式，宿主启动 gdb-multi-mcp 进程。
    gdb_mcp: MCPClient | None = None
    exposed_gdb_tools: list = []
    gdb_create_session_tool = None
    gdb_load_core_tool = None
    try:
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
                    "FASTMCP_CHECK_FOR_UPDATES": "off",
                    "FASTMCP_SHOW_SERVER_BANNER": "false",
                },
            ),
            execution_timeout=max(float(timeout), 120.0),
        )
        async with asyncio.timeout(45.0):
            await gdb_mcp.connect()
        gdb_tools = await gdb_mcp.list_tools()

        def _gdb_tool(short_name: str):
            tool = next(
                (c for c in gdb_tools if c.name.endswith(f"__{short_name}")),
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
        for tool in exposed_gdb_tools:
            tool.is_read_only = True
    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "GDB MCP 不可用，Reserve 将在无 GDB 工具下降级运行: %s", exc,
        )
        if gdb_mcp is not None:
            try:
                await gdb_mcp.close()
            except RuntimeError:
                pass
        gdb_mcp = None
        exposed_gdb_tools = []
        gdb_create_session_tool = None
        gdb_load_core_tool = None

    project_root = Path(project_dir).resolve()
    target_path = Path(target).expanduser().resolve()
    authorized_file_roots: list[Path] = []
    if target_path.exists():
        authorized_file_roots.append(
            target_path if target_path.is_dir() else target_path.parent,
        )
    if artifact_root is not None:
        authorized_file_roots.append(Path(artifact_root).expanduser().resolve())

    # Docker 模式下 Agent 通过 scoped_shell 发现的文件路径是容器内路径
    # （/workspace/...），但 IDA MCP（宿主 HTTP）和 GDB MCP（宿主 stdio）
    # 都在宿主机运行，需要宿主路径。此闭包将容器路径反向映射回宿主路径。
    _host_session_dir = (
        Path(session_dir).resolve() if session_dir is not None else None
    )

    def _resolve_host_path(value: str) -> Path:
        """尝试将路径解析为宿主文件系统路径（兼容容器路径和宿主路径）。"""
        p = Path(value).expanduser()
        if p.is_file():
            return p.resolve()
        # 容器路径 → 宿主路径：/workspace/<rel> → <session_dir>/<rel>
        if _host_session_dir is not None:
            p_str = str(p)
            prefix = _CONTAINER_WORKDIR + "/"
            if p_str.startswith(prefix):
                rel = p_str[len(prefix):]
                host = (_host_session_dir / rel).resolve()
                if host.is_file():
                    return host
            # 直接 /workspace → session_dir 本身
            if p_str == _CONTAINER_WORKDIR:
                host = _host_session_dir.resolve()
                if host.is_dir():
                    return host
        return p.resolve()

    def _authorized_file(value: str, label: str) -> Path:
        source = _resolve_host_path(value)
        if not source.is_file():
            raise FileNotFoundError(f"{label}不存在: {value}")
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
        if gdb_create_session_tool is None:
            return '{"error":"GDB MCP 不可用，无法创建调试会话"}'
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
        if gdb_load_core_tool is None:
            return '{"error":"GDB MCP 不可用，无法加载核心转储"}'
        executable_path = _authorized_file(executable, "可执行文件")
        core_path = _authorized_file(core, "核心转储")
        result = await gdb_load_core_tool.call(
            executable=str(executable_path),
            core=str(core_path),
        )
        return _tool_result_text(result)

    # 延迟绑定：ida_open_binary 需要在上传成功后向 toolkit 动态注册新工具，
    # 但 toolkit 在本函数返回前才创建。用可变容器传递引用。
    _toolkit_ref: list = [None]

    async def ida_open_binary(input_path: str) -> str:
        """上传二进制到容器化 IDA MCP 并等待分析完成，返回元数据 JSON。

        上传成功后自动刷新 IDA MCP 工具列表（idle → ready 后完整 47 个
        工具可用），并将新工具动态注册到 Agent toolkit。

        Args:
            input_path: 本任务工作区内待分析二进制的绝对路径。
        """
        if ida_mcp is None:
            return '{"error":"IDA MCP 不可用，无法执行逆向分析"}'
        try:
            source = _authorized_file(input_path, "待分析文件")
        except (FileNotFoundError, PermissionError) as exc:
            return f'{{"error":"{exc}"}}'

        # POST /upload（阻塞至自动分析完成），multipart 字段 file。
        # 上传成功即完成切库，随后 MCP 工具直接分析当前库。
        import aiohttp

        upload_url = f"{ida_base_url}/upload"
        async with aiohttp.ClientSession() as session:
            with source.open("rb") as fh:
                data = aiohttp.FormData()
                data.add_field("file", fh, filename=source.name)
                try:
                    async with session.post(
                        upload_url,
                        data=data,
                        timeout=aiohttp.ClientTimeout(
                            total=max(float(timeout), 600.0),
                        ),
                    ) as resp:
                        body = await resp.text()
                        if resp.status != 200:
                            return (
                                f'{{"error":"IDA 上传失败 HTTP {resp.status}: '
                                f'{body[:500]}"}}'
                            )
                except Exception as exc:  # noqa: BLE001
                    return f'{{"error":"IDA 上传异常: {exc}"}}'

        try:
            import json as _json

            meta = _json.loads(body)
            if not meta.get("ok"):
                return f'{{"error":"IDA 未就绪: {body[:500]}"}}'

            # ── 上传成功：刷新 IDA 工具列表并动态注册 ──
            # 个别服务器版本在 idle 状态下只暴露少量工具，上传后重新拉取工具
            # 列表，把新增工具通过 toolkit.add_tool() 注入 Agent，使其可被调用。
            try:
                refreshed = await ida_mcp.list_tools()
                existing_names: set[str] = set()
                if _toolkit_ref[0] is not None:
                    existing = await _toolkit_ref[0]._get_available_tools(None)
                    existing_names = set(existing.keys())
                added = 0
                for tool in refreshed:
                    short = tool.name.rsplit("__", 1)[-1]
                    if (
                        short in _ida_allowed_tools
                        and not tool.name.endswith("__idb_open")
                        and tool.name not in existing_names
                    ):
                        tool.is_read_only = True
                        if _toolkit_ref[0] is not None:
                            await _toolkit_ref[0].add_tool(tool)
                            added += 1
                if added:
                    import logging as _logging
                    _logging.getLogger(__name__).info(
                        "IDA 上传成功，已动态注册 %d 个新工具", added,
                    )
            except Exception as refresh_exc:  # noqa: BLE001
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "IDA 工具刷新失败（已有工具仍可用）: %s", refresh_exc,
                )

            # 返回给 Agent 的关键字段：module/base/functions/md5/sha256 等。
            return _json.dumps(
                {
                    "status": meta.get("server_status", "ready"),
                    "binary": meta.get("binary"),
                    "module": meta.get("module"),
                    "base": meta.get("base"),
                    "functions": meta.get("functions"),
                    "size": meta.get("size"),
                    "md5": meta.get("md5"),
                    "sha256": meta.get("sha256"),
                },
                ensure_ascii=False,
            )
        except ValueError:
            return f'{{"error":"IDA 返回非 JSON: {body[:500]}"}}'

    toolkit = StrictJSONToolkit(
        tools=[
            AllowedFunctionTool(analysis, is_read_only=True),
            create_intelpwn_tool(timeout, session_dir=session_dir),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="reserve", artifact_root=artifact_root, executor=executor),
            AllowedFunctionTool(ida_open_binary, is_read_only=True),
            AllowedFunctionTool(gdb_create_session, is_read_only=False),
            AllowedFunctionTool(gdb_load_core, is_read_only=True),
            *exposed_ida_tools,
            *exposed_gdb_tools,
        ],
        skills_or_loaders=skill_list,
    )
    # 绑定 toolkit 引用，供 ida_open_binary 上传后动态注册新 IDA 工具。
    _toolkit_ref[0] = toolkit
    agent = Agent(
        name=REVERSE_EXPERT,
        system_prompt=RESERVE_SYS_PROMPT,
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
