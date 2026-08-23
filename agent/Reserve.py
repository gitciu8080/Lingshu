"""逆向分析 Agent — 通过容器化 IDA MCP 对二进制文件执行反编译分析。

流程：
  1. 容器化 IDA MCP（HTTP/SSE，默认 127.0.0.1:8745）常驻运行
  2. 调用 ida_open_binary 上传二进制（POST /upload 阻塞至自动分析完成）
  3. IDA 分析工具直接作用于当前已加载的二进制（无 database 会话参数）
"""
from __future__ import annotations

from agent.prompt_loader import load_prompt
import hashlib
import os
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import HttpMCPConfig, MCPClient
from agentscope.message import UserMsg

from agent.Attack import _build_skill_list
from Tools.IntelPwn import create_intelpwn_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, StrictJSONToolkit, create_scoped_shell_tool, run_interruptible_agent_reply
from Tools.workspace_tools import create_gdb_tool
from agent.experts import REVERSE_EXPERT

RESERVE_SYS_PROMPT = load_prompt("RESERVE")


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

# 容器内工作区挂载点（与 workspace_service / docker_exec 保持一致）。
_CONTAINER_WORKDIR = "/workspace"


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
    executor: "Any",
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
    # （/workspace/...），但 IDA MCP（宿主 HTTP）在宿主机运行，需要宿主
    # 路径。此闭包将容器路径反向映射回宿主路径（GDB 已容器内化，无需映射）。
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
            # GDB 容器内批量调试（替代原宿主侧 gdb-multi-mcp）。
            *create_gdb_tool(session_dir or project_dir, executor=executor),
            *exposed_ida_tools,
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
    return agent


async def close_reverse_agent(agent: Agent | None) -> None:
    """关闭任务持有的 IDA MCP 连接。"""
    if agent is None:
        return
    for attr in ("_ida_mcp_client",):
        client = getattr(agent, attr, None)
        if client is not None:
            try:
                await client.close()
            except RuntimeError:
                pass
