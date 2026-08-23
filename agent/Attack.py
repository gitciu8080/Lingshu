"""Attack：在授权范围内完成分析、验证和利用。

Skill 加载从 MissionState.category_decision 动态生成，不再硬编码 ctf-web。
"""
from __future__ import annotations

from agent.prompt_loader import load_prompt
import asyncio
import logging
import os
from collections.abc import Callable
from pathlib import Path
from types import MethodType

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import HttpMCPConfig, MCPClient
from agentscope.permission import PermissionBehavior, PermissionDecision

from Tools.CVE_Search import cve_search
from Tools.OCR import create_tesseract_ocr_tool
from Tools.SageMath import create_sagemath_tool
from Tools.ScopeRegistry import ScopeRegistry
from Tools.TonyDec import create_tonydec_tool
from Tools.tooling import AllowedFunctionTool, StrictJSONToolkit, create_scoped_shell_tool
from agent.experts import attack_expert_name

logger = logging.getLogger(__name__)


_ANTSWORD_MCP_URL = "http://127.0.0.1:30080/sse"
_ANTSWORD_TOOLS = (
    "shell_list", "shell_get", "shell_add", "shell_edit", "shell_del",
    "shell_capabilities",
    "base_info", "base_probedb",
    "cmd_exec", "cmd_list", "cmd_quote",
    "file_dir", "file_read", "file_write", "file_delete", "file_copy",
    "file_rename", "file_retime", "file_chmod", "file_mkdir", "file_wget",
    "file_hash", "file_upload", "file_download",
    "db_list_confs", "db_get_conf", "db_add_conf", "db_del_conf",
    "db_show_databases", "db_show_tables", "db_show_columns", "db_query",
    "raw_request",
    "mcp_status", "mcp_logs", "mcp_config_get", "mcp_config_set",
)
_ANTSWORD_READ_ONLY_TOOLS = frozenset({
    "shell_list", "shell_get", "shell_capabilities",
    "base_info", "base_probedb", "cmd_list",
    "file_dir", "file_read", "file_hash", "file_download",
    "db_list_confs", "db_get_conf", "db_show_databases", "db_show_tables",
    "db_show_columns", "mcp_status", "mcp_logs", "mcp_config_get",
})


ATTACK_SYS_PROMPT = load_prompt("ATTACK")

# ── Skill 路径映射 ──
_SKILL_PATH_MAP: dict[str, str] = {
    "web": "Skills/ctf-skills/ctf-web",
    "pwn": "Skills/ctf-skills/ctf-pwn",
    "reverse": "Skills/ctf-skills/ctf-reverse",
    "crypto": "Skills/ctf-skills/ctf-crypto",
    "forensics": "Skills/ctf-skills/ctf-forensics",
    "malware": "Skills/ctf-skills/ctf-malware",
    "misc": "Skills/ctf-skills/ctf-misc",
    "osint": "Skills/ctf-skills/ctf-osint",
    "ai-ml": "Skills/ctf-skills/ctf-ai-ml",
    "writeup": "Skills/ctf-skills/ctf-writeup",
}

# _CYBERPENDA_SKILL_MAP: dict[str, list[str]] = {
#     "web": ["api-security", "pentest-tools"],
#     "pwn": ["pwn-chain"],
#     "reverse": ["reverse-skill-router", "reverse-engineering"],
#     "crypto": ["ctf-sandbox-orchestrator"],
#     "forensics": ["digital-forensics"],
#     "malware": ["malware-analysis"],
#     "misc": ["ctf-sandbox-orchestrator"],
#     "osint": ["pentest-tools"],
#     "ai-ml": ["llm-security"],
# }
# _CYBERPENDA_ROOT = "Skills/cyberpenda-bundles"
_KALI_FULL_SKILL = "Skills/kali-full-tools"


async def _connect_antsword_mcp(
    timeout: int,
    exploitation_approved: Callable[[], bool] | None = None,
) -> tuple[MCPClient, list]:
    """连接 API 托管的 AntSword SSE MCP，并校验 37 个工具契约。"""
    url = os.getenv("LINGSHU_ANTSWORD_MCP_URL", _ANTSWORD_MCP_URL).strip()
    client = MCPClient(
        name="AntSword_Tool",
        # AntSword SSE 是 HTTP 服务；Attack 使用无状态 MCP，避免长连接在
        # 任务取消/收尾时跨 asyncio task 关闭 anyio cancel scope。
        is_stateful=False,
        mcp_config=HttpMCPConfig(url=url, timeout=15.0),
        enable_tools=list(_ANTSWORD_TOOLS),
        execution_timeout=max(float(timeout), 120.0),
    )
    try:
        tools = await client.list_tools()
        available = {tool.name.rsplit("__", 1)[-1] for tool in tools}
        missing = set(_ANTSWORD_TOOLS) - available
        if missing:
            raise RuntimeError(
                f"AntSword MCP 缺少工具: {', '.join(sorted(missing))}",
            )
    except BaseException:
        # stateless MCP 没有需要由外层关闭的连接上下文。
        raise

    # 读取/探测类操作可用于分析；任何可执行命令或修改目标的工具
    # 都与 MissionState.exploitation_approved 实时联动，不依赖模型遵守提示词。
    for tool in tools:
        short_name = tool.name.rsplit("__", 1)[-1]
        tool.is_read_only = short_name in _ANTSWORD_READ_ONLY_TOOLS

        async def _check_permissions(
            _self,
            *_args,
            _short_name: str = short_name,
            **_kwargs,
        ) -> PermissionDecision:
            if _short_name in _ANTSWORD_READ_ONLY_TOOLS:
                return PermissionDecision(
                    behavior=PermissionBehavior.ALLOW,
                    message="AntSword 只读信息收集已放行",
                )
            if exploitation_approved is not None and exploitation_approved():
                return PermissionDecision(
                    behavior=PermissionBehavior.ALLOW,
                    message="AntSword 操作已通过灵枢攻击阶段人工审批",
                )
            return PermissionDecision(
                behavior=PermissionBehavior.DENY,
                message="AntSword 写入/执行操作需先通过攻击阶段人工审批",
            )

        tool.check_permissions = MethodType(_check_permissions, tool)
    return client, tools


def _build_skill_list(
    category_decision: dict | None,
    project_dir: str | Path = "",
) -> list[str]:
    """根据题型分类决策构建 Skill 加载路径。

    Args:
        category_decision: MissionState.category_decision 的字典形式。
        project_dir: 项目根目录（用于路径存在性检查）。

    Returns:
        Skill 路径列表，始终包含 writeup。

    Raises:
        FileNotFoundError: 题型已确定但对应 Skill 目录缺失。
    """
    skill_paths: list[str] = []
    project_path = Path(project_dir) if project_dir else None

    if category_decision and category_decision.get("primary", "unknown") != "unknown":
        primary = category_decision["primary"]
        if primary in _SKILL_PATH_MAP:
            path = _SKILL_PATH_MAP[primary]
            if project_path and not (project_path / path).is_dir():
                raise FileNotFoundError(
                    f"题型 {primary!r} 的 Skill 目录不存在: {path}. "
                    f"请确认 Skills/ctf-skills/ctf-{primary}/ 已安装。"
                )
            skill_paths.append(path)

        # secondary
        for cat in category_decision.get("secondary", []):
            if cat in _SKILL_PATH_MAP and cat != primary:
                p = _SKILL_PATH_MAP[cat]
                if project_path and not (project_path / p).is_dir():
                    continue  # 次要 Skill 缺失不阻塞
                skill_paths.append(p)

    # writeup 始终加载
    skill_paths.append(_SKILL_PATH_MAP["writeup"])
    # kali-full 工具清单始终加载（docker 工作区内能力目录）
    skill_paths.append(_KALI_FULL_SKILL)
    # CyberPenda bundles 完整保存在仓库中，但运行时只加载与当前分类相关的目录。

    #加载CyberPenda已关闭
    # categories: list[str] = []
    # if category_decision:
    #     primary = str(category_decision.get("primary") or "")
    #     categories = [primary, *[str(value) for value in category_decision.get("secondary", [])]]
    # cyberpenda_names = ["attack-chain"]
    # for category in categories:
    #     cyberpenda_names.extend(_CYBERPENDA_SKILL_MAP.get(category, []))
    # for name in dict.fromkeys(cyberpenda_names):
    #     path = f"{_CYBERPENDA_ROOT}/{name}"
    #     if project_path and not (project_path / path / "SKILL.md").is_file():
    #         continue
    #     skill_paths.append(path)


    return skill_paths


async def create_attack_agent(
    model,
    analysis_agent: Agent | None = None,
    target: str = "",
    project_dir: str | Path = "",
    timeout: int = 120,
    category_decision: dict | None = None,
    scope_registry: ScopeRegistry | None = None,
    max_iters: int = 20,
    expert_context: str = "",
    event_callback=None,
    rag_middleware=None,
    *,
    offloader=None,
    context_config=None,
    state=None,
    artifact_root: str | Path | None = None,
    exploitation_approved: Callable[[], bool] | None = None,
    executor: "Any | None" = None,
) -> Agent:
    """创建 Attack Agent。

    Args:
        model: LLM 模型。
        analysis_agent: 已废弃，保留参数兼容。Attack 现在内联分析推理。
        target: 授权目标字符串（向后兼容）。
        project_dir: 项目根目录。
        timeout: 命令超时秒数。
        category_decision: 题型分类决策（v0.2.0 新增）。为 None 时仅加载 writeup。
        max_iters: ReAct 最大推理迭代次数，由调用方按任务复杂度分配。
    """
    skill_list = _build_skill_list(category_decision, project_dir)

    antsword_mcp: MCPClient | None = None
    antsword_tools: list = []
    try:
        antsword_mcp, antsword_tools = await _connect_antsword_mcp(
            timeout,
            exploitation_approved,
        )
    except Exception as exc:  # AntSword 不可用不应让非 WebShell 任务整体失败
        logger.warning("Attack 未能接入 AntSword MCP: %s", exc)

    toolkit = StrictJSONToolkit(
        tools=[
            AllowedFunctionTool(cve_search, is_read_only=True),
            create_sagemath_tool(project_dir, timeout=min(timeout, 300), executor=executor),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry, role="attack", artifact_root=artifact_root, executor=executor),
            create_tesseract_ocr_tool(project_dir, timeout=min(timeout, 90), executor=executor),
            create_tonydec_tool(project_dir, executor=executor),
            *antsword_tools,
        ],
        skills_or_loaders=skill_list,
    )
    agent = Agent(
        name=attack_expert_name(
            str((category_decision or {}).get("primary") or "unknown"),
            str((category_decision or {}).get("target_kind") or ""),
            expert_context,
        ),
        system_prompt=ATTACK_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        middlewares=[rag_middleware] if rag_middleware is not None else [],
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
    agent._antsword_mcp_client = antsword_mcp
    return agent


async def close_attack_agent(agent: Agent | None) -> None:
    """关闭 Attack 任务持有的 AntSword SSE 会话，不关闭 GUI 服务。"""
    if agent is None:
        return
    client = getattr(agent, "_antsword_mcp_client", None)
    if client is not None and client.is_stateful and client.is_connected:
        try:
            await client.close()
        except RuntimeError:
            pass
