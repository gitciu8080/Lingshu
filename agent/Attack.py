"""Attack：在授权范围内完成分析、验证和利用。

Skill 加载从 MissionState.category_decision 动态生成，不再硬编码 ctf-web。
"""
from __future__ import annotations

from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.mcp import MCPClient, StdioMCPConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from Tools.CVE_Search import cve_search
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool, create_scoped_shell_tool, stream_agent_reply
from agent.experts import attack_expert_name


ATTACK_SYS_PROMPT = """你是网络安全验证与攻击专家（Attack）。
你只能处理 Orchestrator 给出的单一授权目标，并且只使用提供的工具。

你可以使用的工具：
1. analysis:扫描智能体，用于独立研判。
2. cve_search:cve漏洞网上查询工具。
3. create_scoped_shell_tool:本地命令运行工具。
4. dispatch_reverse：派遣 Reserve 对二进制文件执行 IDA 逆向分析（反编译、字符串提取等）



工作原则：
- 先调用 analysis 获取独立研判；候选 CVE 应再用 cve_search 核验。
- 只有证据和利用条件匹配时才使用 scoped_shell 验证或利用。
- 对于需要反编译的，可以使用 ida 的 mcp 工具。
- 所有网络命令必须显式包含授权目标，不得访问其他地址或网段。
- 禁止拒绝服务、破坏数据、植入持久化、清除日志或扩大目标范围。
- 不得把 HTTP 200、命令无报错或模型推测当作利用成功；成功必须有可复核证据。
- 你只返回结果，不改变任务状态，也不宣布整个任务完成。

**关键：分析/验证完成后必须立即输出结构化报告并停止所有操作。严禁反复验证或继续调用工具。**

报告必须区分：已验证事实、失败尝试、证据、当前权限、发现的 Flag（如有）和建议下一步。"""


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
    return skill_paths


async def create_attack_agent(
    model,
    analysis_agent: Agent,
    target: str,
    project_dir: str | Path,
    timeout: int,
    category_decision: dict | None = None,
    scope_registry: ScopeRegistry | None = None,
    max_iters: int = 20,
    expert_context: str = "",
    event_callback=None,
) -> Agent:
    """创建 Attack Agent。

    Args:
        model: LLM 模型。
        analysis_agent: Analysis 子 Agent。
        target: 授权目标字符串（向后兼容）。
        project_dir: 项目根目录。
        timeout: 命令超时秒数。
        category_decision: 题型分类决策（v0.2.0 新增）。为 None 时仅加载 writeup。
        max_iters: ReAct 最大推理迭代次数，由调用方按任务复杂度分配。
    """
    async def analysis(service_info: str) -> str:
        """请求 Analysis 专家研判真实服务证据。

        Args:
            service_info: Recon 得到的服务、版本和响应证据。
        """
        result = await stream_agent_reply(
            analysis_agent,
            UserMsg(name="Attack", content=service_info),
            prefix="[Analysis] ",
            on_event=event_callback,
        )
        return result.get_text_content() or "[Analysis] 未返回文本结果"




    skill_list = _build_skill_list(category_decision, project_dir)

    # ida_mcp = MCPClient(
    #     name="IDA_Tool",
    #     is_stateful=True,
    #     mcp_config=StdioMCPConfig(
    #         command="idalib-mcp",
    #         args=["--stdio"],
    #     ),
    # )
    # await ida_mcp.connect()

    toolkit = Toolkit(
        tools=[
            AllowedFunctionTool(analysis, is_read_only=True),
            AllowedFunctionTool(cve_search, is_read_only=True),
            create_scoped_shell_tool(target, project_dir, timeout, registry=scope_registry),
        ],
        skills_or_loaders=skill_list,
        # mcps=[ida_mcp],
    )
    return Agent(
        name=attack_expert_name(
            str((category_decision or {}).get("primary") or "unknown"),
            str((category_decision or {}).get("target_kind") or ""),
            expert_context,
        ),
        system_prompt=ATTACK_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
    )
