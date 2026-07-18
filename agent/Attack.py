"""Attack：在授权范围内完成分析、验证和利用。"""
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from agent.CVE_Search import cve_search
from agent.tooling import AllowedFunctionTool, create_scoped_shell_tool


ATTACK_SYS_PROMPT = """你是网络安全验证与攻击专家（Attack）。
你只能处理 Orchestrator 给出的单一授权目标，并且只使用提供的工具。

工作原则：
- 先调用 analysis 获取独立研判；候选 CVE 应再用 cve_search 核验。
- 只有证据和利用条件匹配时才使用 scoped_shell 验证或利用。
- 所有网络命令必须显式包含授权目标，不得访问其他地址或网段。
- 禁止拒绝服务、破坏数据、植入持久化、清除日志或扩大目标范围。
- 不得把 HTTP 200、命令无报错或模型推测当作利用成功；成功必须有可复核证据。
- 你只返回结果，不改变任务状态，也不宣布整个任务完成。

报告必须区分：已验证事实、失败尝试、证据、当前权限、发现的 Flag（如有）和建议下一步。"""


def create_attack_agent(
    model,
    analysis_agent: Agent,
    target: str,
    project_dir: str | Path,
    timeout: int,
) -> Agent:
    async def analysis(service_info: str) -> str:
        """请求 Analysis 专家研判真实服务证据。

        Args:
            service_info: Recon 得到的服务、版本和响应证据。
        """
        result = await analysis_agent.reply(
            UserMsg(name="Attack", content=service_info),
        )
        return result.get_text_content() or "[Analysis] 未返回文本结果"

    toolkit = Toolkit(
        tools=[
            AllowedFunctionTool(analysis, is_read_only=True),
            AllowedFunctionTool(cve_search, is_read_only=True),
            create_scoped_shell_tool(target, project_dir, timeout),
        ],
        skills_or_loaders=["Skills/ctf-skills/ctf-web"],
    )
    return Agent(
        name="Attack",
        system_prompt=ATTACK_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=20),
    )
