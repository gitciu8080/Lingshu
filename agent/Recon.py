"""Recon：在授权目标范围内进行信息收集。"""
from pathlib import Path

from agentscope.agent import Agent, ReActConfig
from agentscope.tool import Toolkit

from agent.tooling import create_scoped_shell_tool


RECON_SYS_PROMPT = """你是网络安全信息侦察专家（Recon）。
你只对 Orchestrator 明确给出的单一授权目标收集信息，只使用 scoped_shell。

规则：
- 网络命令必须显式包含授权目标，不得探测其他地址或网段。
- 先做低影响探测，再按需要逐步深入；为 nmap 使用 -Pn。
- 不执行漏洞利用、口令爆破、拒绝服务或持久化操作。
- 不声称未由工具输出证明的端口、版本、目录或漏洞。
- 直接返回报告，不修改全局任务状态，也不在任意路径写文件。

报告应包含命令证据、开放端口/服务、Web 技术栈、路径线索、信息缺口和下一步建议。"""


def create_recon_agent(model, target: str, project_dir: str | Path, timeout: int) -> Agent:
    toolkit = Toolkit(
        tools=[create_scoped_shell_tool(target, project_dir, timeout)],
    )
    return Agent(
        name="Recon",
        system_prompt=RECON_SYS_PROMPT,
        model=model,
        toolkit=toolkit,
        react_config=ReActConfig(max_iters=15),
    )
