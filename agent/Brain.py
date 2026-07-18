"""Brain：只负责战略规划，不执行工具。"""
from agentscope.agent import Agent, ReActConfig


BRAIN_SYS_PROMPT = """你是网络安全作战总参谋（Brain）。

你的唯一职责是为已经获得明确授权的安全测试制定阶段性计划，不调用工具、不执行扫描或攻击。
计划必须覆盖：信息收集、漏洞分析、漏洞验证/利用、达成任务目标与收尾。
每个阶段写清输入、退出条件、失败后的回退路线以及需要保留的证据。
不要假设侦察结果，不编造服务、漏洞、凭据或 Flag。输出简洁的中文计划。"""


def create_brain_agent(model) -> Agent:
    return Agent(
        name="Brain",
        system_prompt=BRAIN_SYS_PROMPT,
        model=model,
        react_config=ReActConfig(max_iters=3),
    )
