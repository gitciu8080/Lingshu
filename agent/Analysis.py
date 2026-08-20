"""Analysis：只进行漏洞研判，不执行命令。"""
from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit

from Tools.AgenticMemory import create_query_memory_tool
from Tools.CVE_Search import create_cve_search_tool
from agent.experts import ANALYSIS_EXPERT

ANALYSIS_SYS_PROMPT = """你是网络安全漏洞分析专家（Analysis）。
你只根据提供的真实侦察证据进行研判，不执行命令，不改变任务状态。
区分“已确认事实、合理推测、仍需验证”，列出候选 CVE、影响条件、误报风险和安全验证建议。
不得把版本相近当作漏洞成立，不得编造 CVE、PoC 或成功结果。输出结构化中文报告。"""


def create_analysis_agent(model, *, offloader=None, context_config=None, state=None) -> Agent:
    return Agent(
        name=ANALYSIS_EXPERT,
        system_prompt=ANALYSIS_SYS_PROMPT,
        model=model,
        react_config=ReActConfig(max_iters=3, interruption_raise_cancelled_error=True),
        toolkit=StrictJSONToolkit(tools=[
            create_cve_search_tool(),
            create_query_memory_tool()
        ]),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
