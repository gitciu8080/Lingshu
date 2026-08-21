"""Analysis：只进行漏洞研判，不执行命令。"""
from agent.prompt_loader import load_prompt
from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit

from Tools.AgenticMemory import create_query_memory_tool
from Tools.CVE_Search import create_cve_search_tool
from agent.experts import ANALYSIS_EXPERT

ANALYSIS_SYS_PROMPT = load_prompt("ANALYSIS")


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
