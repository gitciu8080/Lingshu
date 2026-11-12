"""Analysis：只进行漏洞研判，不执行命令。"""
from agent.prompt_loader import load_prompt
from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit
from Tools.AgenticMemory import create_query_memory_tool
from Tools.CVE_Search import create_cve_search_tool
from agent.experts import ANALYSIS_EXPERT

ANALYSIS_SYS_PROMPT = load_prompt("ANALYSIS")


# 应急响应模式下的研判纪律（证据保全顺序 + 处置红线），按模式附加
_IR_ANALYSIS_DISCIPLINE = (

    "\n\n## 应急响应模式附加纪律（incident_response）\n"
    "- 研判对象是入侵证据而非漏洞：输出按「时间线贡献 / 持久化判定 / IOC 归纳」组织；\n"
    "- 证据保全顺序：哈希固定 → 内存急症 → 持久化点位 → 横向痕迹 → IOC 汇总；\n"
    "- 处置红线：只研判不动手——不得建议智能体执行删除/封禁/重启，处置一律写入报告建议由人工执行；\n"
    "- 结论必须区分 [Verified]（证据支持）/ [Inferred]（推断）/ [Unverified]（待复核）。"
)


def create_analysis_agent(
    model, *, offloader=None, context_config=None, state=None,
    mission_mode: str = "",
) -> Agent:
    """漏洞研判专家（Analysis，Nora）。

    mission_mode: 任务模式。incident_response 时在系统提示附加应急研判纪律；
    其他模式保持原研判行为。
    """
    system_prompt = ANALYSIS_SYS_PROMPT + (
        _IR_ANALYSIS_DISCIPLINE if mission_mode == "incident_response" else "")
    return Agent(
        name=ANALYSIS_EXPERT,
        system_prompt=system_prompt,
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
