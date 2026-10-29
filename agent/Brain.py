"""Brain：只负责战略规划，通过 SubmitPlan 原子提交结构化计划。"""
from agent.prompt_loader import load_prompt
from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit
from agent.experts import BRAIN_EXPERT


BRAIN_SYS_PROMPT = load_prompt("BRAIN")


def create_brain_agent(
    model,
    tools: list | None = None,
    max_iters: int = 15,
    rag_middleware=None,
    *,
    plan_tool_mode: str = "batch",
    offloader=None,
    context_config=None,
    state=None,
    mission_mode: str = "",
) -> Agent:
    """创建战略规划 Agent。

    部分本地 Qwen Agent 模型可稳定调用扁平参数工具，但不能可靠构造
    ``items[]`` 嵌套数组；``item`` 模式保留旧版逐条 AddPlan 契约。
    """
    system_prompt = BRAIN_SYS_PROMPT
    # IR 计划阶段白名单：应急响应任务的计划项使用 IR 四阶段语义
    if mission_mode == "incident_response":
        ir_phases = "ir_identification / ir_containment / ir_eradication / ir_recovery / complete"
        system_prompt = system_prompt.replace(
            "recon / analysis / exploitation / post_exploitation / complete",
            ir_phases,
        )
    if plan_tool_mode == "item":
        system_prompt = system_prompt.replace("SubmitPlan", "AddPlan").replace(
            "先用 AddPlan 工具**一次性**提交 4~8 条笼统的结构化计划（不得拆成多次\n"
            "工具调用，执行细节由 Orchestrator 在实施中细化维护）。items 中的 id 从 1\n"
            "连续递增，content 用一句话概括该步要达成什么（不要包含具体命令或参数），phase 只能取值：\n"
            "recon / analysis / exploitation / post_exploitation / complete。\n"
            "全部登记完成后，再输出人类可读的计划正文。",
            "先用 AddPlan 工具逐条登记 4~8 条笼统的结构化计划（每条调用一次）。"
            "id 从 1 连续递增，content 用一句话概括该步要达成什么（不要包含具体命令或参数），"
            "phase 只能取值：recon / analysis / exploitation / post_exploitation / complete。"
            "全部登记完成后，再输出人类可读的计划正文。",
        )
    return Agent(
        name=BRAIN_EXPERT,
        system_prompt=system_prompt,
        model=model,
        toolkit=StrictJSONToolkit(tools=tools or []),
        middlewares=[rag_middleware] if rag_middleware is not None else [],
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
