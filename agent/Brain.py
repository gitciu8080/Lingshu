"""Brain：只负责战略规划，通过 SubmitPlan 原子提交结构化计划。"""
from agentscope.agent import Agent, ReActConfig
from Tools.tooling import StrictJSONToolkit
from agent.experts import BRAIN_EXPERT


BRAIN_SYS_PROMPT = """你是网络安全作战总参谋（Brain）。

## 职责
为已获授权安全测试制定阶段性计划。除 SubmitPlan 批量登记计划外，
不执行扫描或攻击。若提供 search_knowledge 工具，可按需检索本地 Writeup
以完善策略；检索结果只是参考，不能替代真实侦察证据。

## 输入信息
你将收到：
- 授权目标（IP:端口或文件路径）和任务目标
- 目标类型（network/archive/single_file/directory）
- 系统初步题型分类（primary + secondary + 置信度 + 证据）
- 文件解压清单（如为归档目标）

## 计划要素
每个阶段写清：输入、动作、退出条件、失败回退、证据保留。
覆盖信息收集→漏洞分析→验证/利用→达成目标与收尾。

## 题型判断规则
- 系统已给出初步分类，你**不得擅自修改正式题型**。
- 若你认为题型需要修正，输出结构化建议：

  **分类修正建议**
  proposed_category: <题型>
  reason: <依据>
  requires_orchestrator_approval: true

- 若证据不足，在计划中加入「重新分类检查点」：
  注明侦察后根据哪些证据（如文件类型/服务版本）来确认最终题型。

## 约束
- 不假设侦察结果，不编造服务、漏洞、凭据或 Flag。
- 输出简洁中文计划。
- 输出plan成功后进入下一环节

## 输出格式
先用 SubmitPlan 工具**一次性**提交 4~8 条笼统的结构化计划（不得拆成多次
工具调用，执行细节由 Orchestrator 在实施中细化维护）。items 中的 id 从 1
连续递增，content 用一句话概括该步要达成什么（不要包含具体命令或参数），phase 只能取值：
recon / analysis / exploitation / post_exploitation / complete。
全部登记完成后，再输出人类可读的计划正文。"""


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
) -> Agent:
    """创建战略规划 Agent。

    部分本地 Qwen Agent 模型可稳定调用扁平参数工具，但不能可靠构造
    ``items[]`` 嵌套数组；``item`` 模式保留旧版逐条 AddPlan 契约。
    """
    system_prompt = BRAIN_SYS_PROMPT
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
