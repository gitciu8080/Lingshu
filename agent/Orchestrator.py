"""Orchestrator：唯一可以修改任务状态的战术决策核心。"""
from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from AgenticMemory import get_experience_hint, save_mission
from TaskState import MissionState, MissionStore, Phase
from agent.tooling import AllowedFunctionTool, stream_agent_reply


ORCHESTRATOR_SYS_PROMPT = """你是网络安全行动总指挥（Orchestrator）。
你是唯一允许推进任务阶段、记录发现和宣布任务结束的 Agent。

可用能力：
- dispatch_recon：派遣 Recon 收集事实证据。
- dispatch_attack：派遣 Attack 做分析、验证、利用或目标达成工作。
- view_mission_state：查看结构化任务状态。
- complete_mission：仅在成功条件有证据或已达到明确失败条件时结束任务。

决策规则：
1. 先侦察；信息不足时说明缺口并再次侦察。
2. 将原始侦察结果完整交给 Attack，先分析再验证/利用。
3. 失败后基于证据选择补充侦察或其他候选路径，禁止无依据重复。
4. 只有获得可复核证据后才能标记成功。发现 Flag 时在 complete_mission 中明确提交。
5. 所有专业 Agent 只产生结果；你通过工具维护状态。
6. 禁止扩大目标范围、拒绝服务、数据破坏、持久化和日志清除。
7. 不得跳过 complete_mission；若迭代耗尽，应如实报告未完成，不能伪造成功。"""


def create_orchestrator_agent(
    model,
    recon_agent: Agent,
    attack_agent: Agent,
    mission: MissionState,
    store: MissionStore,
) -> Agent:
    async def dispatch_recon(focus: str = "全面但低影响的信息收集") -> str:
        """派遣 Recon 对本次授权目标进行信息收集。

        Args:
            focus: 本轮需要补齐的具体信息或扫描重点。
        """
        if mission.phase not in {Phase.RECON, Phase.ANALYSIS, Phase.EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Recon"
        if mission.phase != Phase.RECON:
            mission.transition(Phase.RECON, f"需要补充侦察: {focus}")
        mission.record("Orchestrator", "dispatch_recon", focus=focus)
        store.save(mission)
        result = await stream_agent_reply(
            recon_agent,
            UserMsg(
                name="Orchestrator",
                content=f"授权目标：{mission.target}\n本轮重点：{focus}\n只返回真实工具证据和侦察报告。",
            ),
            prefix="[Recon] ",
        )
        report = result.get_text_content() or "[Recon] 未返回文本结果"
        mission.add_finding("Recon", report)
        mission.transition(Phase.ANALYSIS, "收到新的侦察证据")
        store.save(mission)
        return f"[Recon 侦察报告]\n{report}"

    async def dispatch_attack(target_info: str, objective: str = "漏洞分析") -> str:
        """派遣 Attack 分析或验证当前授权目标。

        Args:
            target_info: 来自 Recon 的服务、版本、端口和响应证据。
            objective: 本轮目标，如漏洞分析、漏洞验证、获取初始访问或寻找 Flag。
        """
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Attack"
        lower = objective.lower()
        exploitation = any(
            word in lower or word in objective
            for word in ("exploit", "验证", "利用", "访问", "shell", "flag", "提权")
        )
        if exploitation and mission.phase == Phase.ANALYSIS:
            mission.transition(Phase.EXPLOITATION, f"开始执行: {objective}")
        if any(word in lower or word in objective for word in ("flag", "post", "提权")):
            if mission.phase == Phase.EXPLOITATION:
                mission.transition(Phase.POST_EXPLOITATION, f"开始执行: {objective}")
        mission.record("Orchestrator", "dispatch_attack", objective=objective)
        store.save(mission)
        result = await stream_agent_reply(
            attack_agent,
            UserMsg(
                name="Orchestrator",
                content=(
                    f"授权目标：{mission.target}\n本轮目标：{objective}\n\n"
                    f"真实目标信息：\n{target_info}"
                ),
            ),
            prefix="[Attack] ",
        )
        report = result.get_text_content() or "[Attack] 未返回文本结果"
        mission.add_attack_step(objective, report)
        store.save(mission)
        return f"[Attack 报告]\n{report}"

    def view_mission_state() -> dict:
        """查看当前结构化任务状态。"""
        return mission.to_dict()

    def complete_mission(success: bool, summary: str, flag: str = "") -> str:
        """结束任务并保存长期经验。

        Args:
            success: 是否已用证据确认达成用户目标。
            summary: 包含证据、攻击链、失败尝试和结论的任务总结。
            flag: 已确认的 Flag；未发现时必须留空。
        """
        if mission.phase in {Phase.COMPLETED, Phase.FAILED}:
            return "[拒绝] 任务已经结束"
        mission.flag = flag.strip() or None
        mission.success = bool(success)
        mission.summary = summary
        terminal = Phase.COMPLETED if success else Phase.FAILED
        mission.transition(terminal, "Orchestrator 提交最终任务结论")
        store.save(mission)
        save_mission(
            target=mission.target,
            goal=mission.goal,
            plan=mission.plan,
            attack_chain=mission.attack_chain,
            success=mission.success,
            summary=summary,
            flag=mission.flag,
        )
        return f"[任务已结束] success={mission.success}, flag={mission.flag or '未发现'}"

    tools = [
        AllowedFunctionTool(dispatch_recon, is_concurrency_safe=False),
        AllowedFunctionTool(dispatch_attack, is_concurrency_safe=False),
        AllowedFunctionTool(view_mission_state, is_read_only=True),
        AllowedFunctionTool(complete_mission, is_concurrency_safe=False),
    ]
    prompt = ORCHESTRATOR_SYS_PROMPT
    experience_hint = get_experience_hint()
    if experience_hint:
        prompt += f"\n\n{experience_hint}"
    return Agent(
        name="Orchestrator",
        system_prompt=prompt,
        model=model,
        toolkit=Toolkit(tools=tools),
        react_config=ReActConfig(max_iters=30),
    )
