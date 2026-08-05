"""Orchestrator：唯一可以修改任务状态的战术决策核心。"""
from collections.abc import Awaitable, Callable
from typing import Any

from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from AgenticMemory import get_experience_hint, save_mission
from TaskState import MissionState, MissionStore, Phase
from Tools.tooling import AllowedFunctionTool, stream_agent_reply

# 计划条目允许的阶段归属与状态取值
_PLAN_PHASES = {"recon", "analysis", "exploitation", "post_exploitation", "complete"}
_PLAN_STATUSES = {"pending", "in_progress", "completed", "failed", "skipped"}


ORCHESTRATOR_SYS_PROMPT = """你是网络安全行动总指挥（Orchestrator）。
你是唯一允许推进任务阶段、记录发现和宣布任务结束的 Agent。

可用能力：
- dispatch_recon：派遣 Recon 做纯被动信息收集（端口/服务/指纹/页面源码）。
- dispatch_attack：派遣 Attack 做分析、验证、利用或目标达成工作。
- dispatch_reverse：派遣 Reserve 对二进制文件执行 IDA 逆向分析（反编译、字符串提取等）。
- request_exploitation_approval：首次执行验证/利用类攻击动作前，请求人工批准。
- update_plan：维护作战计划清单——新增/细化条目，或标记条目状态。
- view_mission_state：查看结构化任务状态。
- complete_mission：仅在成功条件有证据或已达到明确失败条件时结束任务。


行动纪律（严格遵守顺序）：
1. 先用 dispatch_recon 做被动侦察，Recon 只负责收集，不验证不利用。
2. 侦察完毕后，把发现汇总成方案，明确要做什么、怎么做、预期拿到什么证据。
3. 拿出方案后，先调用 request_exploitation_approval 请求人工批准，
   批准前不得调用 dispatch_attack 做任何验证/利用动作。
4. 批准后，调用 dispatch_attack 执行方案；所有攻击动作通过 Attack 执行，
   不要把主动探测或 payload 验证交给 Recon。
5. 失败后基于证据选择补充侦察（回到步骤 1）或其他候选路径，禁止无依据重复。
6. 只有获得可复核证据后才能标记成功。发现 Flag 时在 complete_mission 中明确提交。
7. 禁止扩大目标范围、拒绝服务、数据破坏、持久化和日志清除。
8. 不得跳过 complete_mission；若迭代耗尽，应如实报告未完成，不能伪造成功。
9. 用 update_plan 维护计划清单：开始某项前标记 in_progress，拿到工具证据后标记
   completed（必须在 evidence 中写明证据摘要）；侦察发现新路径时用 add 补充条目。
   禁止无证据标记完成。"""


def create_orchestrator_agent(
    model,
    recon_agent: Agent,
    attack_agent: Agent,
    reserve_agent:Agent,
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    approval_callback: Callable[[str, dict | None], Awaitable[bool]] | None = None,
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
                content=f"授权目标：{mission.target}\n本轮重点：{focus}\n收集到足够证据后立即输出最终报告，禁止继续调用工具。",
            ),
            prefix="[Recon] ",
            on_event=event_callback,
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
        # 兜底拦截：攻击类动作必须先获得人工批准，
        # 即使 LLM 跳过 request_exploitation_approval 也无法直接进入攻击阶段
        if exploitation and not mission.exploitation_approved:
            return (
                "[拒绝] 该动作将进入攻击阶段（EXPLOITATION），但尚未获得人工批准。"
                "请先调用 request_exploitation_approval 说明行动计划与依据，等待人工批准。"
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
                    f"真实目标信息：\n{target_info}\n\n"
                    "完成分析/验证后立即输出最终报告，禁止继续调用工具。"
                ),
            ),
            prefix="[Attack] ",
            on_event=event_callback,
        )
        report = result.get_text_content() or "[Attack] 未返回文本结果"
        mission.add_attack_step(objective, report)
        store.save(mission)
        return f"[Attack 报告]\n{report}"

    async def dispatch_reverse(binary_path: str, objective: str = "二进制逆向分析") -> str:
        """派遣 Reserve 对指定二进制文件执行逆向分析。

        Args:
            binary_path: 待分析二进制文件的绝对路径（如 /WorkDir/uploads/target.exe）。
            objective: 本轮分析目标，如反编译提取算法、寻找 Flag、分析恶意行为。
        """
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Reserve"
        lower = objective.lower()
        if any(word in lower or word in objective for word in ("exploit", "利用", "patch", "patch")):
            if mission.phase == Phase.ANALYSIS:
                mission.transition(Phase.EXPLOITATION, f"逆向进入利用阶段: {objective}")
        mission.record("Orchestrator", "dispatch_reverse", binary_path=binary_path, objective=objective)
        store.save(mission)
        result = await stream_agent_reply(
            reserve_agent,
            UserMsg(
                name="Orchestrator",
                content=(
                    f"授权目标：{mission.target}\n"
                    f"二进制文件：{binary_path}\n"
                    f"本轮目标：{objective}\n\n"
                    "若 IDA 尚未启动，先用 scoped_shell 执行 idat 加载文件。\n"
                    "分析完成后立即输出最终报告，禁止继续调用工具。"
                ),
            ),
            prefix="[Reserve] ",
            on_event=event_callback,
        )
        report = result.get_text_content() or "[Reserve] 未返回文本结果"
        mission.add_finding("Reserve", report)
        store.save(mission)
        return f"[Reserve 逆向报告]\n{report}"

    async def request_exploitation_approval(reason: str) -> str:
        """首次进入攻击阶段（EXPLOITATION）前，请求人工批准。

        Args:
            reason: 进入攻击阶段的理由，概述计划执行的验证/利用动作及其证据依据。

        系统会自动附加上下文摘要（目标、侦察发现、作战计划等），
        帮助操作员做出有依据的决策。
        """
        if mission.exploitation_approved:
            return "[已批准] 本次任务的攻击阶段已获人工批准，无需重复申请，可直接 dispatch_attack。"
        if approval_callback is None:
            mission.record(
                "Orchestrator", "exploitation_approval_unavailable", reason=reason,
            )
            store.save(mission)
            return (
                "[拒绝] 当前运行环境没有人工审批通道，无法获得攻击授权。"
                "请继续只做分析，或调用 complete_mission 如实结束任务。"
            )

        # ── 构建扫描摘要，帮助操作员决策 ──
        scan_summary: dict[str, Any] = {
            "target": mission.target,
            "goal": mission.goal,
            "phase": mission.phase.value,
            "findings": mission.findings[-10:] if len(mission.findings) > 10 else mission.findings,
            "findings_count": len(mission.findings),
            "plan_items": mission.plan_items,
            "attack_steps": mission.attack_chain[-5:] if len(mission.attack_chain) > 5 else mission.attack_chain,
        }

        approved = await approval_callback(reason, scan_summary)
        mission.record(
            "Orchestrator",
            "exploitation_approval",
            reason=reason,
            approved=approved,
        )
        if approved:
            mission.exploitation_approved = True
            store.save(mission)
            return "[批准] 人工已批准进入攻击阶段，可调用 dispatch_attack 执行验证/利用动作。"
        store.save(mission)
        return (
            "[拒绝] 人工拒绝了本次攻击阶段授权。你可以选择：补充侦察收集更多依据、"
            "调整方案后重新申请批准，或调用 complete_mission 如实报告任务无法继续。"
        )

    def view_mission_state() -> dict:
        """查看当前结构化任务状态。"""
        return mission.to_dict()

    def _push_plan_update() -> None:
        """向 SSE 订阅者推送计划清单全量快照。"""
        if event_callback is not None:
            event_callback(
                "plan_updated",
                items=mission.plan_items,
                phase=mission.phase.value,
            )

    def _find_plan_item(item_id: str) -> dict | None:
        return next(
            (it for it in mission.plan_items if it.get("id") == item_id), None,
        )

    def update_plan(
        action: str,
        item_id: str = "",
        content: str = "",
        phase: str = "",
        status: str = "",
        evidence: str = "",
    ) -> str:
        """维护作战计划清单：新增、细化或标记条目状态。

        Args:
            action: add（新增条目）/ update（修改条目内容或阶段归属）/ mark（标记条目状态）。
            item_id: update/mark 的目标条目 id（如 p2）。
            content: add/update 时的条目描述。
            phase: add/update 时的阶段归属：recon/analysis/exploitation/post_exploitation/complete。
            status: mark 时的目标状态：in_progress/completed/failed/skipped。
            evidence: 标记 completed 时必填的工具证据摘要。
        """
        action = action.strip().lower()
        items = mission.plan_items

        if action == "add":
            if not content.strip():
                return "[拒绝] add 必须提供 content（条目描述）"
            if phase not in _PLAN_PHASES:
                return f"[拒绝] 非法 phase: {phase or '(空)'}，可选: {sorted(_PLAN_PHASES)}"
            max_n = 0
            for it in items:
                suffix = str(it.get("id", ""))[1:]
                if str(it.get("id", "")).startswith("p") and suffix.isdigit():
                    max_n = max(max_n, int(suffix))
            new_item = {
                "id": f"p{max_n + 1}",
                "content": content.strip(),
                "phase": phase,
                "status": "pending",
                "evidence": "",
                "origin": "orchestrator",
            }
            items.append(new_item)
            mission.record("Orchestrator", "plan_item_added", item=new_item)

        elif action == "update":
            target = _find_plan_item(item_id)
            if target is None:
                return f"[拒绝] 未找到计划条目: {item_id or '(空)'}"
            if not content.strip() and not phase:
                return "[拒绝] update 至少需提供 content 或 phase 之一"
            if phase and phase not in _PLAN_PHASES:
                return f"[拒绝] 非法 phase: {phase}，可选: {sorted(_PLAN_PHASES)}"
            if content.strip():
                target["content"] = content.strip()
            if phase:
                target["phase"] = phase
            mission.record(
                "Orchestrator", "plan_item_updated",
                item_id=item_id, content=target["content"], phase=target["phase"],
            )

        elif action == "mark":
            target = _find_plan_item(item_id)
            if target is None:
                return f"[拒绝] 未找到计划条目: {item_id or '(空)'}"
            if status not in _PLAN_STATUSES:
                return f"[拒绝] 非法 status: {status or '(空)'}，可选: {sorted(_PLAN_STATUSES)}"
            # 防伪造闸门：标完成必须附工具证据
            if status == "completed" and not evidence.strip():
                return "[拒绝] 标记 completed 必须在 evidence 中写明工具证据摘要"
            target["status"] = status
            if evidence.strip():
                target["evidence"] = evidence.strip()
            mission.record(
                "Orchestrator", "plan_item_marked",
                item_id=item_id, status=status, evidence=target.get("evidence", ""),
            )

        else:
            return f"[拒绝] 非法 action: {action or '(空)'}，可选: add/update/mark"

        store.save(mission)
        _push_plan_update()
        summary = ", ".join(f"{it['id']}({it['status']})" for it in items)
        return f"[已更新] 计划清单共 {len(items)} 项: {summary}"

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
        # 确定性收尾：残留计划项不依赖 LLM 逐项 mark，终态统一处理
        for item in mission.plan_items:
            if item.get("status") == "in_progress":
                item["status"] = "completed" if success else "failed"
            elif item.get("status") == "pending":
                item["status"] = "skipped"
        store.save(mission)
        _push_plan_update()
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
        AllowedFunctionTool(dispatch_reverse, is_concurrency_safe=False),
        AllowedFunctionTool(view_mission_state, is_read_only=True),
        AllowedFunctionTool(update_plan, is_concurrency_safe=False),
        AllowedFunctionTool(complete_mission, is_concurrency_safe=False),
        AllowedFunctionTool(request_exploitation_approval, is_concurrency_safe=False),
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
