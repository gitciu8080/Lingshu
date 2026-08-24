"""Orchestrator：唯一可以修改任务状态的战术决策核心。"""
from agent.prompt_loader import load_prompt
import asyncio
import httpx
import re
from collections.abc import Awaitable, Callable
from typing import Any
from datetime import datetime
from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg

from Tools.AgenticMemory import (
    create_query_memory_tool,
    extract_lessons,
    save_mission,
)
from core.TaskState import MissionState, MissionStore, Phase
from Tools.fingerprint import (
    compute_action_fingerprint,
    error_type,
    mark_plan_item_blocked,
    should_meltdown,
)
from Tools.Plan import (
    create_add_plan_tool,
    create_delete_plan_tool,
    create_list_plan_tool,
    create_update_plan_tool,
    push_plan_update,
)
from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import (
    AgentMaxIterationsError,
    StrictJSONToolkit,
    AllowedFunctionTool,
    run_interruptible_agent_reply,
)
from agent.experts import ORCHESTRATOR_EXPERT
from agent.categorize import extract_recon_signals


ORCHESTRATOR_SYS_PROMPT = load_prompt("ORCHESTRATOR")


def create_orchestrator_agent(
    model,
    recon_agent: Agent,
    attack_agent: Agent,
    reserve_agent: Agent,
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    approval_callback: Callable[[str, dict | None], Awaitable[bool | dict[str, Any]]] | None = None,
    scope_registry: ScopeRegistry | None = None,
    scope_auditor: Agent | None = None,
    steering_state: dict[str, Any] | None = None,
    nss_context: dict[str, Any] | None = None,
    slab_context: dict[str, Any] | None = None,
    max_iters: int = 30,
    *,
    knowledge_context_provider: Callable[[str, str], Awaitable[str]] | None = None,
    offloader=None,
    context_config=None,
    state=None,
) -> Agent:
    steering = steering_state if steering_state is not None else {"pending": None, "processed": False, "queue": []}
    steering.setdefault("queue", [])

    def _check_steering() -> str | None:
        """入口检查 + 中断后检查：消费待处理的用户指令。"""
        if steering.get("cancel_requested"):
            raise asyncio.CancelledError()
        # 新情报统一交由 run_mission 主循环注入成下一轮 Orchestrator 输入。
        # 这里不消费指令，避免子 Agent 被取消时消息只留在工具返回值中而丢失。
        if steering.get("queue") or (
            steering.get("pending") and not steering.get("processed")
        ):
            raise asyncio.CancelledError()
        return None

    async def dispatch_recon(
        focus: str = "全面但低影响的信息收集",
        hypothesis_id: str = "",
    ) -> str:
        """派遣 Recon 对本次授权目标进行信息收集。

        Args:
            focus: 本轮需要补齐的具体信息或扫描重点。
            hypothesis_id: 本动作要验证的结构化假设 ID；纯探索可留空。
        """
        # 入口检查：是否有待处理的用户指令（无需等待子 Agent 取消）
        msg = _check_steering()
        if msg is not None:
            return msg
        # 本地附件分析属于 Recon 能力，即使任务已进入 post_exploitation
        # 也允许回补；远程利用仍由 Attack 的能力闸门控制。
        if mission.phase not in {
            Phase.RECON, Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION,
        }:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Recon"
        attempt = mission.begin_attempt(
            "recon",
            recon_agent.name,
            mission.target,
            {"focus": focus, "hypothesis_id": hypothesis_id},
        )
        # post_exploitation 中的本地补侦不回退任务阶段，避免完成 Recon 后
        # 远程 Attack 因阶段变成 RECON 而被错误拒绝。
        if mission.phase != Phase.RECON and mission.phase != Phase.POST_EXPLOITATION:
            mission.transition(Phase.RECON, f"需要补充侦察: {focus}")
        mission.record("Orchestrator", "dispatch_recon", focus=focus)
        store.checkpoint(mission, "recon_dispatch_before")
        try:
            result = await run_interruptible_agent_reply(
                recon_agent,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        f"授权目标：{mission.target}\n本轮重点：{focus[:2000]}\n"
                        "收集到足够证据后立即输出最终报告，禁止继续调用工具。"
                    ),
                ),
                prefix="[Recon] ",
                on_event=event_callback,
            )
            report = result.get_text_content() or "[Recon] 未返回文本结果"
        except AgentMaxIterationsError as exc:
            mission.finish_attempt(attempt, "failure", str(exc), information_gain="none")
            mission.record("Orchestrator", "recon_max_iters_exceeded", error=str(exc))
            store.save(mission)
            return (
                f"[Recon 超迭代] {exc}。"
                f"请缩小本轮 focus 范围重新调度，或改用其他路径。"
            )
        except asyncio.CancelledError:
            # 不在此处消费 steering：统一由主循环捕获 CancelledError 后注入，
            # 避免指令被消费但 Orchestrator reply 又被取消导致指令丢失。
            mission.finish_attempt(
                attempt, "interrupted", "Recon 被用户指令或停止请求中断",
            )
            store.checkpoint(mission, "recon_interrupted")
            raise
        before_evidence = len(mission.evidence_records)
        evidence = mission.add_evidence(
            recon_agent.name,
            "recon_report",
            report,
            category=str((mission.category_decision or {}).get("primary") or ""),
            confidence=float((mission.category_decision or {}).get("confidence") or 0.0),
        )
        fact_count = len(mission.facts)
        for signal in extract_recon_signals([report]):
            mission.add_fact(
                signal.content,
                recon_agent.name,
                [evidence.id],
                category=signal.category,
                confidence=signal.confidence,
            )
        mission.add_finding("Recon", report)
        mission.finish_attempt(
            attempt,
            "success",
            report,
            [evidence.id],
            "medium" if len(mission.facts) > fact_count else (
                "low" if len(mission.evidence_records) > before_evidence else "none"
            ),
        )
        mission.transition(Phase.ANALYSIS, "收到新的侦察证据")
        store.checkpoint(mission, "recon_report_received")
        knowledge_note = ""
        if knowledge_context_provider is not None:
            knowledge = await knowledge_context_provider(
                "Orchestrator",
                f"Recon 新证据后的知识缺口：{focus[:1000]}",
            )
            if knowledge:
                knowledge_note = (
                    "\n\n[Knowledge Context 更新（仅供参考，不是事实/证据）]\n"
                    f"{knowledge}"
                )
        return f"[Recon 侦察报告]\n{report}{knowledge_note}"

    async def dispatch_attack(
        target_info: str,
        objective: str = "漏洞分析",
        service: str = "",
        cve: str = "",
        hypothesis_id: str = "",
    ) -> str:
        """派遣 Attack 分析或验证当前授权目标。

        Args:
            target_info: 来自 Recon 的服务、版本、端口和响应证据。
            objective: 本轮目标，如漏洞分析、漏洞验证、获取初始访问或寻找 Flag。
            service: 侦察已确认的服务名（如 "Apache 2.4.49"），供长期记忆登记；未知留空。
            cve: 已确认的 CVE 编号（如 "CVE-2021-41773"），未确认不得填写。
            hypothesis_id: 本动作要验证的结构化假设 ID。
        """
        msg = _check_steering()
        if msg is not None:
            return msg
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Attack"
        # P3 去重（v0.3.0 升级为动作指纹）：工具名+目标+规范化参数+目标
        # 描述+证据版本，防止只改写 objective 措辞绕过；相同动作+相同
        # 错误达到阈值自动熔断。
        evidence_version = len(mission.findings) + len(mission.attack_chain)
        fingerprint = compute_action_fingerprint(
            "dispatch_attack", mission.target,
            {"target_info": target_info, "objective": objective, "service": service, "cve": cve,
             "hypothesis_id": hypothesis_id},
            objective, evidence_version,
        )
        if should_meltdown(mission.retry_counters, fingerprint):
            mission.record(
                "Orchestrator",
                "attack_meltdown",
                objective=objective,
                fingerprint=fingerprint,
                retries=mission.retry_counters.get(fingerprint, 0),
            )
            marked = mark_plan_item_blocked(
                mission, fingerprint, f"相同动作+相同错误已执行 {mission.retry_counters.get(fingerprint, 0)} 次，自动熔断",
            )
            store.save(mission)
            blocked_note = f"（已熔断计划项 {marked}）" if marked else ""
            return (
                f"[熔断] 该 Attack 动作（指纹 {fingerprint[:12]}…）已连续失败达到阈值，"
                f"禁止通过改写措辞重试。请补充侦察收集新证据后再调度。{blocked_note}"
            )
        # 与最近一次执行的动作指纹完全相同且无新证据 → 拒绝（无意义重放）
        if mission.last_action_fingerprint == fingerprint and evidence_version == len(mission.attack_chain):
            mission.record(
                "Orchestrator",
                "attack_duplicate_rejected",
                objective=objective,
                fingerprint=fingerprint,
            )
            store.save(mission)
            return (
                "[拒绝] 该 Attack 动作与最近一次完全相同（指纹一致）且无新证据。"
                "请基于最新侦察/攻击结果调整 target_info 或 objective，"
                "或先补充侦察收集新证据后再调度。"
            )
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
        attempt = mission.begin_attempt(
            "attack",
            attack_agent.name,
            mission.target,
            {
                "target_info": target_info,
                "objective": objective,
                "service": service,
                "cve": cve,
                "hypothesis_id": hypothesis_id,
            },
        )
        if exploitation and mission.phase == Phase.ANALYSIS:
            mission.transition(Phase.EXPLOITATION, f"开始执行: {objective}")
        if any(word in lower or word in objective for word in ("flag", "post", "提权")):
            if mission.phase == Phase.EXPLOITATION:
                mission.transition(Phase.POST_EXPLOITATION, f"开始执行: {objective}")
        mission.record("Orchestrator", "dispatch_attack", objective=objective)
        store.checkpoint(mission, "attack_dispatch_before")
        store.save(mission)
        attack_knowledge = ""
        if knowledge_context_provider is not None:
            try:
                attack_knowledge = await knowledge_context_provider(
                    "Attack",
                    f"本轮目标：{objective[:700]}；服务：{service[:300]}；CVE：{cve[:80]}",
                )
            except UnicodeDecodeError as exc:
                mission.finish_attempt(attempt, "failure", f"QueryMemory 后端损坏: {exc}")
                mission.record("Orchestrator", "memory_backend_error", error=str(exc))
                store.save(mission)
                return f"[QueryMemory 后端错误] {exc}。不削弱当前 Hypothesis，请改用无记忆上下文重试。"
            except KeyError as exc:
                mission.finish_attempt(attempt, "failure", f"知识上下文协议字段缺失: {exc}")
                mission.record("Orchestrator", "knowledge_protocol_error", missing_field=str(exc))
                store.save(mission)
                return f"[协议错误] 知识上下文缺少字段 {exc}，未执行 Attack。"
        knowledge_section = (
            "\n\nKnowledge Context（本地知识库参考，不是当前目标事实/证据）：\n"
            f"{attack_knowledge}\n"
            "必须用真实目标信息核验，不能把该参考直接写成已验证结论。"
            if attack_knowledge else ""
        )
        try:
            result = await run_interruptible_agent_reply(
                attack_agent,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        f"授权目标：{mission.target}\n本轮目标：{objective[:1500]}\n\n"
                        f"真实目标信息（当前相关证据）：\n{target_info[:8000]}\n\n"
                        f"{knowledge_section}\n\n"
                        "完成分析/验证后立即输出最终报告，禁止继续调用工具。"
                    ),
                ),
                prefix="[Attack] ",
                on_event=event_callback,
            )
            report = result.get_text_content() or "[Attack] 未返回文本结果"
            if report.strip().strip("\"'") == "task_overview":
                mission.finish_attempt(attempt, "failure", "Attack 响应缺少结构化 task_overview")
                mission.record("Orchestrator", "attack_protocol_error", missing_field="task_overview")
                store.save(mission)
                return "[Attack 协议错误] 响应仅返回 task_overview，专家本轮不可用；不削弱当前 Hypothesis。"
        except AgentMaxIterationsError as exc:
            # 超迭代：写入失败步骤（保审计 + 供 P3 去重），返回明确结果
            mission.add_attack_step(objective, f"[Attack 超迭代] {exc}，本轮未产出有效结果")
            mission.finish_attempt(attempt, "failure", str(exc), information_gain="none")
            store.save(mission)
            return (
                f"[Attack 超迭代] {exc}。"
                f"请基于已有证据调整 objective 或补充侦察，避免重复调度。"
            )
        except KeyError as exc:
            mission.finish_attempt(attempt, "failure", f"Attack 响应协议字段缺失: {exc}")
            mission.record("Orchestrator", "attack_protocol_error", missing_field=str(exc))
            store.save(mission)
            return f"[Attack 协议错误] 缺少响应字段 {exc}，专家本轮不可用；不削弱当前 Hypothesis。"
        except asyncio.CancelledError:
            # 不在此处消费 steering：统一由主循环捕获 CancelledError 后注入。
            mission.finish_attempt(
                attempt, "interrupted", "Attack 被用户指令或停止请求中断",
            )
            store.checkpoint(mission, "attack_interrupted")
            raise
        before_evidence = len(mission.evidence_records)
        evidence = mission.add_evidence(
            attack_agent.name,
            "attack_report",
            report,
            category=str((mission.category_decision or {}).get("primary") or ""),
            confidence=0.8,
        )
        fact_ids_before = len(mission.facts)
        flag_match = re.search(r"(?:[A-Za-z0-9_]+)?flag\{[^{}\r\n]+\}|[A-Za-z0-9_]+\{[^{}\r\n]+\}", report, re.IGNORECASE)
        if flag_match:
            mission.add_fact(
                f"Attack 报告中发现待验证 Flag 候选：{flag_match.group(0)}",
                attack_agent.name,
                [evidence.id],
                category=str((mission.category_decision or {}).get("primary") or ""),
                confidence=0.85,
            )
        mission.add_attack_step(objective, report, service, cve)
        mission.finish_attempt(
            attempt,
            "success",
            report,
            [evidence.id],
            "high" if len(mission.facts) > fact_ids_before else (
                "low" if len(mission.evidence_records) > before_evidence else "none"
            ),
        )
        # 循环收敛：记录指纹与错误类型计数（确定性错误按类型累计；
        # 无确定性错误或结果含成功信号时不再累加，避免误熔断）
        mission.last_action_fingerprint = fingerprint
        err = error_type(report)
        if err is not None and "成功" not in report and "flag{" not in report.lower():
            mission.retry_counters[fingerprint] = (
                mission.retry_counters.get(fingerprint, 0) + 1
            )
            mission.record(
                "Orchestrator", "attack_error_counted",
                error_type=err, fingerprint=fingerprint,
                retries=mission.retry_counters[fingerprint],
            )
        store.checkpoint(mission, "attack_report_received")
        return f"[Attack 报告]\n{report}"

    async def dispatch_reverse(
        binary_path: str,
        objective: str = "二进制逆向分析",
        hypothesis_id: str = "",
    ) -> str:
        """派遣 Reserve 对指定二进制文件执行逆向分析。

        Args:
            binary_path: 待分析二进制文件的绝对路径（如 /WorkDir/uploads/target.exe）。
            objective: 本轮分析目标，如反编译提取算法、寻找 Flag、分析恶意行为。
            hypothesis_id: 本动作要验证的结构化假设 ID。
        """
        msg = _check_steering()
        if msg is not None:
            return msg
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Reserve"
        lower = objective.lower()
        attempt = mission.begin_attempt(
            "reverse",
            reserve_agent.name,
            mission.target,
            {"binary_path": binary_path, "objective": objective,
             "hypothesis_id": hypothesis_id},
        )
        if any(word in lower or word in objective for word in ("exploit", "利用", "patch")):
            if mission.phase == Phase.ANALYSIS:
                mission.transition(Phase.EXPLOITATION, f"逆向进入利用阶段: {objective}")
        mission.record("Orchestrator", "dispatch_reverse", binary_path=binary_path, objective=objective)
        store.save(mission)
        try:
            result = await run_interruptible_agent_reply(
                reserve_agent,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        f"授权目标：{mission.target}\n"
                        f"二进制文件：{binary_path}\n"
                        f"本轮目标：{objective[:1500]}\n\n"
                        "先调用 ida_open_binary 打开文件并保存 database 会话 ID，"
                        "禁止手动启动 idat 或直接调用 idb_open；需要动态验证时使用 "
                        "gdb_create_session，结束后关闭 GDB 会话。\n"
                        "分析完成后立即输出最终报告，禁止继续调用工具。"
                    ),
                ),
                prefix="[Reserve] ",
                on_event=event_callback,
            )
            report = result.get_text_content() or "[Reserve] 未返回文本结果"
        except AgentMaxIterationsError as exc:
            mission.finish_attempt(attempt, "failure", str(exc), information_gain="none")
            mission.record("Orchestrator", "reverse_max_iters_exceeded", error=str(exc))
            store.save(mission)
            return (
                f"[Reserve 超迭代] {exc}。"
                f"请缩小分析目标后重新调度，或改用其他路径。"
            )
        except asyncio.CancelledError:
            mission.finish_attempt(
                attempt, "interrupted", "Reserve 被用户指令或停止请求中断",
            )
            store.checkpoint(mission, "reverse_interrupted")
            raise
        before_evidence = len(mission.evidence_records)
        evidence = mission.add_evidence(
            reserve_agent.name,
            "reverse_report",
            report,
            artifact=binary_path,
            category=str((mission.category_decision or {}).get("primary") or ""),
            confidence=0.85,
        )
        fact_count = len(mission.facts)
        for signal in extract_recon_signals([report]):
            mission.add_fact(
                signal.content,
                reserve_agent.name,
                [evidence.id],
                category=signal.category,
                confidence=signal.confidence,
            )
        mission.add_finding("Reserve", report)
        mission.finish_attempt(
            attempt,
            "success",
            report,
            [evidence.id],
            "medium" if len(mission.facts) > fact_count else (
                "low" if len(mission.evidence_records) > before_evidence else "none"
            ),
        )
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
            mission.exploitation_approval_status = "unavailable"
            mission.exploitation_approval_decision = "审批通道不可用"
            mission.exploitation_approval_resolved_at = datetime.now().astimezone().isoformat()
            mission.record(
                "Orchestrator", "exploitation_approval_unavailable", reason=reason,
            )
            store.save(mission)
            return (
                "[拒绝] 当前运行环境没有人工审批通道，无法获得攻击授权。"
                "请继续只做分析，或调用 complete_mission 如实结束任务。"
            )

        pending_plan_steps = [
            str(item.get("content") or "")
            for item in mission.plan_items
            if item.get("status") in {"pending", "in_progress"} and item.get("content")
        ]
        evidence_hint = (
            str(mission.findings[-1].get("report") or "")[:240]
            if mission.findings else "当前仅有计划上下文，执行前需再次核验证据"
        )
        base_steps = pending_plan_steps[:3] or ["依据现有证据确认目标与利用前置条件"]
        # 固定生成三个不同风险/深度的候选方案；用户可选择并调整执行优先级。
        approval_options: list[dict[str, Any]] = [
            {
                "id": "minimal-validation",
                "title": "最小化安全验证",
                "risk": "低",
                "summary": "优先使用单次、低影响、可回滚的验证动作确认漏洞，不扩大战果。",
                "steps": [base_steps[0], "执行最小化 PoC 并保存可复核证据", "获得验证结论后调用 complete_mission 或 continue 推进"],
            },
            {
                "id": "evidence-driven",
                "title": "证据驱动验证",
                "risk": "中",
                "summary": "按侦察证据和作战计划逐项验证，兼顾覆盖率与影响控制。",
                "steps": base_steps + ["确认成功条件、失败尝试与风险边界"],
            },
            {
                "id": "goal-oriented",
                "title": "目标导向验证",
                "risk": "中高",
                "summary": f"围绕任务目标“{mission.goal}”优先验证最可能形成完整攻击链的路径。",
                "steps": ["优先处理最高置信度攻击路径", *base_steps[:2], "达到任务目标或边界条件后调用 complete_mission 或 continue 推进"],
            },
        ]

        # ── 构建扫描摘要，帮助操作员决策 ──
        scan_summary: dict[str, Any] = {
            "target": mission.target,
            "goal": mission.goal,
            "phase": mission.phase.value,
            "findings": mission.findings[-10:] if len(mission.findings) > 10 else mission.findings,
            "findings_count": len(mission.findings),
            "plan_items": mission.plan_items,
            "attack_steps": mission.attack_chain[-5:] if len(mission.attack_chain) > 5 else mission.attack_chain,
            "evidence_hint": evidence_hint,
            "approval_options": approval_options,
        }

        mission.exploitation_approval_status = "pending"
        mission.exploitation_approval_decision = ""
        mission.exploitation_approval_requested_at = datetime.now().astimezone().isoformat()
        mission.exploitation_approval_resolved_at = ""
        store.save(mission)
        approval_result = await approval_callback(reason, scan_summary)
        if isinstance(approval_result, dict):
            approved = bool(approval_result.get("approved"))
            selected_id = str(approval_result.get("selected_plan_id") or approval_options[0]["id"])
            selected_option = next(
                (option for option in approval_options if option["id"] == selected_id),
                approval_options[0],
            )
            priority_order = [
                str(value) for value in approval_result.get("priority_order", [])
                if any(option["id"] == str(value) for option in approval_options)
            ]
            for option in approval_options:
                if option["id"] not in priority_order:
                    priority_order.append(option["id"])
            decision = str(approval_result.get("decision") or ("批准" if approved else "拒绝"))
        else:
            approved = bool(approval_result)
            selected_option = approval_options[0]
            priority_order = [option["id"] for option in approval_options]
            decision = "批准" if approved else "拒绝"
        mission.record(
            "Orchestrator",
            "exploitation_approval",
            reason=reason,
            approved=approved,
            decision=decision,
            selected_plan_id=selected_option["id"],
            priority_order=priority_order,
        )
        mission.exploitation_approval_decision = decision
        mission.exploitation_approval_resolved_at = datetime.now().astimezone().isoformat()
        if approved:
            mission.exploitation_approved = True
            mission.exploitation_approval_status = "approved"
            mission.approved_attack_plan = {
                "selected": selected_option,
                "priority_order": priority_order,
                "approved_at_phase": mission.phase.value,
            }
            # 审批结果入检查点：崩溃恢复后不重复询问常规利用审批
            store.checkpoint(mission, "exploitation_approved")
            return (
                "[批准] 人工已批准进入攻击阶段。\n"
                f"选定方案：{selected_option['title']}（{selected_option['id']}）\n"
                f"方案优先级：{' > '.join(priority_order)}\n"
                "后续 dispatch_attack 必须优先遵循选定方案及用户调整后的顺序。"
            )
        mission.exploitation_approved = False
        mission.exploitation_approval_status = (
            "recon_requested" if "补充侦察" in decision else "denied"
        )
        store.save(mission)
        return (
            "[拒绝] 人工拒绝了本次攻击阶段授权。你可以选择：补充侦察收集更多依据、"
            "调整方案后重新申请批准，或调用 complete_mission 如实报告任务无法继续。"
        )

    async def request_scope_expansion(ip_or_cidr: str, evidence: str, reason: str = "") -> str:
        """请求将内网 IP 或网段纳入授权范围，经 ScopeAuditor 审核后生效。

        Args:
            ip_or_cidr: 待授权的 IP 地址（如 10.42.3.240）或网段（如 10.42.0.0/16）。
            evidence: 证据原文，必须包含该 IP 在侦察/攻击报告中的出现位置
                      （如 "Jolokia remoteAddr=10.42.3.240"）。
            reason: 补充说明为何需要访问该 IP（可选）。
        """
        if scope_registry is None:
            return "[拒绝] 授权范围注册表不可用，无法扩容"
        if scope_auditor is None:
            return "[拒绝] ScopeAuditor 未配置，无法审核扩容请求"

        import ipaddress
        # 基础格式校验
        try:
            if "/" in ip_or_cidr:
                ipaddress.ip_network(ip_or_cidr, strict=False)
            else:
                ipaddress.ip_address(ip_or_cidr)
        except ValueError:
            return f"[拒绝] 无效的 IP/CIDR 格式: {ip_or_cidr}"

        # 已授权直接返回
        if "/" not in ip_or_cidr and scope_registry.is_ip_allowed(ip_or_cidr):
            return f"[已授权] {ip_or_cidr} 已在授权范围内，无需重复申请"

        # 收集近期证据供 ScopeAuditor 审核
        recent_reports = []
        for f in mission.findings[-5:]:
            recent_reports.append(f"[{f.get('source','?')}] {f.get('report','')[:800]}")
        for a in mission.attack_chain[-3:]:
            recent_reports.append(f"[Attack:{a.get('objective','?')}] {a.get('report','')[:800]}")
        context = "\n---\n".join(recent_reports) if recent_reports else "（暂无侦察/攻击报告）"

        # 调用 ScopeAuditor 审核
        audit_prompt = (
            f"授权目标：{mission.target}\n"
            f"待审核 IP/网段：{ip_or_cidr}\n"
            f"提交证据：{evidence}\n"
            f"申请理由：{reason or '（无）'}\n\n"
            f"近期侦察/攻击报告（证据上下文）：\n{context}\n\n"
            f"请审核是否批准将 {ip_or_cidr} 纳入授权范围。"
        )
        result = await run_interruptible_agent_reply(
            scope_auditor,
            UserMsg(name="Orchestrator", content=audit_prompt),
            prefix="[ScopeAuditor] ",
            on_event=event_callback,
        )
        verdict = result.get_text_content() or "REJECTED\n（无输出）"

        approved = verdict.strip().upper().startswith("APPROVED")
        mission.record(
            "Orchestrator",
            "scope_expansion",
            ip_or_cidr=ip_or_cidr,
            evidence=evidence[:200],
            auditor_verdict=verdict[:200],
            approved=approved,
        )

        if approved:
            if "/" in ip_or_cidr:
                msg = scope_registry.add_network(ip_or_cidr, evidence, approved_by="ScopeAuditor")
            else:
                msg = scope_registry.add_ip(ip_or_cidr, evidence, approved_by="ScopeAuditor")
            # 持久化授权范围
            mission.authorized_scope = scope_registry.snapshot()
            store.save(mission)
            if event_callback:
                event_callback("scope_updated", **mission.authorized_scope)
            return f"{msg}\nScopeAuditor 意见：{verdict.split(chr(10), 1)[1] if chr(10) in verdict else verdict}"
        else:
            store.save(mission)
            return f"[拒绝] ScopeAuditor 拒绝了扩容请求。\n意见：{verdict}"

    def manage_hypothesis(
        operation: str,
        hypothesis_id: str = "",
        statement: str = "",
        status: str = "",
        confidence: float = -1.0,
        supporting_evidence: list[str] | None = None,
        opposing_evidence: list[str] | None = None,
        next_validation: str = "",
    ) -> dict:
        """新增或更新结构化 Hypothesis。

        Args:
            operation: propose 或 update。
            hypothesis_id: update 时必填，如 h1。
            statement: propose 时的假设正文。
            status: proposed/testing/supported/weakened/rejected/confirmed。
            confidence: 0~1；不修改时传 -1。
            supporting_evidence: 支持证据 ID 列表。
            opposing_evidence: 反对证据 ID 列表。
            next_validation: 下一步验证方向。
        """
        try:
            if operation == "propose":
                item = mission.add_hypothesis(
                    statement, confidence=0.5 if confidence < 0 else confidence,
                    next_validation=next_validation,
                )
            elif operation == "update":
                item = mission.update_hypothesis(
                    hypothesis_id,
                    status=status or None,
                    supporting_evidence=supporting_evidence,
                    opposing_evidence=opposing_evidence,
                    confidence=None if confidence < 0 else confidence,
                    next_validation=next_validation if next_validation else None,
                )
            else:
                return {"ok": False, "error": "operation 仅支持 propose/update"}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        store.save(mission)
        if event_callback is not None:
            active = [
                value for value in mission.hypotheses
                if value.status not in {"rejected", "confirmed"}
            ]
            current = next(
                (value for value in reversed(active) if value.status == "testing"),
                active[-1] if active else None,
            )
            event_callback(
                "target_info",
                hypotheses=[{
                    "id": value.id,
                    "statement": value.statement,
                    "status": value.status,
                    "confidence": value.confidence,
                    "supporting_evidence": list(value.supporting_evidence),
                    "opposing_evidence": list(value.opposing_evidence),
                    "related_actions": list(value.related_actions),
                    "next_validation": value.next_validation,
                    "updated_at": value.updated_at,
                } for value in active[-12:]],
                active_hypothesis=({
                    "id": current.id,
                    "statement": current.statement,
                    "status": current.status,
                    "confidence": current.confidence,
                    "supporting_evidence": list(current.supporting_evidence),
                    "opposing_evidence": list(current.opposing_evidence),
                    "related_actions": list(current.related_actions),
                    "next_validation": current.next_validation,
                    "updated_at": current.updated_at,
                } if current else None),
                agent="Orchestrator",
            )
        return {"ok": True, "hypothesis": {
            "id": item.id, "statement": item.statement, "status": item.status,
            "confidence": item.confidence,
            "supporting_evidence": item.supporting_evidence,
            "opposing_evidence": item.opposing_evidence,
            "related_actions": item.related_actions,
            "next_validation": item.next_validation,
        }}

    def view_mission_state() -> dict:
        """查看有界决策状态；完整状态仍持久化，但不灌入 Agent Prompt。"""
        return {
            "context_layers": mission.context_layers(limit=8),
            "success": mission.success,
            "active_plan_item": mission.active_plan_item,
            "counts": {
                "evidence": len(mission.evidence_records),
                "actions": len(mission.action_history),
                "failed_paths": len(mission.failed_paths),
            },
        }

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
        store.checkpoint(mission, "mission_terminal")
        push_plan_update(mission, event_callback)
        # P0-D：任务终态前确定性提炼失败/成功教训并随长期记忆存档；
        # 提炼失败不阻断任务收尾（安全降级为空列表）。
        try:
            lessons = extract_lessons(
                failed_paths=mission.failed_paths,
                attack_chain=mission.attack_chain,
                success=mission.success,
            )
        except Exception:
            lessons = []
        save_mission(
            target=mission.target,
            goal=mission.goal,
            plan=mission.plan,
            attack_chain=mission.attack_chain,
            success=mission.success,
            summary=summary,
            flag=mission.flag,
            lessons=lessons,
        )
        return f"[任务已结束] success={mission.success}, flag={mission.flag or '未发现'}"
    
    async def submit_nss_flag(flag: str) -> str:
        """向 NSSCTF Agent Arena 提交 Flag 并获取判定结果。

        仅当任务由 NSSCTF Arena 发起（携带 nss_context）时可用。
        Args:
            flag: 候选 Flag（如 NSSCTF{...}）。
        """
        if not nss_context:
            mission.record("Orchestrator", "nss_submit_unavailable", flag=flag)
            store.save(mission)
            return "[不可用] 当前任务未接入 NSSCTF Arena，无法提交。请在 complete_mission 中报告 Flag。"
        attempt_id = nss_context.get("attempt_id")
        token = nss_context.get("token", "")
        api_base = nss_context.get("api_base", "https://www.nssctf.cn/api")
        if not attempt_id:
            return "[不可用] 缺少 attempt_id，无法提交。"

        candidate = (flag or "").strip()
        if not candidate:
            return "[拒绝] Flag 不能为空。"
        if not candidate.startswith("NSSCTF{") and not candidate.startswith("flag"):
            mission.record("Orchestrator", "nss_submit_format_warning", flag=candidate)
            store.save(mission)
            return (
                f"[警告] Flag '{candidate}' 不符合常见格式（NSSCTF{...}），"
                f"请确认候选值，确认无误后再提交。"
            )

        payload = {"flag": candidate}
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        url = f"{api_base}/skill/agent/arena/attempt/{attempt_id}/submit/"
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except Exception as exc:
            mission.record("Orchestrator", "nss_submit_error", flag=candidate, error=str(exc))
            store.save(mission)
            return f"[提交失败] 请求异常: {exc}"

        correct = bool(data.get("correct"))
        remaining = data.get("remaining_wrong_attempts")
        mission.nss_submit = {
            "attempt_id": attempt_id,
            "flag": candidate,
            "correct": correct,
            "remaining_wrong_attempts": remaining,
            "api_base": api_base,
        }
        mission.record(
            "Orchestrator", "nss_submit",
            flag=candidate, correct=correct, remaining_wrong_attempts=remaining,
        )
        store.checkpoint(mission, "nss_flag_submitted")
        if event_callback:
            event_callback("nss_submit", **mission.nss_submit)
        if correct:
            mission.flag = candidate
            mission.success = True
            # MissionFinalizer：在线判定正确立即进入 COMPLETED，不再依赖
            # LLM 调用 complete_mission；残留计划项确定性收尾
            if mission.phase not in {Phase.COMPLETED, Phase.FAILED, Phase.CANCELLED}:
                mission.transition(Phase.COMPLETED, "NSS Flag 判定正确")
                for item in mission.plan_items:
                    if item.get("status") == "in_progress":
                        item["status"] = "completed"
                    elif item.get("status") == "pending":
                        item["status"] = "skipped"
            # 正确 Flag 提交立即固化终态信号，崩溃后仍能恢复为 completed
            store.checkpoint(mission, "nss_flag_correct")
            push_plan_update(mission, event_callback)
            return (
                f"[提交成功] ✅ NSSCTF 判定 Flag 正确！attempt_id={attempt_id}。"
                f"剩余错误次数: {remaining}。任务已标记完成，无需再调用 complete_mission。"
            )
        return (
            f"[提交失败] ❌ NSSCTF 判定 Flag 错误。剩余错误次数: {remaining}。"
            f"请分析失败原因，重新尝试或调用 complete_mission 如实收尾。"
        )


    async def submit_slab_flag(flag: str) -> str:
        """向 slab-match 平台提交 Flag 并获取判定结果。

        仅当任务由 slab-match 发起（携带 slab_context）时可用。
        Args:
            flag: 候选 Flag（DASCTF{...} / flag{...} 或花括号内内容）。
        """
        if not slab_context:
            mission.record("Orchestrator", "slab_submit_unavailable", flag=flag)
            store.save(mission)
            return "[不可用] 当前任务未接入 slab-match 平台，无法提交。请在 complete_mission 中报告 Flag。"
        exercise_id = slab_context.get("exercise_id")
        access_key = slab_context.get("access_key", "")
        api_base = slab_context.get("api_base", "https://pro.dasctf.com")
        if not exercise_id:
            return "[不可用] 缺少 exercise_id，无法提交。"

        candidate = (flag or "").strip()
        if not candidate:
            return "[拒绝] Flag 不能为空。"
        # 平台格式：DASCTF{...}/flag{...}，提交时仅需花括号内内容
        inner: str | None = None
        match = re.search(r"(?:DASCTF|flag)\{([^{}\r\n]+)\}", candidate)
        if match:
            inner = match.group(1).strip()
        elif candidate and "{" not in candidate and "}" not in candidate \
                and not any(ch.isspace() for ch in candidate):
            inner = candidate
        if not inner:
            mission.record("Orchestrator", "slab_submit_format_warning", flag=candidate)
            store.save(mission)
            return (
                f"[警告] Flag '{candidate[:80]}' 无法解析为平台格式"
                f"（DASCTF{{...}}/flag{{...}} 或纯内容），请确认候选值后再提交。"
            )

        payload = {"exerciseId": exercise_id, "flag": inner}
        headers = {
            "X-Agent-AccessKey": access_key,
            "Content-Type": "application/json",
            # 平台 WAF 拦截 python-httpx 默认 UA
            "User-Agent": "curl/8.5.0",
        }
        url = f"{api_base}/slab-match/api/v1/agent/answer-panel/answer"
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            body = resp.json()
            if body.get("code") != "00000":
                raise RuntimeError(f"slab API 错误 {body.get('code')}: {body.get('message', body)}")
            data = body.get("data", {})
        except Exception as exc:
            mission.record("Orchestrator", "slab_submit_error", flag=candidate, error=str(exc))
            store.save(mission)
            return f"[提交失败] 请求异常: {exc}"

        correct = bool(data.get("isCorrect"))
        mission.slab_submit = {
            "exercise_id": exercise_id,
            "flag": candidate,
            "submitted": inner,
            "correct": correct,
            "api_base": api_base,
        }
        mission.record(
            "Orchestrator", "slab_submit",
            flag=candidate, submitted=inner, correct=correct,
        )
        store.checkpoint(mission, "slab_flag_submitted")
        if event_callback:
            event_callback("slab_submit", **mission.slab_submit)
        if correct:
            mission.flag = candidate
            mission.success = True
            # 在线判定正确立即进入 COMPLETED，残留计划项确定性收尾
            if mission.phase not in {Phase.COMPLETED, Phase.FAILED, Phase.CANCELLED}:
                mission.transition(Phase.COMPLETED, "slab Flag 判定正确")
                for item in mission.plan_items:
                    if item.get("status") == "in_progress":
                        item["status"] = "completed"
                    elif item.get("status") == "pending":
                        item["status"] = "skipped"
            store.checkpoint(mission, "slab_flag_correct")
            push_plan_update(mission, event_callback)
            return (
                f"[提交成功] ✅ slab-match 判定 Flag 正确！exercise_id={exercise_id}。"
                f"任务已标记完成，无需再调用 complete_mission。"
            )
        return (
            f"[提交失败] ❌ slab-match 判定 Flag 错误（已提交 {inner}）。"
            f"请分析失败原因，重新尝试或调用 complete_mission 如实收尾。"
        )


    tools = [
        AllowedFunctionTool(dispatch_recon, is_concurrency_safe=False),
        AllowedFunctionTool(dispatch_attack, is_concurrency_safe=False),
        AllowedFunctionTool(manage_hypothesis, is_concurrency_safe=False),
        AllowedFunctionTool(view_mission_state, is_read_only=True),
        create_add_plan_tool(mission, store, event_callback, default_origin="orchestrator"),
        create_update_plan_tool(mission, store, event_callback),
        create_delete_plan_tool(mission, store, event_callback),
        create_list_plan_tool(mission),
        AllowedFunctionTool(complete_mission, is_concurrency_safe=False),
        AllowedFunctionTool(request_exploitation_approval, is_concurrency_safe=False),
        create_query_memory_tool(),
    ]
    category = str((mission.category_decision or {}).get("primary") or "unknown")
    target_kind = str((mission.target_spec or {}).get("kind") or "")
    if category in {"pwn", "reverse", "malware"} or target_kind != "network":
        tools.append(AllowedFunctionTool(dispatch_reverse, is_concurrency_safe=False))
    if target_kind == "network":
        tools.append(AllowedFunctionTool(request_scope_expansion, is_concurrency_safe=False))
    if nss_context:
        tools.append(AllowedFunctionTool(submit_nss_flag, is_concurrency_safe=False))
    if slab_context:
        tools.append(AllowedFunctionTool(submit_slab_flag, is_concurrency_safe=False))
    enabled_capabilities = [
        "recon", "attack", "hypothesis", "plan", "state", "approval", "memory",
    ]
    if category in {"pwn", "reverse", "malware"} or target_kind != "network":
        enabled_capabilities.append("reverse")
    if target_kind == "network":
        enabled_capabilities.append("scope_expansion")
    if nss_context:
        enabled_capabilities.append("nss_submit")
    if slab_context:
        enabled_capabilities.append("slab_submit")
    orchestrator_prompt = (
        ORCHESTRATOR_SYS_PROMPT
        + "\n本轮已启用职责："
        + ", ".join(enabled_capabilities)
        + "。"
    )
    return Agent(
        name=ORCHESTRATOR_EXPERT,
        system_prompt=orchestrator_prompt,
        model=model,
        toolkit=StrictJSONToolkit(tools=tools),
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )

# 超过 20轮自动提出窗口显示是否迭代

# 审核多方案选择，默认第一个，给用户选择

#
