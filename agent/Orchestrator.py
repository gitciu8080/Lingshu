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
    run_expert_reply_with_continuation,
)
from agent.experts import ORCHESTRATOR_EXPERT
from agent.categorize import (
    CategoryDecision,
    evaluate_reclassification,
    extract_recon_signals,
)


ORCHESTRATOR_SYS_PROMPT = load_prompt("ORCHESTRATOR")

# 攻击/利用类动作关键词：objective 命中即视为进入攻击阶段，
# 未获人工批准时被 dispatch_attack 兜底闸门拦截（含后渗透/横向类动作）。
_EXPLOITATION_KEYWORDS = (
    "exploit", "验证", "利用", "访问", "shell", "flag", "提权",
    "后渗透", "横向",
)
# 后渗透阶段触发词：objective 命中且当前处于 EXPLOITATION 时迁入 POST_EXPLOITATION。
_POST_EXPLOITATION_TRIGGERS = ("flag", "post", "提权", "后渗透", "横向")

# 报告回灌指挥官上下文的字符上限：全文已按原顺序登记 Evidence/findings，
# 超限只回灌截断版，指挥官需要细节时经 view_mission_state 按需查看。
_REPORT_RETURN_LIMIT = 4000


def _bounded_report(report: str) -> str:
    text = str(report or "")
    if len(text) <= _REPORT_RETURN_LIMIT:
        return text
    return text[:_REPORT_RETURN_LIMIT] + (
        f"\n…（报告已截断，全文 {len(text)} 字符已登记 Evidence；"
        "需要细节时调用 view_mission_state 查看证据摘要。）"
    )


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
    ensure_scope_approved: Callable[[], Awaitable[bool]] | None = None,
    offloader=None,
    context_config=None,
    state=None,
    network_recon_agent: Agent | None = None,
    artifact_recon_agent: Agent | None = None,
    category_change_callback: Callable[[str, str, str], Awaitable[None]] | None = None,
    brain_agent: Agent | None = None,
) -> Agent:
    steering = steering_state if steering_state is not None else {"pending": None, "processed": False, "queue": []}
    steering.setdefault("queue", [])

    # P5 后台并行派遣（recon/reverse）：同一专家实例并发 reply 不安全
    # （Agent state 无并发保护），按 role 忙碌互斥；不同 role 是不同实例，
    # 天然可并行。后台路径完整保留 begin_attempt/checkpoint/evidence 审计链。
    bg_state: dict[str, Any] = {"ready": [], "running": {}, "busy_roles": set()}
    _BG_LIMIT = 2  # 后台并发专家上限

    async def _apply_runtime_reclassification(
        report: str,
        *,
        source: str,
        evidence_id: str,
    ) -> str:
        """将执行期新证据纳入分类，并在题型改变后刷新下游能力。

        这不是让模型凭印象改标签：仍复用评分、强信号和证据指纹去重规则。
        已授权网络目标一旦取得 HTTP 协议证据，Web 主攻击面优先；附件的
        DEX/ELF 等保留为 secondary，避免再次被辅助材料带偏。
        """
        raw = mission.category_decision or {}
        previous = CategoryDecision(
            primary=str(raw.get("primary") or "unknown"),  # type: ignore[arg-type]
            secondary=list(raw.get("secondary") or []),  # type: ignore[arg-type]
            confidence=float(raw.get("confidence") or 0.0),
            scores=dict(raw.get("scores") or {}),
            evidence=list(raw.get("evidence") or []),
            stage=str(raw.get("stage") or "post_recon"),  # type: ignore[arg-type]
        )
        result = evaluate_reclassification(
            previous,
            [report],
            seen_evidence_fingerprints={
                str(item.get("evidence_fingerprint") or "")
                for item in mission.category_history
            },
        )
        target_kind = str((mission.target_spec or {}).get("kind") or "")
        has_http_evidence = any(signal.category == "web" for signal in result.signals)
        web_guard = bool(mission.authorized and target_kind == "network" and has_http_evidence)
        if web_guard:
            candidate = result.candidate
            secondary = [
                item for item in [candidate.primary, *candidate.secondary]
                if item not in {"web", "unknown"}
            ]
            scores = dict(candidate.scores)
            scores["web"] = max(
                float(scores.get("web", 0.0)),
                max((float(value) for value in scores.values()), default=0.0) + 1.0,
            )
            result.candidate = CategoryDecision(
                primary="web",
                secondary=list(dict.fromkeys(secondary)),
                confidence=1.0,
                scores=scores,
                evidence=[
                    *candidate.evidence,
                    "分类护栏: 已授权网络目标已确认 HTTP/HTTPS，Web 为主攻击面；附件类型仅作辅分类",
                ],
                stage="post_recon",
            )
            result.accepted = previous.primary != "web" or result.candidate != previous
            result.reason = (
                "应用 Web 网络主线护栏：已授权网络目标存在 HTTP/HTTPS 协议证据，"
                "主分类切换为 web；附件文件类型保留为辅分类"
            )

        final = result.candidate if result.accepted else previous
        mission.category_history.append({
            "stage": "runtime",
            "source": source,
            "previous": {
                "primary": previous.primary, "secondary": previous.secondary,
                "confidence": previous.confidence, "scores": previous.scores,
                "evidence": previous.evidence, "stage": previous.stage,
            },
            "candidate": {
                "primary": result.candidate.primary, "secondary": result.candidate.secondary,
                "confidence": result.candidate.confidence, "scores": result.candidate.scores,
                "evidence": result.candidate.evidence, "stage": result.candidate.stage,
            },
            "accepted": result.accepted,
            "reason": result.reason,
            "evidence_id": evidence_id,
            "evidence_fingerprint": result.evidence_fingerprint,
            "web_network_guard_applied": web_guard,
            "created_at": datetime.now().isoformat(),
        })
        if not result.accepted:
            return ""

        mission.category_decision = {
            "primary": final.primary,
            "secondary": final.secondary,
            "confidence": final.confidence,
            "scores": final.scores,
            "evidence": final.evidence,
            "stage": final.stage,
        }
        mission.record(
            "Orchestrator", "category_runtime_reclassified",
            source=source, previous=previous.primary, current=final.primary,
            evidence_id=evidence_id, reason=result.reason,
        )
        if category_change_callback is not None and previous.primary != final.primary:
            await category_change_callback(previous.primary, final.primary, result.reason)
        store.save(mission)
        return (
            f"\n[题型已切换] {previous.primary} → {final.primary}。{result.reason}"
            if previous.primary != final.primary else ""
        )

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

    async def _recon_core(
        focus: str = "",
        hypothesis_id: str = "",
        route: str = "auto",
    ) -> str:
        """Recon 派遣执行体（同步/后台共用；审计链全量保留）。

        Args:
            focus: 本轮需要补齐的具体信息或扫描重点。
            hypothesis_id: 本动作要验证的结构化假设 ID；纯探索可留空。
            route: Recon 路由：artifact（本地附件分析）、network（网络侦察）或 auto（由当前能力自动选择）。
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
        route = str(route or "auto").strip().lower()
        if route not in {"auto", "artifact", "network"}:
            return "[拒绝] route 只能是 artifact、network 或 auto"
        mode = mission.mission_mode or (
            "authorized_pentest"
            if str((mission.target_spec or {}).get("kind") or "") == "network"
            else "ctf"
        )
        if (
            mission.scope_approval_status == "denied"
            and mode in {"authorized_pentest", "hybrid_taskbook"}
            and (mission.declared_scope or {}).get("targets")
        ):
            mission.record("Orchestrator", "capability_blocked", reason="scope_denied", action="dispatch_recon")
            store.save(mission)
            return "[阻塞] 网络范围审批未通过，已停止 Recon；请重新授权或安全收尾。"
        selected_recon = recon_agent
        if route == "artifact":
            selected_recon = artifact_recon_agent or recon_agent
        elif route == "network":
            if network_recon_agent is None:
                return "[不可用] 当前任务未挂载 NetworkRecon 能力；请改用 artifact 或先补充网络目标。"
            selected_recon = network_recon_agent
        elif network_recon_agent is not None and (
            str((mission.target_spec or {}).get("kind") or "") == "network"
            or any(token in focus.lower() for token in ("网络", "端口", "服务", "http", "dns", "ip"))
        ):
            selected_recon = network_recon_agent
        # 惰性范围审批（5e19dc2a 复盘）：任务启动不再被范围审批阻塞，本地
        # 附件分析先行；首次真正需要网络侦察时才请求人工审批任务书声明的
        # 未预授权目标。批准后授权范围已登记，本轮正常继续；用户显式输入
        # 的目标已在注册表中，此闸门对其直接放行。
        if (
            selected_recon is network_recon_agent
            and mission.scope_approval_status == "pending"
            and ensure_scope_approved is not None
        ):
            if not await ensure_scope_approved():
                mission.record(
                    "Orchestrator", "capability_blocked",
                    reason="scope_denied", action="dispatch_recon",
                )
                store.save(mission)
                return "[阻塞] 网络范围审批未通过，已停止 Recon；请继续本地分析或安全收尾。"
        attempt = mission.begin_attempt(
            "recon",
            selected_recon.name,
            mission.target,
            {"focus": focus, "hypothesis_id": hypothesis_id, "route": route, "agent": selected_recon.name},
        )
        # post_exploitation 中的本地补侦不回退任务阶段，避免完成 Recon 后
        # 远程 Attack 因阶段变成 RECON 而被错误拒绝。
        if mission.phase != Phase.RECON and mission.phase != Phase.POST_EXPLOITATION:
            mission.transition(Phase.RECON, f"需要补充侦察: {focus}")
        mission.record("Orchestrator", "dispatch_recon", focus=focus, route=route, selected_agent=selected_recon.name)
        store.checkpoint(mission, "recon_dispatch_before")
        try:
            report = await run_expert_reply_with_continuation(
                selected_recon,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        f"授权目标：{mission.target}\n本轮重点：{focus[:2000]}\n"
                        "收集到足够证据后立即输出最终报告，禁止继续调用工具。"
                    ),
                ),
                prefix="[Recon] ",
                on_event=event_callback,
                label="Recon",
            )
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
        if not report:
            # 补轮与上下文恢复仍为空：不登记伪证据、不推进阶段，
            # 收敛本轮 attempt 并把重试决策交还主循环。
            mission.finish_attempt(
                attempt,
                "failure",
                "Recon 未返回文本结果（补轮与恢复机制均无可用输出）",
                information_gain="none",
            )
            mission.record("Orchestrator", "recon_no_text_result")
            store.save(mission)
            return (
                "[Recon 空结果] 专家本轮未返回任何文本（含补轮）。"
                "本轮未登记证据，已完成的工具产物全部保留；"
                "请直接重新调度一次并收窄 focus，或改用其他路径推进。"
            )
        before_evidence = len(mission.evidence_records)
        evidence = mission.add_evidence(
            selected_recon.name,
            "recon_report",
            report,
            category=str((mission.category_decision or {}).get("primary") or ""),
            confidence=float((mission.category_decision or {}).get("confidence") or 0.0),
        )
        fact_count = len(mission.facts)
        for signal in extract_recon_signals([report]):
            mission.add_fact(
                signal.content,
                selected_recon.name,
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
        category_note = await _apply_runtime_reclassification(
            report,
            source=selected_recon.name,
            evidence_id=evidence.id,
        )
        return f"[Recon 侦察报告]\n{_bounded_report(report)}{category_note}"

    # P2 差量注入游标：记录上次 Attack 派遣时的 facts 水位，专家 UserMsg
    # 只自动拼接新增 Facts，避免每次重灌全量证据推高专家压缩频率。
    attack_fact_mark = 0

    async def dispatch_attack(
        target_info: str,
        objective: str = "漏洞分析",
        service: str = "",
        cve: str = "",
        hypothesis_id: str = "",
    ) -> str:
        """派遣 Attack 分析或验证当前授权目标。

        Args:
            target_info: 本轮新增的关键证据（服务/版本/端口/响应片段）。
                只需填写自上次 Attack 派遣以来新增或变化的部分，禁止重复
                粘贴历史证据——历史 Facts 会由系统自动拼接给专家。
            objective: 本轮目标，如漏洞分析、漏洞验证、获取初始访问或寻找 Flag。
            service: 侦察已确认的服务名（如 "Apache 2.4.49"），供长期记忆登记；未知留空。
            cve: 已确认的 CVE 编号（如 "CVE-2021-41773"），未确认不得填写。
            hypothesis_id: 本动作要验证的结构化假设 ID。
        """
        nonlocal attack_fact_mark
        msg = _check_steering()
        if msg is not None:
            return msg
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Attack"
        mode = mission.mission_mode or (
            "authorized_pentest"
            if str((mission.target_spec or {}).get("kind") or "") == "network"
            else "ctf"
        )
        if mode in {"authorized_pentest", "hybrid_taskbook"}:
            declared = list((mission.declared_scope or {}).get("targets") or [])
            scope_missing = bool(declared) and not any(
                scope_registry and scope_registry.is_target_allowed(str(normalized))
                for normalized in declared
            )
            # 惰性范围审批：目标未入授权范围且状态仍 pending 时，先发起人工
            # 审批而不是直接阻塞；批准后目标入范围，本轮 Attack 正常继续。
            if (
                scope_missing
                and mission.scope_approval_status == "pending"
                and ensure_scope_approved is not None
                and await ensure_scope_approved()
            ):
                scope_missing = False
            if scope_missing:
                if mission.scope_approval_status not in {"denied", "unavailable"}:
                    mission.scope_approval_status = "pending"
                mission.record("Orchestrator", "capability_blocked", reason="scope_missing", targets=declared)
                store.save(mission)
                return "[阻塞] 当前任务的网络目标尚未进入有效授权范围，请先完成范围审批。"
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
            for word in _EXPLOITATION_KEYWORDS
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
        if any(word in lower or word in objective for word in _POST_EXPLOITATION_TRIGGERS):
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
        # 差量证据：自上次 Attack 派遣以来的新增 Facts（有界，最近 5 条）。
        delta_facts = mission.facts[attack_fact_mark:]
        attack_fact_mark = len(mission.facts)
        delta_section = ""
        if delta_facts:
            delta_lines = "\n".join(
                f"- {str(getattr(fact, 'content', fact))[:400]}"
                for fact in delta_facts[-5:]
            )
            delta_section = (
                "\n\n自上次 Attack 派遣以来的新增 Facts（最近 5 条，完整历史"
                "已在你此前的会话上下文中）：\n" + delta_lines
            )
        try:
            report = await run_expert_reply_with_continuation(
                attack_agent,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        f"授权目标：{mission.target}\n本轮目标：{objective[:1500]}\n\n"
                        f"本轮新增关键证据（调用方筛选，勿重复历史）：\n{target_info[:2000]}\n"
                        f"{delta_section}"
                        f"{knowledge_section}\n\n"
                        "完成分析/验证后立即输出最终报告，禁止继续调用工具。"
                    ),
                ),
                prefix="[Attack] ",
                on_event=event_callback,
                label="Attack",
            )
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
        if not report:
            # 补轮与上下文恢复仍为空：不登记伪证据、不产生攻击步骤。
            mission.finish_attempt(
                attempt,
                "failure",
                "Attack 未返回文本结果（补轮与恢复机制均无可用输出）",
                information_gain="none",
            )
            mission.record("Orchestrator", "attack_no_text_result")
            store.save(mission)
            return (
                "[Attack 空结果] 专家本轮未返回任何文本（含补轮）。"
                "本轮未登记证据；请直接重新调度一次并强调最终消息必须输出"
                "完整中文报告，或基于已有证据改用其他路径。"
            )
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
                f"Attack 报告中发现待验证 Flag/关键凭据候选：{flag_match.group(0)}",
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
        category_note = await _apply_runtime_reclassification(
            report,
            source=attack_agent.name,
            evidence_id=evidence.id,
        )
        return f"[Attack 报告]\n{_bounded_report(report)}{category_note}"

    async def _reverse_core(
        binary_path: str,
        objective: str = "二进制逆向分析",
        hypothesis_id: str = "",
    ) -> str:
        """Reserve 派遣执行体（同步/后台共用；审计链全量保留）。

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
            report = await run_expert_reply_with_continuation(
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
                        "若 MCP 工具报 Session not found，说明上一会话已关闭，"
                        "直接重新调用 ida_open_binary 即可获取新会话继续分析，"
                        "不要反复用旧会话 ID 重试。\n"
                        "分析完成后立即输出最终报告，禁止继续调用工具。"
                    ),
                ),
                prefix="[Reserve] ",
                on_event=event_callback,
                label="Reserve",
            )
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
        if not report:
            # c5ca9b2b 复盘："[Reserve] 未返回文本结果" 曾作为伪证据入库并
            # 消耗一轮 attempt；现在转为失败收敛 + 明确续推指引。
            mission.finish_attempt(
                attempt,
                "failure",
                "Reserve 未返回文本结果（补轮与恢复机制均无可用输出）",
                information_gain="none",
            )
            mission.record("Orchestrator", "reverse_no_text_result")
            store.save(mission)
            return (
                "[Reserve 空结果] 专家本轮未返回任何文本（含补轮）。"
                "本轮未登记证据，已打开的 IDA/GDB 会话与工具产物全部保留；"
                "请直接重新调度一次并收窄 objective（可提示专家从既有会话继续），"
                "若连续两轮均为空结果，视为该能力暂时不可用，改用其他路径推进。"
            )
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
        return f"[Reserve 逆向报告]\n{_bounded_report(report)}"

    # ── P5 后台派遣封装与收取（机制移植自 fast 模式 Captain，已验证语义） ──
    def _note_bg_report(role: str, objective: str, result_text: str) -> None:
        text = str(result_text or "")
        trimmed = text[:_REPORT_RETURN_LIMIT] + (
            "\n…（结果已截断；完整内容与证据链已按原顺序登记）"
            if len(text) > _REPORT_RETURN_LIMIT else ""
        )
        bg_state["ready"].append({
            "role": role, "objective": str(objective)[:200], "report": trimmed,
        })

    async def _bg_worker(handle: str, role: str, objective: str, coro) -> None:
        try:
            result = await coro
            _note_bg_report(role, objective, result or "（后台派遣未返回结果）")
        except asyncio.CancelledError:
            mission.record(
                "Orchestrator", "dispatch_background_cancelled",
                role=role, handle=handle,
            )
            store.save(mission)
            raise
        except Exception as exc:  # noqa: BLE001 - 后台失败也必须可收取
            mission.record(
                "Orchestrator", "dispatch_background_failed",
                role=role, handle=handle, error=str(exc)[:300],
            )
            store.save(mission)
            _note_bg_report(role, objective, f"[后台执行失败] {exc}")
        finally:
            bg_state["busy_roles"].discard(role)
            bg_state["running"].pop(handle, None)

    def _spawn_background(role: str, objective: str, factory) -> str:
        """转入后台执行：忙碌互斥 + 并发上限，检查通过后才创建协程。"""
        if role in bg_state["busy_roles"]:
            return (
                f"[拒绝] {role} 专家正在执行任务（同一专家不能并行处理两个任务）。"
                "请调用 check_experts(wait=true) 等待其完成，或改派其它角色。"
            )
        if len(bg_state["running"]) >= _BG_LIMIT:
            return (
                f"[拒绝] 后台专家已达并发上限（{_BG_LIMIT}）。"
                "请先调用 check_experts 收取已完成报告，或等待运行中的任务结束。"
            )
        handle = f"{role}#{len(bg_state['running']) + len(bg_state['ready']) + 1}"
        # 同步占位：防止同一批工具调用里紧随的第二次派发绕过忙碌检查
        bg_state["busy_roles"].add(role)
        task = asyncio.create_task(
            _bg_worker(handle, role, objective, factory()),
            name=f"orch-expert:{handle}",
        )
        bg_state["running"][handle] = {
            "role": role, "objective": str(objective)[:200], "task": task,
        }
        return (
            f"[后台执行中] {handle}（{role}）。你可以继续推进互不依赖的其他工作"
            "（如 Attack 或其他角色侦察）；完成后用 check_experts(wait=true) "
            "等待并收取报告。"
        )

    async def dispatch_recon(
        focus: str = "",
        hypothesis_id: str = "",
        route: str = "auto",
        background: bool = False,
    ) -> str:
        """派遣 Recon 对本次授权目标进行信息收集。

        Args:
            focus: 本轮需要补齐的具体信息或扫描重点。
            hypothesis_id: 本动作要验证的结构化假设 ID；纯探索可留空。
            route: Recon 路由：artifact（本地附件分析）、network（网络侦察）或 auto（由当前能力自动选择）。
            background: True 时转入后台立即返回句柄（可与逆向/攻击等其他角色
                并行推进）；完成后经 check_experts 收取报告。同一时刻同一角色
                只能有一个任务。多假设并行补侦时优先用后台模式。
        """
        if background:
            mission.record(
                "Orchestrator", "dispatch_background",
                role="recon", focus=str(focus)[:300], route=str(route or "auto"),
            )
            store.save(mission)
            return _spawn_background(
                "recon", focus,
                lambda: _recon_core(focus=focus, hypothesis_id=hypothesis_id, route=route),
            )
        return await _recon_core(focus=focus, hypothesis_id=hypothesis_id, route=route)

    async def dispatch_reverse(
        binary_path: str,
        objective: str = "二进制逆向分析",
        hypothesis_id: str = "",
        background: bool = False,
    ) -> str:
        """派遣 Reserve 对指定二进制文件执行逆向分析。

        Args:
            binary_path: 待分析二进制文件的绝对路径（如 /WorkDir/uploads/target.exe）。
            objective: 本轮分析目标，如反编译提取算法、寻找 Flag、分析恶意行为。
            hypothesis_id: 本动作要验证的结构化假设 ID。
            background: True 时转入后台立即返回句柄（可与侦察/攻击等其他角色
                并行推进）；完成后经 check_experts 收取报告。逆向分析通常耗时
                较长，与网络侧工作互不依赖时优先用后台模式。
        """
        if background:
            mission.record(
                "Orchestrator", "dispatch_background",
                role="reverse", objective=str(objective)[:300],
            )
            store.save(mission)
            return _spawn_background(
                "reverse", objective,
                lambda: _reverse_core(binary_path, objective, hypothesis_id),
            )
        return await _reverse_core(binary_path, objective, hypothesis_id)

    async def check_experts(wait: bool = False, timeout: int = 240) -> str:
        """收取后台派遣专家（recon/reverse）的报告。

        Args:
            wait: True 时等待至少一份报告完成（有界超时）再返回。
            timeout: 等待上限秒数（10~600）。
        """
        if wait and not bg_state["ready"]:
            running = [entry["task"] for entry in bg_state["running"].values()
                       if not entry["task"].done()]
            if running:
                bounded = max(10, min(int(timeout), 600))
                await asyncio.wait(
                    running, timeout=bounded, return_when=asyncio.FIRST_COMPLETED,
                )
        ready = bg_state["ready"]
        bg_state["ready"] = []
        running_now = {
            handle: f"{info['role']}：{info['objective']}"
            for handle, info in bg_state["running"].items()
            if not info["task"].done()
        }
        if not ready:
            if running_now:
                lines = "\n".join(f"- {h}（{t}）" for h, t in running_now.items())
                return f"暂无已完成的报告。仍在运行：\n{lines}"
            return (
                "当前没有后台派遣的专家"
                "（用 dispatch_recon/dispatch_reverse 的 background=true 派出）。"
            )
        parts = [f"已收取 {len(ready)} 份报告："]
        for item in ready:
            parts.append(
                f"\n===== [{item['role']}] {item['objective']} =====\n{item['report']}"
            )
        if running_now:
            lines = "\n".join(f"- {h}（{t}）" for h, t in running_now.items())
            parts.append(f"\n仍在运行：\n{lines}")
        return "\n".join(parts)

    # ── P6 Brain 按需顾问：计划级变更时咨询，Brain 只输出建议不改状态 ──
    async def consult_brain(trigger: str, context_summary: str = "") -> str:
        """就计划级变更咨询 Brain 顾问，获取作战计划调整建议。

        你仍是唯一任务状态变更者：Brain 只输出建议，计划落地仍由你用
        AddPlan/UpdatePlan/DeletePlan 执行。适合题型翻盘、计划项失败过半、
        范围扩容获批后等战略调整场景；常规推进不需要咨询。

        Args:
            trigger: 咨询动因，如"题型翻盘为 pwn"、"计划项 3/5 已失败"、
                "范围扩容获批，新增 10.10.10.0/24"。
            context_summary: 补充上下文（关键证据/失败路径摘要，简洁）。
        """
        if brain_agent is None:
            return "[不可用] 本轮未接入 Brain 顾问。"
        items_summary = "\n".join(
            f"- {item.get('id')} [{item.get('status')}] {str(item.get('content') or '')[:120]}"
            for item in mission.plan_items[:12]
        ) or "（无结构化计划项）"
        failed_summary = "\n".join(
            f"- {str(getattr(fp, 'reason', '') or fp)[:200]}"
            for fp in (mission.failed_paths or [])[-6:]
        ) or "（无）"
        mission.record("Orchestrator", "brain_consulted", trigger=str(trigger)[:300])
        store.save(mission)
        try:
            advice = await run_expert_reply_with_continuation(
                brain_agent,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        "任务执行中咨询。以下是当前作战计划状态与近期失败路径。\n"
                        f"咨询动因：{str(trigger)[:500]}\n"
                        f"补充上下文：{str(context_summary)[:2000]}\n\n"
                        f"当前计划项：\n{items_summary}\n\n"
                        f"近期失败路径：\n{failed_summary}\n\n"
                        "请输出计划调整建议：需要新增/修改/删除/重排哪些计划项，"
                        "每条给出理由与退出条件；不要调用任何工具，直接输出建议正文。"
                    ),
                ),
                prefix="[Brain] ",
                on_event=event_callback,
                label="Brain",
            )
        except AgentMaxIterationsError:
            return "[Brain 顾问] 超迭代，本轮无建议输出；可稍后带更聚焦的动因重试。"
        text = str(advice or "").strip()
        if not text:
            return "[Brain 顾问] 本轮无建议输出；可稍后带更聚焦的动因重试。"
        return f"[Brain 顾问建议]\n{_bounded_report(text)}"

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
                "steps": ["优先处理最高置信度攻击路径", *base_steps[:2], "达成任务目标或触及边界条件后，先评估攻击链完整性与影响面，再调用 complete_mission 或 continue 推进"],
            },
        ]

        # ── 构建扫描摘要，帮助操作员决策 ──
        scan_summary: dict[str, Any] = {
            "approval_type": "exploitation",
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
        mode = mission.mission_mode or (
            "authorized_pentest"
            if str((mission.target_spec or {}).get("kind") or "") == "network"
            else "ctf"
        )
        if mode == "ctf":
            return "[拒绝] CTF 模式使用题目固定范围，不允许调用 request_scope_expansion"
        if mode == "incident_response":
            return "[拒绝] 应急响应模式不允许扩展远程授权范围"
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

        # 幂等短路：已经在有效范围内的目标不应再次触发人工审批。
        if "/" not in ip_or_cidr and scope_registry.is_ip_allowed(ip_or_cidr):
            return f"[已授权] {ip_or_cidr} 已在授权范围内，无需重复申请"

        # 范围扩展必须先经过独立的人工作业审批，再交由 ScopeAuditor
        # 做证据审计；不能用利用阶段审批替代目标范围审批。
        scope_summary = {
            "approval_type": "scope",
            "target": mission.target,
            "goal": mission.goal,
            "scope_request": {
                "target": ip_or_cidr,
                "evidence": evidence[:2000],
                "reason": reason[:1000],
            },
            "findings": mission.findings[-5:],
        }
        if approval_callback is not None:
            mission.scope_approval_status = "pending"
            mission.scope_approval_decision = ""
            mission.scope_approval_requested_at = datetime.now().astimezone().isoformat()
            store.save(mission)
            approval = await approval_callback(
                f"请求将 {ip_or_cidr} 纳入本次授权范围：{reason or '需要验证任务书声明目标'}",
                scope_summary,
            )
            approved_by_user = bool(approval.get("approved")) if isinstance(approval, dict) else bool(approval)
            decision = str(approval.get("decision") or ("批准" if approved_by_user else "拒绝")) if isinstance(approval, dict) else ("批准" if approved_by_user else "拒绝")
            mission.scope_approval_decision = decision
            mission.scope_approval_resolved_at = datetime.now().astimezone().isoformat()
            if not approved_by_user:
                mission.scope_approval_status = "denied"
                store.save(mission)
                return f"[拒绝] 用户未批准将 {ip_or_cidr} 纳入授权范围。"
        else:
            mission.scope_approval_status = "unavailable"
            store.save(mission)
            return "[拒绝] 当前没有范围审批通道，无法扩展授权范围"

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
            success: 是否已用证据确认达成任务目标。渗透模式
                （authorized_pentest/hybrid_taskbook）下判据是已验证漏洞与
                评估结论（含后渗透评估与攻击链闭环）是否支撑目标达成，
                不以获取 Flag 为唯一标准。
            summary: 包含证据、攻击链、失败尝试和结论的任务总结。
            flag: 可选达成证据：CTF 模式的 Flag 值，或渗透模式下发现的
                关键凭据/数据可达性证明；未发现时必须留空。
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
        outcome = f"success={mission.success}"
        if mission.flag:
            outcome += f", flag={mission.flag}"
        return f"[任务已结束] {outcome}"
    
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
    # 题型可在运行期依据新证据切换。始终注册本地逆向能力，使 Web→reverse
    # 等切换无需重建 Orchestrator；真正的执行仍受 ScopeRegistry 与工具闸门约束。
    tools.append(AllowedFunctionTool(dispatch_reverse, is_concurrency_safe=False))
    # P5：后台派遣收取（recon/reverse 可与其他角色并行，报告经此收取）
    tools.append(AllowedFunctionTool(check_experts, is_read_only=True))
    mode = mission.mission_mode or (
        "authorized_pentest" if target_kind == "network" else "ctf"
    )
    if mode in {"authorized_pentest", "hybrid_taskbook"}:
        tools.append(AllowedFunctionTool(request_scope_expansion, is_concurrency_safe=False))
    if nss_context:
        tools.append(AllowedFunctionTool(submit_nss_flag, is_concurrency_safe=False))
    if slab_context:
        tools.append(AllowedFunctionTool(submit_slab_flag, is_concurrency_safe=False))
    if brain_agent is not None:
        tools.append(AllowedFunctionTool(consult_brain, is_concurrency_safe=False))
    enabled_capabilities = [
        "recon", "attack", "hypothesis", "plan", "state", "approval", "memory",
        "background_dispatch", "check_experts",
    ]
    if artifact_recon_agent is not None:
        enabled_capabilities.append("artifact_recon")
    if network_recon_agent is not None:
        enabled_capabilities.append("network_recon")
    enabled_capabilities.append("reverse")
    if mode in {"authorized_pentest", "hybrid_taskbook"}:
        enabled_capabilities.append("scope_expansion")
    if nss_context:
        enabled_capabilities.append("nss_submit")
    if slab_context:
        enabled_capabilities.append("slab_submit")
    if brain_agent is not None:
        enabled_capabilities.append("brain_advisor")
    orchestrator_prompt = (
        ORCHESTRATOR_SYS_PROMPT
        + "\n本轮已启用职责："
        + ", ".join(enabled_capabilities)
        + "。"
    )
    agent = Agent(
        name=ORCHESTRATOR_EXPERT,
        system_prompt=orchestrator_prompt,
        model=model,
        toolkit=StrictJSONToolkit(tools=tools),
        react_config=ReActConfig(max_iters=max_iters, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )
    # 主循环窥视通道：后台报告就绪时由 main 主循环注入收取提示
    # （与 fast 模式 Captain 同机制，_fast_pending_report_hint 通用读取）
    agent._lingshu_bg = bg_state
    return agent

# 超过 20轮自动提出窗口显示是否迭代

# 审核多方案选择，默认第一个，给用户选择

#
