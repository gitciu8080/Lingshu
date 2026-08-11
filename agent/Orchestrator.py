"""Orchestrator：唯一可以修改任务状态的战术决策核心。"""
import asyncio
import httpx
from collections.abc import Awaitable, Callable
from typing import Any

from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg
from agentscope.tool import Toolkit

from Tools.AgenticMemory import create_query_memory_tool, save_mission
from TaskState import MissionState, MissionStore, Phase
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
    AllowedFunctionTool,
    stream_agent_reply,
)
from agent.experts import ORCHESTRATOR_EXPERT


ORCHESTRATOR_SYS_PROMPT = """你是网络安全行动总指挥（Orchestrator）。
你是唯一允许推进任务阶段、记录发现和宣布任务结束的 Agent。

可用能力：
- dispatch_recon：派遣 Recon 做纯被动信息收集（端口/服务/指纹/页面源码）。
- dispatch_attack：派遣 Attack 做分析、验证、利用或目标达成工作。

- request_exploitation_approval：首次执行验证/利用类攻击动作前，请求人工批准。
- request_scope_expansion：侦察中发现的靶机内网 IP 不在初始授权范围时，
  提交证据经 ScopeAuditor 审核后纳入授权。侦察报告中出现的内网地址
  （10.x / 172.16-31.x / 192.168.x）就是合法证据。
  命令中直接使用未授权 IP 会被 scoped_shell 拦截，必须通过本工具正规扩容。
- AddPlan / UpdatePlan / DeletePlan / ListPlan：维护作战计划清单——
  新增、细化、删除条目，标记状态或查看当前清单。
- QueryMemory：按服务名查询长期记忆中的历史攻击经验（已知 CVE / 相关任务），
  侦察确认服务指纹后可参考复用；服务名留空则查看近期任务概览。
- view_mission_state：查看结构化任务状态。
- complete_mission：仅在成功条件有证据或已达到明确失败条件时结束任务。
- submit_nss_flag：向 NSSCTF Agent Arena 提交 Flag 并获取判定结果
  （仅由 NSSCTF 竞技场发起的任务可用）。发现候选 Flag 时优先用它在线校验：
  正确 → 以 success=true 结束；错误 → 根据剩余次数调整思路继续。


行动纪律（严格遵守顺序）：
1. 先用 dispatch_recon 做被动侦察，Recon 只负责收集，不验证不利用。
2. 侦察完毕后，把发现汇总成方案，明确要做什么、怎么做、预期拿到什么证据。
3. 侦察中若发现靶机在服务响应/日志/系统属性中暴露了内网 IP，应将相关片段
   作为证据提交 request_scope_expansion 申请授权，获得批准后再对该 IP 发起探测。
4. 需要经隧道或代理访问靶机内部服务时，对隧道另一端的内网地址同样要先调用
   request_scope_expansion 扩容再连接，不得绕过授权直接发起。
5. 拿出方案后，先调用 request_exploitation_approval 请求人工批准，
   批准前不得调用 dispatch_attack 做任何验证/利用动作。
6. 批准后，调用 dispatch_attack 执行方案；所有攻击动作通过 Attack 执行，
   不要把主动探测或 payload 验证交给 Recon。
7. 失败后基于证据选择补充侦察（回到步骤 1）或其他候选路径，禁止无依据重复。
   制定方案前可先 QueryMemory 查询历史经验：确认了服务/版本指纹时，按服务名
   检索已知 CVE 与历史攻击链，命中则作为候选路径依据，未命中则回归当前证据。
8. 只有获得可复核证据后才能标记成功。发现 Flag 时在 complete_mission 中明确提交。
9. 禁止扩大目标范围、拒绝服务、数据破坏、持久化和日志清除。
10. 不得跳过 complete_mission；若迭代耗尽，应如实报告未完成，不能伪造成功。
11. 用 UpdatePlan 维护计划清单：开始某项前标记 in_progress，拿到工具证据后标记
    completed（必须在 evidence 中写明证据摘要）；侦察发现新路径时用 AddPlan 补充条目，
    条目失效时用 DeletePlan 移除，用 ListPlan 随时查看当前清单。
    禁止无证据标记完成。"""


def create_orchestrator_agent(
    model,
    recon_agent: Agent,
    attack_agent: Agent,
    reserve_agent: Agent,
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    approval_callback: Callable[[str, dict | None], Awaitable[bool]] | None = None,
    scope_registry: ScopeRegistry | None = None,
    scope_auditor: Agent | None = None,
    steering_state: dict[str, Any] | None = None,
    nss_context: dict[str, Any] | None = None,
) -> Agent:
    steering = steering_state if steering_state else {"pending": None, "processed": False}

    def _check_steering() -> str | None:
        """入口检查 + 中断后检查：消费待处理的用户指令。"""
        pending = steering.get("pending")
        if pending and not steering.get("processed"):
            steering["processed"] = True
            steering["pending"] = None
            return (
                f"[用户指令] {pending}\n\n"
                f"请基于已有侦察证据和此指令调整行动方向。"
                f"无需重复已完成的侦察步骤。"
            )
        return None

    async def dispatch_recon(focus: str = "全面但低影响的信息收集") -> str:
        """派遣 Recon 对本次授权目标进行信息收集。

        Args:
            focus: 本轮需要补齐的具体信息或扫描重点。
        """
        # 入口检查：是否有待处理的用户指令（无需等待子 Agent 取消）
        msg = _check_steering()
        if msg is not None:
            return msg
        if mission.phase not in {Phase.RECON, Phase.ANALYSIS, Phase.EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Recon"
        if mission.phase != Phase.RECON:
            mission.transition(Phase.RECON, f"需要补充侦察: {focus}")
        mission.record("Orchestrator", "dispatch_recon", focus=focus)
        store.save(mission)
        try:
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
        except AgentMaxIterationsError as exc:
            mission.record("Orchestrator", "recon_max_iters_exceeded", error=str(exc))
            store.save(mission)
            return (
                f"[Recon 超迭代] {exc}。"
                f"请缩小本轮 focus 范围重新调度，或改用其他路径。"
            )
        except asyncio.CancelledError:
            # 不在此处消费 steering：统一由主循环捕获 CancelledError 后注入，
            # 避免指令被消费但 Orchestrator reply 又被取消导致指令丢失。
            raise
        mission.add_finding("Recon", report)
        mission.transition(Phase.ANALYSIS, "收到新的侦察证据")
        store.save(mission)
        return f"[Recon 侦察报告]\n{report}"

    async def dispatch_attack(
        target_info: str,
        objective: str = "漏洞分析",
        service: str = "",
        cve: str = "",
    ) -> str:
        """派遣 Attack 分析或验证当前授权目标。

        Args:
            target_info: 来自 Recon 的服务、版本、端口和响应证据。
            objective: 本轮目标，如漏洞分析、漏洞验证、获取初始访问或寻找 Flag。
            service: 侦察已确认的服务名（如 "Apache 2.4.49"），供长期记忆登记；未知留空。
            cve: 已确认的 CVE 编号（如 "CVE-2021-41773"），未确认不得填写。
        """
        msg = _check_steering()
        if msg is not None:
            return msg
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Attack"
        # P3 去重：与最近一次已执行目标完全相同且无新证据 → 拒绝，堵住迭代黑洞
        last_step = mission.attack_chain[-1] if mission.attack_chain else None
        if last_step and last_step.get("objective", "").strip() == objective.strip():
            mission.record(
                "Orchestrator",
                "attack_duplicate_rejected",
                objective=objective,
            )
            store.save(mission)
            return (
                "[拒绝] 该 Attack 目标与最近一次完全相同，且无新证据。"
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
        if exploitation and mission.phase == Phase.ANALYSIS:
            mission.transition(Phase.EXPLOITATION, f"开始执行: {objective}")
        if any(word in lower or word in objective for word in ("flag", "post", "提权")):
            if mission.phase == Phase.EXPLOITATION:
                mission.transition(Phase.POST_EXPLOITATION, f"开始执行: {objective}")
        mission.record("Orchestrator", "dispatch_attack", objective=objective)
        store.save(mission)
        try:
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
        except AgentMaxIterationsError as exc:
            # 超迭代：写入失败步骤（保审计 + 供 P3 去重），返回明确结果
            mission.add_attack_step(objective, f"[Attack 超迭代] {exc}，本轮未产出有效结果")
            store.save(mission)
            return (
                f"[Attack 超迭代] {exc}。"
                f"请基于已有证据调整 objective 或补充侦察，避免重复调度。"
            )
        except asyncio.CancelledError:
            # 不在此处消费 steering：统一由主循环捕获 CancelledError 后注入。
            raise
        mission.add_attack_step(objective, report, service, cve)
        store.save(mission)
        return f"[Attack 报告]\n{report}"

    async def dispatch_reverse(binary_path: str, objective: str = "二进制逆向分析") -> str:
        """派遣 Reserve 对指定二进制文件执行逆向分析。

        Args:
            binary_path: 待分析二进制文件的绝对路径（如 /WorkDir/uploads/target.exe）。
            objective: 本轮分析目标，如反编译提取算法、寻找 Flag、分析恶意行为。
        """
        msg = _check_steering()
        if msg is not None:
            return msg
        if mission.phase not in {Phase.ANALYSIS, Phase.EXPLOITATION, Phase.POST_EXPLOITATION}:
            return f"[拒绝] 当前阶段 {mission.phase.value} 不允许派遣 Reserve"
        lower = objective.lower()
        if any(word in lower or word in objective for word in ("exploit", "利用", "patch", "patch")):
            if mission.phase == Phase.ANALYSIS:
                mission.transition(Phase.EXPLOITATION, f"逆向进入利用阶段: {objective}")
        mission.record("Orchestrator", "dispatch_reverse", binary_path=binary_path, objective=objective)
        store.save(mission)
        try:
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
        except AgentMaxIterationsError as exc:
            mission.record("Orchestrator", "reverse_max_iters_exceeded", error=str(exc))
            store.save(mission)
            return (
                f"[Reserve 超迭代] {exc}。"
                f"请缩小分析目标后重新调度，或改用其他路径。"
            )
        except asyncio.CancelledError:
            msg = _check_steering()
            if msg is not None:
                return msg
            raise
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
        result = await stream_agent_reply(
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
        # 确定性收尾：残留计划项不依赖 LLM 逐项 mark，终态统一处理
        for item in mission.plan_items:
            if item.get("status") == "in_progress":
                item["status"] = "completed" if success else "failed"
            elif item.get("status") == "pending":
                item["status"] = "skipped"
        store.save(mission)
        push_plan_update(mission, event_callback)
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
            resp = await httpx.AsyncClient(timeout=60.0).post(url, json=payload, headers=headers)
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
        store.save(mission)
        if event_callback:
            event_callback("nss_submit", **mission.nss_submit)
        if correct:
            mission.flag = candidate
            mission.success = True
            store.save(mission)
            return (
                f"[提交成功] ✅ NSSCTF 判定 Flag 正确！attempt_id={attempt_id}。"
                f"剩余错误次数: {remaining}。可调用 complete_mission 以成功状态结束任务。"
            )
        return (
            f"[提交失败] ❌ NSSCTF 判定 Flag 错误。剩余错误次数: {remaining}。"
            f"请分析失败原因，重新尝试或调用 complete_mission 如实收尾。"
        )


    tools = [
        AllowedFunctionTool(dispatch_recon, is_concurrency_safe=False),
        AllowedFunctionTool(dispatch_attack, is_concurrency_safe=False),
        AllowedFunctionTool(dispatch_reverse, is_concurrency_safe=False),
        AllowedFunctionTool(view_mission_state, is_read_only=True),
        create_add_plan_tool(mission, store, event_callback, default_origin="orchestrator"),
        create_update_plan_tool(mission, store, event_callback),
        create_delete_plan_tool(mission, store, event_callback),
        create_list_plan_tool(mission),
        AllowedFunctionTool(complete_mission, is_concurrency_safe=False),
        AllowedFunctionTool(request_exploitation_approval, is_concurrency_safe=False),
        AllowedFunctionTool(request_scope_expansion, is_concurrency_safe=False),
        AllowedFunctionTool(submit_nss_flag, is_concurrency_safe=False),
        create_query_memory_tool(),
    ]
    return Agent(
        name=ORCHESTRATOR_EXPERT,
        system_prompt=ORCHESTRATOR_SYS_PROMPT,
        model=model,
        toolkit=Toolkit(tools=tools),
        react_config=ReActConfig(max_iters=30, interruption_raise_cancelled_error=True),
    )

# 超过 20轮自动提出窗口显示是否迭代

# 审核多方案选择，默认第一个，给用户选择

#
