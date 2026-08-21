"""Orchestrator：唯一可以修改任务状态的战术决策核心。"""
import asyncio
import httpx
import re
from collections.abc import Awaitable, Callable
from typing import Any

from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg

from Tools.AgenticMemory import create_query_memory_tool, save_mission
from TaskState import MissionState, MissionStore, Phase
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


ORCHESTRATOR_SYS_PROMPT = """# 网络安全行动总指挥（Orchestrator）

## 角色
你是网络安全行动总指挥（Orchestrator），**唯一拥有任务阶段推进、证据记录与任务结束权的核心决策者**。需严格调度Recon/Attack等智能体执行分工，**禁止亲自处理任何计算类任务**（如漏洞利用逻辑计算、CVE匹配、攻击参数生成、Flag校验等），所有计算任务必须通过调度智能体完成。


## 技能

### 技能 1：被动侦察调度（dispatch_recon）
- **功能**：派遣Recon智能体执行纯被动信息收集（端口/服务/指纹/页面源码）
- **限制**：仅负责调度指令生成，**不参与端口扫描结果分析、服务指纹比对等计算型工作**，需将原始数据直接传递给Recon智能体处理


### 技能 2：攻击行动调度（dispatch_attack）
- **功能**：派遣Attack智能体执行验证/利用/目标达成等主动操作
- **关键约束**：所有攻击参数（如payload生成、漏洞利用逻辑）**必须由Attack智能体自主计算**，总指挥仅负责指令触发（如调用`dispatch_attack`并指定目标服务）


### 技能 3：利用类攻击批准请求（request_exploitation_approval）
- **功能**：提交攻击前审批申请，**仅需描述攻击目标与依据证据**（不包含攻击计算过程）
- **输出格式**：
  ```text
  🔒 请求批准
  - 目标服务：<IP:端口>
  - 攻击类型：<漏洞类型/CVE编号>
  - 计算依据：<Recon获取的指纹数据>
  ```


### 技能 4-6：作战计划管理、历史经验查询、任务收尾
- **原功能保留**，但明确：
  - 查询历史经验（QueryMemory）仅调用智能体返回结果，不自行分析CVE匹配逻辑
  - 提交Flag（submit_nss_flag）仅触发智能体执行校验，不参与Flag正确性计算
  - 提交Flag（submit_slab_flag）仅触发智能体执行校验，不参与Flag正确性计算
  - 任务状态更新（UpdatePlan）仅记录智能体返回的计算结果（如"攻击成功/失败"）


## 新增限制
1. **禁止计算型任务**：不亲自执行任何计算，包括但不限于：
   - 漏洞利用逻辑设计与参数生成
   - CVE漏洞匹配与攻击链计算
   - NSSCTF Flag校验算法及结果判断
   - 端口扫描结果的有效性分析
   - 攻击路径的计算优化（如最优Payload选择）

2. **严格委托原则**：所有计算密集型任务必须通过智能体执行：
   - 侦察结果分析 → 由Recon智能体生成原始数据后，通过action接口传递给总指挥
   - 攻击动作执行 → 仅触发Attack智能体执行，不干预其内部计算过程
   - 作战方案优化 → 仅基于智能体返回的计算结果（如"剩余尝试次数"）调整计划

3. **计算型指令规范**：需通过结构化指令触发智能体计算：
   - 调用`QueryMemory`获取历史攻击经验（由智能体返回计算结果）
   - 使用`submit_nss_flag`提交Flag校验（由任务系统直接处理计算逻辑）

4. **状态监控边界**：仅依据智能体返回的状态信息（如"攻击次数剩余2次"）进行任务管理，不自行计算剩余次数


## 原有限制延续
- 必须通过request_exploitation_approval获取攻击批准
- 内网IP扩容需走request_scope_expansion流程
- 作战计划需通过AddPlan/UpdatePlan维护，禁止无证据标记完成
- 禁止伪造任务结果，未完成任务需明确标注失败状态

（注：所有计算型任务的输出参数必须由智能体返回，总指挥仅负责指令触发与流程控制）

"""


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
    *,
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
        store.checkpoint(mission, "recon_dispatch_before")
        try:
            result = await run_interruptible_agent_reply(
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
        store.checkpoint(mission, "recon_report_received")
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
        # P3 去重（v0.3.0 升级为动作指纹）：工具名+目标+规范化参数+目标
        # 描述+证据版本，防止只改写 objective 措辞绕过；相同动作+相同
        # 错误达到阈值自动熔断。
        evidence_version = len(mission.findings) + len(mission.attack_chain)
        fingerprint = compute_action_fingerprint(
            "dispatch_attack", mission.target,
            {"target_info": target_info, "objective": objective, "service": service, "cve": cve},
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
        if exploitation and mission.phase == Phase.ANALYSIS:
            mission.transition(Phase.EXPLOITATION, f"开始执行: {objective}")
        if any(word in lower or word in objective for word in ("flag", "post", "提权")):
            if mission.phase == Phase.EXPLOITATION:
                mission.transition(Phase.POST_EXPLOITATION, f"开始执行: {objective}")
        mission.record("Orchestrator", "dispatch_attack", objective=objective)
        store.checkpoint(mission, "attack_dispatch_before")
        store.save(mission)
        try:
            result = await run_interruptible_agent_reply(
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
            result = await run_interruptible_agent_reply(
                reserve_agent,
                UserMsg(
                    name="Orchestrator",
                    content=(
                        f"授权目标：{mission.target}\n"
                        f"二进制文件：{binary_path}\n"
                        f"本轮目标：{objective}\n\n"
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
                "steps": [base_steps[0], "执行最小化 PoC 并保存可复核证据", "获得结论后立即停止"],
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
                "steps": ["优先处理最高置信度攻击路径", *base_steps[:2], "达到任务目标或边界条件后立即停止"],
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
        if approved:
            mission.exploitation_approved = True
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
        store.checkpoint(mission, "mission_terminal")
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
            resp = await httpx.AsyncClient(timeout=60.0).post(url, json=payload, headers=headers)
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
        AllowedFunctionTool(submit_slab_flag, is_concurrency_safe=False),
        create_query_memory_tool(),
    ]
    return Agent(
        name=ORCHESTRATOR_EXPERT,
        system_prompt=ORCHESTRATOR_SYS_PROMPT,
        model=model,
        toolkit=StrictJSONToolkit(tools=tools),
        react_config=ReActConfig(max_iters=30, interruption_raise_cancelled_error=True),
        offloader=offloader,
        context_config=context_config,
        state=state,
    )

# 超过 20轮自动提出窗口显示是否迭代

# 审核多方案选择，默认第一个，给用户选择

#
