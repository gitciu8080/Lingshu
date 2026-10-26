"""快速模式指挥官（Blade）：单 Agent 调度 + 按需唤起专家子 Agent。

ZCode 式架构的灵枢实现：指挥官持只读 shell 与 spawn_expert 派工工具，
专家子 Agent 带独立上下文出发、报告文本作为工具结果返回（过程不进
指挥官上下文）。与标准模式（Orchestrator 工作流）完全隔离：本模块
不依赖也不修改 Orchestrator/Brain 的任何代码。
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Callable

import httpx
from agentscope.agent import Agent, ReActConfig
from agentscope.message import UserMsg

from agent.context import build_agent_context_config
from agent.prompt_loader import load_prompt
from Tools.tool_catalog import create_tool_catalog_tools
from Tools.tooling import (
    AllowedFunctionTool,
    StrictJSONToolkit,
    create_scoped_shell_tool,
    run_expert_reply_with_continuation,
)

FAST_CAPTAIN_EXPERT = "Blade - 快速夺旗指挥官"

# spawn_expert 允许的角色（与 main.py fast 分支装配的专家一一对应）
SPAWN_ROLES: tuple[str, ...] = ("attack", "reverse", "triage", "recon", "analysis")

_ROLE_DESCRIPTIONS: dict[str, str] = {
    "attack": "攻击专家（按题型 web/pwn/crypto/forensics/misc 自动装配技能）",
    "reverse": "逆向分析专家（IDA/GDB、脱壳、算法还原）",
    "triage": "文件体检专家（解压附件的取证初筛，禁联网）",
    "recon": "网络侦察专家（仅授权目标的被动侦察）",
    "analysis": "漏洞研判专家（CVE 检索与纯推理，不执行命令）",
}

_REPORT_LIMIT = 4000


def _bounded_context(mission: Any) -> str:
    """给专家注入的有界事实摘要（专家看不到指挥官对话历史）。"""
    parts: list[str] = [f"任务目标：{(mission.goal or '')[:400]}"]
    if getattr(mission, "findings", None):
        tail = mission.findings[-3:]
        parts.append("近期发现：\n" + "\n".join(
            f"- {str(item.get('report') or item.get('finding') or '')[:300]}"
            for item in tail
        ))
    if getattr(mission, "flag", None):
        parts.append(f"已知 flag 候选：{mission.flag}")
    return "\n".join(parts)


def create_fast_captain_agent(
    model,
    *,
    experts: dict[str, Any],
    mission: Any,
    store: Any,
    event_callback: Callable[..., None] | None,
    target: str,
    workdir: str,
    timeout: int,
    scope_registry: Any = None,
    nss_context: dict | None = None,
    slab_context: dict | None = None,
    max_iters: int = 15,
    offloader: Any = None,
    context_config: Any = None,
    state: Any = None,
    artifact_root: Any = None,
) -> Agent:
    """装配快速模式指挥官。

    Args:
        experts: role → LazyAgent（attack/reverse/triage/recon/analysis），
            由 main.py fast 分支用现有专家工厂创建（继承模型分工与预算）。
        mission/store/event_callback: 共享的权威任务状态与事件通道。
        nss_context/slab_context: 平台在线提交上下文（可选）。
    """
    from core.TaskState import Phase  # 延迟导入防环

    # 后台专家状态：同一专家实例并发 reply 不安全（Agent state 无并发保护），
    # 因此按 role 忙碌互斥；不同 role 是不同实例，天然可并行。
    bg_state: dict[str, Any] = {"ready": [], "running": {}, "busy_roles": set()}
    _BG_LIMIT = 2  # 后台并发专家上限

    def _note_report(role: str, objective: str, report_text: str) -> None:
        trimmed = report_text[:_REPORT_LIMIT] + (
            "\n…（报告已截断，完整内容见会话事件流）"
            if len(report_text) > _REPORT_LIMIT else ""
        )
        bg_state["ready"].append({
            "role": role, "objective": objective[:200], "report": trimmed,
        })

    async def _run_expert(key: str, objective: str, *, background: bool) -> str:
        """执行体：同步路径直接返回报告；后台路径把报告放入待收取队列。"""
        lazy = experts[key]
        expert = await lazy.get()
        mission.record(
            "Orchestrator", "expert_dispatched", role=key,
            expert=expert.name, objective=str(objective)[:500],
            background=background,
        )
        store.save(mission)
        try:
            report = await run_expert_reply_with_continuation(
                expert,
                UserMsg(
                    name=FAST_CAPTAIN_EXPERT,
                    content=(
                        f"{_bounded_context(mission)}\n\n"
                        f"本轮任务：{str(objective)[:2000]}\n"
                        "完成后立即输出最终报告（结论/证据/下一步），禁止继续调用工具。"
                    ),
                ),
                prefix=f"[{expert.name.split(' ')[0]}] ",
                on_event=event_callback,
                label=expert.name,
            )
        except Exception as exc:  # noqa: BLE001 - 专家失败返回给指挥官决策
            mission.record("Orchestrator", "expert_failed", role=key, error=str(exc)[:300])
            store.save(mission)
            return f"专家执行失败：{exc}。请调整目标重派或换角色。"
        report_text = str(report or "").strip()
        # 报告即结论：flag 候选顺手登记（先挂证据再记事实，满足审计约束），
        # 指挥官据此收尾。
        flag_match = re.search(
            r"(?:[A-Za-z0-9_]+)?flag\{[^{}\r\n]+\}", report_text, re.IGNORECASE,
        )
        if flag_match and not mission.flag:
            evidence = mission.add_evidence(
                f"fast:{key}", "expert_report",
                f"{expert.name} 报告中发现 Flag 候选: {flag_match.group(0)}",
                confidence=0.85,
            )
            mission.add_fact(
                f"专家报告中发现 Flag 候选: {flag_match.group(0)}", "fast_mode",
                [evidence.id], confidence=0.85,
            )
            store.save(mission)
        if background:
            mission.record(
                "Orchestrator", "expert_completed", role=key,
                objective=str(objective)[:200], report_chars=len(report_text),
            )
            store.save(mission)
            _note_report(key, objective, report_text or "（专家未返回报告）")
            return ""  # 后台路径不直接回传，由 check_experts 收取
        if len(report_text) > _REPORT_LIMIT:
            return report_text[:_REPORT_LIMIT] + "\n…（报告已截断，完整内容见会话事件流）"
        return report_text or "（专家未返回报告，请重派或换角色）"

    async def _background_worker(handle: str, key: str, objective: str) -> None:
        bg_state["busy_roles"].add(key)
        try:
            await _run_expert(key, objective, background=True)
        finally:
            bg_state["busy_roles"].discard(key)
            bg_state["running"].pop(handle, None)

    async def spawn_expert(role: str, objective: str, background: bool = False) -> str:
        """派出专家子 Agent 执行一个聚焦任务并返回其最终报告。

        Args:
            role: 专家角色，可选 attack/reverse/triage/recon/analysis。
            objective: 一句话聚焦目标，必须自包含（专家看不到指挥官对话）。
            background: True 时立即返回句柄、专家转入后台执行（不同角色可
                并行）；报告完成后经 check_experts 收取。同一角色同一时刻
                只能执行一个任务。
        """
        key = str(role or "").strip().lower()
        if key not in experts:
            return (
                f"未知角色 “{role}”。可用角色："
                + "；".join(f"{r}（{_ROLE_DESCRIPTIONS[r]}）" for r in SPAWN_ROLES if r in experts)
            )
        if not str(objective or "").strip():
            return "objective 不能为空：请给出一句自包含的聚焦任务描述。"
        if key in bg_state["busy_roles"]:
            return (
                f"专家 {key} 正在执行任务（同一专家不能并行处理两个任务）。"
                "请改派其它角色，或调用 check_experts(wait=true) 等待其完成。"
            )
        if background:
            if len(bg_state["running"]) >= _BG_LIMIT:
                return (
                    f"后台专家已达并发上限（{_BG_LIMIT}）。请先调用 check_experts "
                    "收取已完成报告，或等待运行中的任务结束。"
                )
            handle = f"{key}#{len(bg_state['running']) + len(bg_state['ready']) + 1}"
            task = asyncio.create_task(
                _background_worker(handle, key, str(objective)),
                name=f"fast-expert:{handle}",
            )
            bg_state["running"][handle] = {
                "role": key, "objective": str(objective)[:200], "task": task,
            }
            return (
                f"已转入后台执行：{handle}（{key}）。"
                "你可以继续派其它角色的专家或做只读查验；"
                "用 check_experts(wait=true) 等待并收取报告。"
            )
        return await _run_expert(key, str(objective), background=False)

    async def check_experts(wait: bool = False, timeout: int = 240) -> str:
        """收取后台专家的报告。

        Args:
            wait: True 时等待至少一份报告完成（有界超时）再返回。
            timeout: 等待上限秒数（10~600）。
        """
        if wait and not bg_state["ready"]:
            running = [entry["task"] for entry in bg_state["running"].values()
                       if not entry["task"].done()]
            if running:
                bounded = max(10, min(int(timeout), 600))
                done, _pending = await asyncio.wait(
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
            return "当前没有后台专家任务（用 spawn_expert(background=true) 派出）。"
        parts = [f"已收取 {len(ready)} 份报告："]
        for item in ready:
            parts.append(
                f"\n===== [{item['role']}] {item['objective']} =====\n{item['report']}"
            )
        if running_now:
            lines = "\n".join(f"- {h}（{t}）" for h, t in running_now.items())
            parts.append(f"\n仍在运行：\n{lines}")
        return "\n".join(parts)

    async def fast_complete_mission(flag: str = "", success: bool = True, reason: str = "") -> str:
        """收尾任务：拿到 flag 立即调用（success=False 表示放弃/失败）。"""
        if mission.phase in {Phase.COMPLETED, Phase.FAILED, Phase.CANCELLED}:
            return "任务已处于终态。"
        if str(flag or "").strip():
            mission.flag = str(flag).strip()
            mission.success = True
            mission.transition(Phase.COMPLETED, "fast_mode_complete")
        elif success:
            mission.success = True
            mission.transition(Phase.COMPLETED, "fast_mode_complete_no_flag")
        else:
            mission.success = False
            mission.summary = str(reason or "")[:2000] or mission.summary
            mission.transition(Phase.FAILED, "fast_mode_abandoned")
        mission.record(
            "Orchestrator", "fast_mode_complete",
            success=mission.success, flag=mission.flag or "",
        )
        store.save(mission)
        if event_callback is not None and mission.flag:
            event_callback("flag_found", flag=mission.flag)
        return (
            f"任务已收尾：success={mission.success}, flag={mission.flag or '无'}。"
            "本轮回复不再调度任何专家。"
        )

    def _submit_to_platform(context: dict, flag: str, *, slab: bool) -> dict:
        """NSS / slab 平台在线判定（correct/wrong/网络错误）。"""
        if slab:
            url = f"{str(context.get('api_base', '')).rstrip('/')}/api/flag/submit"
            headers = {
                "Authorization": f"Bearer {context.get('token', '')}",
                "User-Agent": "curl/8.5.0",
                "Content-Type": "application/json",
            }
            payload: dict[str, Any] = {"flag": flag, "challenge_id": context.get("challenge_id")}
        else:
            url = (
                f"{str(context.get('api_base', '')).rstrip('/')}"
                f"/skill/agent/arena/attempt/{context.get('attempt_id')}/submit/"
            )
            headers = {
                "Authorization": f"Bearer {context.get('token', '')}",
                "Content-Type": "application/json",
            }
            payload = {"flag": flag}
        response = httpx.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        return response.json()

    async def fast_submit_flag(flag: str) -> str:
        """向任务绑定的夺旗平台在线提交 flag（NSS / DASCTF slab）。"""
        value = str(flag or "").strip()
        if not value:
            return "flag 不能为空。"
        context = nss_context or slab_context
        if context is None:
            return "本任务未绑定在线平台，请改用 fast_complete_mission。"
        if nss_context and not value.startswith(("NSSCTF{", "flag")):
            return "NSS 平台要求 flag 以 NSSCTF{ 或 flag 开头，请核对候选值。"
        try:
            result = _submit_to_platform(context, value, slab=bool(slab_context and not nss_context))
        except Exception as exc:  # noqa: BLE001
            return f"提交请求失败：{exc}。请稍后重试或改用 fast_complete_mission。"
        correct = bool(
            result.get("correct") or result.get("data", {}).get("correct")
            or str(result.get("status", "")).lower() in {"correct", "success"}
        )
        if correct:
            if mission.phase not in {Phase.COMPLETED, Phase.FAILED, Phase.CANCELLED}:
                mission.flag = value
                mission.success = True
                mission.transition(Phase.COMPLETED, "platform_flag_correct")
                mission.record("Orchestrator", "fast_mode_flag_correct", flag=value)
                store.save(mission)
            if event_callback is not None:
                event_callback("flag_found", flag=value)
            return "平台判定正确，任务已完成。无需再做任何操作。"
        mission.record(
            "Orchestrator", "fast_mode_flag_wrong", flag=value,
            response=str(result)[:300],
        )
        store.save(mission)
        return "平台判定错误：flag 不正确。请继续解题，不要重复提交该值。"

    tools: list[AllowedFunctionTool] = [
        AllowedFunctionTool(
            spawn_expert,
            name="spawn_expert",
            description=(
                "派出专家子 Agent 执行聚焦任务并返回其报告。"
                "background=true 时转入后台执行（不同角色可并行），报告用 check_experts 收取；"
                "同一角色同一时刻只能执行一个任务。"
            ),
            is_concurrency_safe=False,
        ),
        AllowedFunctionTool(
            check_experts,
            name="check_experts",
            description=(
                "收取后台专家的报告；wait=true 时等待至少一份完成（timeout 秒，默认 240）。"
                "立即模式返回全部已完成报告与运行中清单。"
            ),
            is_concurrency_safe=False,
        ),
        AllowedFunctionTool(
            fast_complete_mission,
            name="fast_complete_mission",
            description="收尾任务：拿到 flag 立即调用（flag 参数）；明确无法解出时 success=False 放弃。",
            is_concurrency_safe=False,
        ),
        create_scoped_shell_tool(
            target, workdir, timeout, registry=scope_registry,
            role="captain", artifact_root=artifact_root, read_only=True,
        ),
        *create_tool_catalog_tools("recon", categories={"recon"}),
    ]
    if nss_context or slab_context:
        tools.append(AllowedFunctionTool(
            fast_submit_flag,
            name="submit_flag",
            description="向任务绑定的夺旗平台（NSS/DASCTF）在线提交 flag 并获得判定。",
            is_concurrency_safe=False,
        ))

    prompt = load_prompt("FAST_CAPTAIN")
    prompt += "\n## 本轮可用专家\n" + "\n".join(
        f"- `{role}`：{_ROLE_DESCRIPTIONS[role]}" for role in SPAWN_ROLES if role in experts
    )
    if nss_context or slab_context:
        prompt += (
            "\n\n本任务绑定在线夺旗平台：拿到 flag 候选后**优先调用 submit_flag**"
            "在线判定（判对即完成任务）；判错则继续解题。\n"
            "平台格式要求：NSS 以 NSSCTF{ 或 flag 开头。"
        )
    agent = Agent(
        name=FAST_CAPTAIN_EXPERT,
        system_prompt=prompt,
        model=model,
        toolkit=StrictJSONToolkit(tools=tools),
        react_config=ReActConfig(
            max_iters=max_iters, interruption_raise_cancelled_error=True,
        ),
        offloader=offloader,
        context_config=context_config or build_agent_context_config(),
        state=state,
    )
    # 主循环窥视通道：后台报告就绪时注入"调用 check_experts"提示。
    agent._lingshu_bg = bg_state
    return agent
