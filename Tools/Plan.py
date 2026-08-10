"""Plan 工具集：Brain / Orchestrator 共用的作战计划清单维护工具。

设计要点：
- 所有工具通过闭包绑定 mission / store / event_callback；
- 每次变更立即持久化（store.save）并推送 plan_updated 事件（SSE → 前端）；
- 标记 completed 强制要求 evidence（防伪造闸门）；
- 全部操作写入审计链（mission.record）。
"""
from collections.abc import Callable
from typing import Any

from TaskState import MissionState, MissionStore
from Tools.tooling import AllowedFunctionTool

# 计划条目允许的阶段归属与状态取值
PLAN_PHASES = {"recon", "analysis", "exploitation", "post_exploitation", "complete"}
PLAN_STATUSES = {"pending", "in_progress", "completed", "failed", "skipped"}


def push_plan_update(
    mission: MissionState,
    event_callback: Callable[[str, dict[str, Any]], None] | None,
) -> None:
    """向 SSE 订阅者推送计划清单全量快照。"""
    if event_callback is not None:
        event_callback(
            "plan_updated",
            items=mission.plan_items,
            phase=mission.phase.value,
        )


def _find_item(items: list[dict], item_id: str) -> dict | None:
    return next((it for it in items if it.get("id") == item_id), None)


def _commit(
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None,
    actor: str,
    action: str,
    **detail: Any,
) -> None:
    """统一收尾：审计 → 持久化 → 推送前端。"""
    mission.record(actor, action, **detail)
    store.save(mission)
    push_plan_update(mission, event_callback)


def create_add_plan_tool(
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    default_origin: str = "brain",
) -> AllowedFunctionTool:
    """创建 AddPlan 工具：向作战计划清单追加一条计划项。"""

    def AddPlan(
        id: int,
        content: str,
        phase: str,
        status: str = "pending",
        evidence: str = "",
        origin: str = "",
    ) -> str:
        """向作战计划清单追加一条计划项。

        Args:
            id: 条目序号（>=1），实际条目 id 为 p<id>，如 1 → p1。
            content: 条目描述，一句话概括该步要达成什么。
            phase: 阶段归属：recon/analysis/exploitation/post_exploitation/complete。
            status: 初始状态：pending/in_progress/completed/failed/skipped，默认 pending。
            evidence: status 为 completed 时必填的证据摘要。
            origin: 来源标识，留空时由绑定的 Agent 决定（brain/orchestrator）。
        """
        if id < 1:
            return f"[拒绝] id 必须 >= 1，收到: {id}"
        content = content.strip()
        if not content:
            return "[拒绝] content（条目描述）不能为空"
        if phase not in PLAN_PHASES:
            return f"[拒绝] 非法 phase: {phase or '(空)'}，可选: {sorted(PLAN_PHASES)}"
        if status not in PLAN_STATUSES:
            return f"[拒绝] 非法 status: {status}，可选: {sorted(PLAN_STATUSES)}"
        # 防伪造闸门：标完成必须附证据
        if status == "completed" and not evidence.strip():
            return "[拒绝] 标记 completed 必须在 evidence 中写明证据摘要"

        items = mission.plan_items
        item_id = f"p{id}"
        if _find_item(items, item_id) is not None:
            return f"[拒绝] 条目 {item_id} 已存在，请更换 id 或用 UpdatePlan 修改"

        new_item = {
            "id": item_id,
            "content": content,
            "phase": phase,
            "status": status,
            "evidence": evidence.strip(),
            "origin": origin.strip() or default_origin,
        }
        items.append(new_item)
        _commit(
            mission, store, event_callback,
            new_item["origin"], "plan_item_added", item=new_item,
        )
        return f"[已添加] {item_id} [{phase}] {content}（计划共 {len(items)} 项）"

    return AllowedFunctionTool(AddPlan, is_concurrency_safe=False)


def create_update_plan_tool(
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> AllowedFunctionTool:
    """创建 UpdatePlan 工具：修改条目内容/阶段，或标记条目状态。"""

    def UpdatePlan(
        id: str,
        content: str = "",
        phase: str = "",
        status: str = "",
        evidence: str = "",
    ) -> str:
        """修改计划条目内容/阶段归属，或标记条目状态。

        Args:
            id: 目标条目 id（如 p2）。
            content: 新的条目描述（可选）。
            phase: 新的阶段归属（可选）。
            status: 目标状态：pending/in_progress/completed/failed/skipped（可选）。
            evidence: 标记 completed 时必填的工具证据摘要。
        """
        target = _find_item(mission.plan_items, id.strip())
        if target is None:
            return f"[拒绝] 未找到计划条目: {id or '(空)'}"
        if not (content.strip() or phase or status or evidence.strip()):
            return "[拒绝] 至少提供 content/phase/status/evidence 之一"
        if phase and phase not in PLAN_PHASES:
            return f"[拒绝] 非法 phase: {phase}，可选: {sorted(PLAN_PHASES)}"
        if status and status not in PLAN_STATUSES:
            return f"[拒绝] 非法 status: {status}，可选: {sorted(PLAN_STATUSES)}"
        # 防伪造闸门：标完成必须附工具证据
        if status == "completed" and not evidence.strip():
            return "[拒绝] 标记 completed 必须在 evidence 中写明工具证据摘要"

        if content.strip():
            target["content"] = content.strip()
        if phase:
            target["phase"] = phase
        if status:
            target["status"] = status
        if evidence.strip():
            target["evidence"] = evidence.strip()
        _commit(
            mission, store, event_callback,
            "Orchestrator", "plan_item_updated",
            item_id=id, status=target["status"], evidence=target.get("evidence", ""),
        )
        return f"[已更新] {id}: status={target['status']}, phase={target['phase']}"

    return AllowedFunctionTool(UpdatePlan, is_concurrency_safe=False)


def create_delete_plan_tool(
    mission: MissionState,
    store: MissionStore,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> AllowedFunctionTool:
    """创建 DeletePlan 工具：删除指定计划条目。"""

    def DeletePlan(id: str) -> str:
        """删除指定计划条目。

        Args:
            id: 目标条目 id（如 p2）。
        """
        items = mission.plan_items
        target = _find_item(items, id.strip())
        if target is None:
            return f"[拒绝] 未找到计划条目: {id or '(空)'}"
        items.remove(target)
        _commit(
            mission, store, event_callback,
            "Orchestrator", "plan_item_deleted", item=target,
        )
        return f"[已删除] {id}（计划剩余 {len(items)} 项）"

    return AllowedFunctionTool(DeletePlan, is_concurrency_safe=False)


def create_list_plan_tool(
    mission: MissionState,
    store: MissionStore | None = None,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> AllowedFunctionTool:
    """创建 ListPlan 工具：查看当前作战计划清单（只读）。"""

    def ListPlan() -> list[dict]:
        """查看当前作战计划清单（全量条目：id/content/phase/status/evidence/origin）。"""
        return mission.plan_items

    return AllowedFunctionTool(ListPlan, is_read_only=True)
