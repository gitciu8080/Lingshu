"""当前任务的结构化状态、持久化与审计日志。"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# 审计链创世哈希：首条事件 previous_hash 的固定锚点
_GENESIS_HASH = "genesis" * 16  # 64 字符，占位创世锚


def _hash_event(payload: dict[str, Any]) -> str:
    """审计事件哈希：对规范化 JSON（排序键、无多余空白）做 SHA-256。"""
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit_chain(events: list["AuditEvent"]) -> tuple[bool, int]:
    """校验审计链完整性；返回 (是否完整, 失败事件序号)。

    旧事件（legacy，无 event_hash）跳过不校验；从第一条带哈希的事件
    开始逐条验证 previous_hash 与自身 event_hash。
    """
    previous_hash = _GENESIS_HASH
    for index, event in enumerate(events):
        if not event.event_hash:
            continue  # legacy 事件不参与哈希链
        if event.seq != index + 1:
            return False, index + 1
        if event.previous_hash != previous_hash:
            return False, index + 1
        expected_hash = _compute_event_hash(event, previous_hash)
        if event.event_hash != expected_hash:
            return False, index + 1
        previous_hash = event.event_hash
    return True, 0


def _compute_event_hash(event: "AuditEvent", previous_hash: str) -> str:
    payload = {
        "seq": event.seq,
        "timestamp": event.timestamp,
        "actor": event.actor,
        "action": event.action,
        "phase": event.phase,
        "details": event.details,
        "previous_hash": previous_hash,
    }
    return _hash_event(payload)


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def _bounded_data(value: Any, *, depth: int = 0) -> Any:
    """限制执行历史中的参数体积，原始产物仍由现有 artifact 机制保存。"""
    if depth >= 4:
        return str(value)[:500]
    if isinstance(value, dict):
        return {
            str(key)[:200]: _bounded_data(item, depth=depth + 1)
            for key, item in list(value.items())[:40]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_data(item, depth=depth + 1) for item in value[:40]]
    if isinstance(value, str):
        return value[:4000]
    return copy.deepcopy(value)


class Phase(str, Enum):
    PLANNING = "planning"
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


_ALLOWED_TRANSITIONS = {
    Phase.PLANNING: {Phase.RECON, Phase.FAILED, Phase.CANCELLED},
    Phase.RECON: {Phase.RECON, Phase.ANALYSIS, Phase.FAILED, Phase.CANCELLED},
    Phase.ANALYSIS: {
        Phase.RECON,
        Phase.ANALYSIS,
        Phase.EXPLOITATION,
        Phase.COMPLETED,
        Phase.FAILED,
        Phase.CANCELLED,
    },
    Phase.EXPLOITATION: {
        Phase.RECON,
        Phase.ANALYSIS,
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.COMPLETED,
        Phase.FAILED,
        Phase.CANCELLED,
    },
    Phase.POST_EXPLOITATION: {
        Phase.POST_EXPLOITATION,
        Phase.COMPLETED,
        Phase.FAILED,
        Phase.CANCELLED,
    },
    Phase.COMPLETED: set(),
    Phase.FAILED: set(),
    Phase.CANCELLED: set(),
}


@dataclass
class AuditEvent:
    timestamp: str
    actor: str
    action: str
    phase: str
    details: dict[str, Any] = field(default_factory=dict)
    # ── v0.3.0 审计链：单调序号 + 前序哈希 + 自身哈希；旧事件为 legacy ──
    seq: int = 0
    previous_hash: str = ""
    event_hash: str = ""


@dataclass
class EvidenceRecord:
    """一次可追溯的原始证据或 Agent 报告引用。"""

    id: str
    source: str
    kind: str
    summary: str
    artifact: str = ""
    category: str = ""
    confidence: float = 0.0
    fingerprint: str = ""
    created_at: str = field(default_factory=_now)


@dataclass
class FactRecord:
    """由证据支持、可供后续决策直接引用的已验证事实。"""

    id: str
    content: str
    source: str
    evidence_ids: list[str] = field(default_factory=list)
    category: str = ""
    confidence: float = 0.0
    created_at: str = field(default_factory=_now)


@dataclass
class AttemptRecord:
    """一次高层行动（Recon/Attack/Reverse）的结构化执行记录。"""

    id: str
    action_type: str
    agent: str
    target: str
    normalized_parameters: dict[str, Any] = field(default_factory=dict)
    status: str = "running"
    result_summary: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    information_gain: str = "none"
    started_at: str = field(default_factory=_now)
    completed_at: str = ""


_HYPOTHESIS_STATUSES = {
    "proposed", "testing", "supported", "weakened", "rejected", "confirmed",
}
_FAILURE_TYPES = {
    "transient", "parameter", "tool", "environment", "method", "hypothesis_rejected",
    "agent_unavailable", "protocol_error", "memory_backend_error", "phase_blocked",
}


@dataclass
class HypothesisRecord:
    """可随证据演进的行动假设。终态假设不会再驱动相同路径。"""

    id: str
    statement: str
    status: str = "proposed"
    supporting_evidence: list[str] = field(default_factory=list)
    opposing_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    related_actions: list[str] = field(default_factory=list)
    next_validation: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass
class ActionRecord:
    """统一 Function/MCP 调用记录；signature 不依赖 LLM。"""

    id: str
    signature: str
    tool: str
    target: str
    context: str = ""
    endpoint: str = ""
    method: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    payload: str = ""
    command: str = ""
    hypothesis_id: str = ""
    status: str = "running"
    result_summary: str = ""
    result_valid: bool = False
    retry_count: int = 0
    decision: str = "execute"
    created_at: str = field(default_factory=_now)
    completed_at: str = ""


@dataclass
class FailedPathRecord:
    """一次失败的结构化记忆，用于 Retry/Fallback/停止路径决策。"""

    id: str
    action_id: str
    action: str
    tool: str
    context: str
    parameters: dict[str, Any]
    failure_type: str
    failure_reason: str
    result: str
    related_hypothesis: str = ""
    retry_count: int = 0
    resolution: str = "fallback"
    signature: str = ""
    created_at: str = field(default_factory=_now)


@dataclass
class MissionState:
    target: str
    goal: str
    authorized: bool
    session_id: str = ""
    title: str = ""
    # 任务模式：ctf / incident_response / authorized_pentest / hybrid_taskbook
    mission_mode: str = ""
    phase: Phase = Phase.PLANNING
    plan: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_chain: list[dict[str, Any]] = field(default_factory=list)
    flag: str | None = None
    success: bool | None = None
    summary: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    events: list[AuditEvent] = field(default_factory=list)

    # ── v0.2.0 新增 ──
    target_spec: dict[str, Any] | None = None
    category_decision: dict[str, Any] | None = None
    category_history: list[dict[str, Any]] = field(default_factory=list)
    authorization_evidence: dict[str, Any] = field(default_factory=dict)

    # 首次进入攻击阶段（EXPLOITATION）的人工批准状态；
    # 持久化后即使崩溃恢复也不会重复询问
    exploitation_approved: bool = False

    # 审批展示与恢复不能只依赖布尔值：false 可能表示从未申请、等待中、
    # 已拒绝或要求补侦。显式状态作为权威运行态随 Mission JSON 持久化。
    exploitation_approval_status: str = "not_requested"
    exploitation_approval_decision: str = ""
    exploitation_approval_requested_at: str = ""
    exploitation_approval_resolved_at: str = ""

    # 人工批准时选定的攻击方案及用户调整后的优先级顺序。
    approved_attack_plan: dict[str, Any] | None = None

    # 动态授权范围快照（ScopeRegistry.snapshot() 的输出），
    # 崩溃恢复时用于重建 ScopeRegistry
    authorized_scope: dict[str, Any] = field(default_factory=dict)
    declared_scope: dict[str, Any] = field(default_factory=dict)
    scope_approval_status: str = "not_required"
    scope_approval_decision: str = ""
    scope_approval_requested_at: str = ""
    scope_approval_resolved_at: str = ""

    # 作战计划清单：Brain 经 AddPlan 登记（笼统条目），
    # Orchestrator 经 AddPlan/UpdatePlan/DeletePlan/ListPlan 维护（Tools/Plan.py）
    # 每项: {id, content, phase, status, evidence, origin}
    #   status: pending | in_progress | completed | failed | skipped
    #   origin: brain | orchestrator
    plan_items: list[dict[str, Any]] = field(default_factory=list)

    # NSSCTF Agent Arena 提交结果（由 Orchestrator 的 submit_nss_flag 工具写入）：
    # {attempt_id, flag, correct, remaining_wrong_attempts}
    nss_submit: dict[str, Any] | None = None

    # slab-match 平台提交结果（由 Orchestrator 的 submit_slab_flag 工具写入）：
    # {exercise_id, flag, submitted, correct, api_base}
    slab_submit: dict[str, Any] | None = None

    # ── v0.3.0 Workspace v2 新增 ──
    # 工作区标识（workspace_service.workspace_id() 的确定性输出）
    workspace_id: str = ""
    # 安全检查点序号：每次 checkpoint 递增，崩溃恢复从最近已提交状态继续
    checkpoint_seq: int = 0
    # 恢复状态机：fresh(新建) / running(运行中) / resumable(可安全继续) /
    # uncertain(存在不确定动作，需人工确认) / terminal(终态，不重放)
    resume_status: str = "fresh"
    # 当前活动计划项 id（如 "p3"），恢复时用于对齐计划清单
    active_plan_item: str | None = None
    # 崩溃前挂起的动作（工具名、参数、指纹、状态），不确定时供前端展示
    pending_action: dict[str, Any] | None = None
    # 最近一次已执行动作的指纹（工具名+目标+规范化参数+目标描述+证据版本）
    last_action_fingerprint: str = ""
    # 相同动作+相同错误的重试计数，达到上限后熔断对应计划项
    retry_counters: dict[str, int] = field(default_factory=dict)
    # 各内部 Agent 的上下文卸载引用（{role: workspace 相对引用}）
    agent_context_refs: dict[str, str] = field(default_factory=dict)

    # ── v0.4.0 最小优化闭环 ──
    # 新旧结构暂时并存：findings/attack_chain 继续供现有 UI、报告和长期记忆使用，
    # 下列结构用于 Orchestrator 的证据和行动决策。
    facts: list[FactRecord] = field(default_factory=list)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    attempts: list[AttemptRecord] = field(default_factory=list)
    hypotheses: list[HypothesisRecord] = field(default_factory=list)
    action_history: list[ActionRecord] = field(default_factory=list)
    failed_paths: list[FailedPathRecord] = field(default_factory=list)
    action_sequence: int = 0
    hypothesis_sequence: int = 0
    failed_path_sequence: int = 0
    complexity: str = "complex"

    # RAG 是参考知识而非当前任务事实。保存最近一次有界检索结果及其状态指纹，
    # 供 Brain/Orchestrator/Attack 共享；不得自动并入 facts/evidence_records。
    knowledge_context: dict[str, Any] = field(default_factory=dict)

    def record(self, actor: str, action: str, **details: Any) -> None:
        self.updated_at = _now()
        # 深拷贝 details：防止调用方后续修改污染已写入审计链的事件
        safe_details = copy.deepcopy(details)
        # 哈希链只链接带哈希的事件；legacy 事件（无 event_hash）不参与
        previous_hash = _GENESIS_HASH
        for event in reversed(self.events):
            if event.event_hash:
                previous_hash = event.event_hash
                break
        seq = len(self.events) + 1
        event = AuditEvent(
            timestamp=self.updated_at,
            actor=actor,
            action=action,
            phase=self.phase.value,
            details=safe_details,
            seq=seq,
            previous_hash=previous_hash,
        )
        event.event_hash = _compute_event_hash(event, previous_hash)
        self.events.append(event)

    def transition(self, phase: Phase, reason: str) -> None:
        if phase not in _ALLOWED_TRANSITIONS[self.phase]:
            raise ValueError(f"非法状态迁移: {self.phase.value} -> {phase.value}")
        previous = self.phase
        self.phase = phase
        self.record(
            "Orchestrator",
            "phase_transition",
            previous=previous.value,
            current=phase.value,
            reason=reason,
        )
        callback = getattr(self, "_phase_callback", None)
        if callback is not None:
            callback(previous, phase, reason)

    def bind_phase_callback(self, callback) -> None:
        """Bind a runtime-only callback invoked after every legal transition."""
        self._phase_callback = callback

    def add_finding(self, source: str, report: str) -> None:
        self.findings.append({"timestamp": _now(), "source": source, "report": report})
        self.record("Orchestrator", "finding_added", source=source)

    def add_attack_step(
        self,
        objective: str,
        report: str,
        service: str = "",
        cve: str = "",
    ) -> None:
        step: dict[str, Any] = {
            "timestamp": _now(),
            "objective": objective,
            "report": report,
        }
        if service:
            step["service"] = service
        if cve:
            step["cve"] = cve
        self.attack_chain.append(step)
        self.record("Orchestrator", "attack_step_added", objective=objective)

    def begin_attempt(
        self,
        action_type: str,
        agent: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> AttemptRecord:
        """创建一条 running Attempt；调用次数不受全局预算限制。"""
        attempt = AttemptRecord(
            id=f"a{len(self.attempts) + 1}",
            action_type=action_type,
            agent=agent,
            target=target,
            normalized_parameters=copy.deepcopy(parameters or {}),
        )
        self.attempts.append(attempt)
        self.record(
            "Orchestrator",
            "attempt_started",
            attempt_id=attempt.id,
            action_type=action_type,
        )
        return attempt

    def finish_attempt(
        self,
        attempt: AttemptRecord,
        status: str,
        result_summary: str,
        evidence_ids: list[str] | None = None,
        information_gain: str = "none",
    ) -> None:
        """确定性收敛 Attempt，并记录本轮信息增益。"""
        if status not in {"success", "failure", "interrupted", "blocked"}:
            raise ValueError(f"非法 Attempt 状态: {status}")
        if information_gain not in {"none", "low", "medium", "high"}:
            raise ValueError(f"非法 information_gain: {information_gain}")
        attempt.status = status
        attempt.result_summary = result_summary[:2000]
        attempt.evidence_ids = list(dict.fromkeys(evidence_ids or []))
        attempt.information_gain = information_gain
        attempt.completed_at = _now()
        self.record(
            "Orchestrator",
            "attempt_finished",
            attempt_id=attempt.id,
            status=status,
            information_gain=information_gain,
            evidence_ids=attempt.evidence_ids,
        )

    def add_evidence(
        self,
        source: str,
        kind: str,
        summary: str,
        *,
        artifact: str = "",
        category: str = "",
        confidence: float = 0.0,
    ) -> EvidenceRecord:
        """写入精确去重的证据；不执行语义级相似度去重。"""
        normalized = summary.strip()
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "source": source,
                    "kind": kind,
                    "summary": normalized,
                    "artifact": artifact,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        ).hexdigest()
        existing = next(
            (item for item in self.evidence_records if item.fingerprint == fingerprint),
            None,
        )
        if existing is not None:
            return existing
        evidence = EvidenceRecord(
            id=f"e{len(self.evidence_records) + 1}",
            source=source,
            kind=kind,
            summary=normalized[:4000],
            artifact=artifact,
            category=category,
            confidence=max(0.0, min(float(confidence), 1.0)),
            fingerprint=fingerprint,
        )
        self.evidence_records.append(evidence)
        self.record(
            "Orchestrator",
            "evidence_added",
            evidence_id=evidence.id,
            source=source,
            kind=kind,
            category=category,
        )
        return evidence

    def add_fact(
        self,
        content: str,
        source: str,
        evidence_ids: list[str],
        *,
        category: str = "",
        confidence: float = 0.0,
    ) -> FactRecord:
        """写入带有效 Evidence 引用的事实；相同内容与引用精确去重。"""
        valid_evidence = {item.id for item in self.evidence_records}
        refs = [item for item in dict.fromkeys(evidence_ids) if item in valid_evidence]
        if not refs:
            raise ValueError("Fact 必须至少引用一条有效 Evidence")
        normalized = content.strip()
        existing = next(
            (
                item for item in self.facts
                if item.content == normalized and item.evidence_ids == refs
            ),
            None,
        )
        if existing is not None:
            return existing
        fact = FactRecord(
            id=f"f{len(self.facts) + 1}",
            content=normalized[:2000],
            source=source,
            evidence_ids=refs,
            category=category,
            confidence=max(0.0, min(float(confidence), 1.0)),
        )
        self.facts.append(fact)
        self.record(
            "Orchestrator",
            "fact_added",
            fact_id=fact.id,
            evidence_ids=refs,
            category=category,
        )
        return fact

    def add_hypothesis(
        self,
        statement: str,
        *,
        confidence: float = 0.5,
        next_validation: str = "",
    ) -> HypothesisRecord:
        """登记假设；完全相同的未终止假设直接复用。"""
        normalized = " ".join(statement.split())
        if not normalized:
            raise ValueError("Hypothesis 内容不能为空")
        existing = next((
            item for item in self.hypotheses
            if item.statement == normalized and item.status not in {"rejected", "confirmed"}
        ), None)
        if existing is not None:
            return existing
        self.hypothesis_sequence += 1
        item = HypothesisRecord(
            id=f"h{self.hypothesis_sequence}",
            statement=normalized[:2000],
            confidence=max(0.0, min(float(confidence), 1.0)),
            next_validation=next_validation.strip()[:1000],
        )
        self.hypotheses.append(item)
        # 限制状态增长；优先保留所有当前有效假设和最近的终态假设。
        if len(self.hypotheses) > 60:
            active = [h for h in self.hypotheses if h.status not in {"rejected", "confirmed"}]
            terminal = [h for h in self.hypotheses if h.status in {"rejected", "confirmed"}]
            active = active[-60:]
            slots = max(0, 60 - len(active))
            kept_terminal = terminal[-slots:] if slots else []
            self.hypotheses = active + kept_terminal
        self.record("Orchestrator", "hypothesis_added", hypothesis_id=item.id)
        return item

    def update_hypothesis(
        self,
        hypothesis_id: str,
        *,
        status: str | None = None,
        supporting_evidence: list[str] | None = None,
        opposing_evidence: list[str] | None = None,
        confidence: float | None = None,
        action_id: str = "",
        next_validation: str | None = None,
    ) -> HypothesisRecord:
        item = next((h for h in self.hypotheses if h.id == hypothesis_id), None)
        if item is None:
            raise ValueError(f"Hypothesis 不存在: {hypothesis_id}")
        if status is not None:
            if status not in _HYPOTHESIS_STATUSES:
                raise ValueError(f"非法 Hypothesis 状态: {status}")
            item.status = status
        valid_evidence = {e.id for e in self.evidence_records}
        if supporting_evidence:
            item.supporting_evidence = list(dict.fromkeys([
                *item.supporting_evidence,
                *[e for e in supporting_evidence if e in valid_evidence],
            ]))[-20:]
        if opposing_evidence:
            item.opposing_evidence = list(dict.fromkeys([
                *item.opposing_evidence,
                *[e for e in opposing_evidence if e in valid_evidence],
            ]))[-20:]
        if confidence is not None:
            item.confidence = max(0.0, min(float(confidence), 1.0))
        if action_id and action_id not in item.related_actions:
            item.related_actions.append(action_id)
            item.related_actions = item.related_actions[-30:]
        if next_validation is not None:
            item.next_validation = next_validation.strip()[:1000]
        item.updated_at = _now()
        self.record(
            "Orchestrator", "hypothesis_updated",
            hypothesis_id=item.id, status=item.status, confidence=item.confidence,
        )
        return item

    def begin_action(
        self,
        signature: str,
        tool: str,
        target: str,
        parameters: dict[str, Any],
        *,
        context: str = "",
        endpoint: str = "",
        method: str = "",
        payload: str = "",
        command: str = "",
        hypothesis_id: str = "",
        retry_count: int = 0,
        decision: str = "execute",
    ) -> ActionRecord:
        self.action_sequence += 1
        action = ActionRecord(
            id=f"x{self.action_sequence}", signature=signature, tool=tool,
            target=target, context=context[:1000], endpoint=endpoint[:1000],
            method=method[:40], parameters=_bounded_data(parameters),
            payload=payload[:2000], command=command[:4000],
            hypothesis_id=hypothesis_id, retry_count=retry_count, decision=decision,
        )
        self.action_history.append(action)
        self.action_history = self.action_history[-200:]
        if hypothesis_id:
            try:
                self.update_hypothesis(hypothesis_id, status="testing", action_id=action.id)
            except ValueError:
                action.hypothesis_id = ""
        self.record("system", "action_started", action_id=action.id, tool=tool, signature=signature)
        return action

    def finish_action(
        self,
        action: ActionRecord,
        *,
        status: str,
        result: str,
        result_valid: bool,
        failure_type: str = "",
        failure_reason: str = "",
        resolution: str = "",
    ) -> FailedPathRecord | None:
        action.status = status
        action.result_summary = result[:4000]
        action.result_valid = bool(result_valid)
        action.completed_at = _now()
        failed: FailedPathRecord | None = None
        if status == "failure":
            if failure_type not in _FAILURE_TYPES:
                failure_type = "method"
            self.failed_path_sequence += 1
            failed = FailedPathRecord(
                id=f"fp{self.failed_path_sequence}", action_id=action.id,
                action=action.context or action.command or action.endpoint or action.tool,
                tool=action.tool, context=action.context,
                parameters=_bounded_data(action.parameters), failure_type=failure_type,
                failure_reason=failure_reason[:1000], result=result[:4000],
                related_hypothesis=action.hypothesis_id,
                retry_count=action.retry_count, resolution=resolution or "fallback",
                signature=action.signature,
            )
            self.failed_paths.append(failed)
            self.failed_paths = self.failed_paths[-120:]
            if action.hypothesis_id and failure_type == "hypothesis_rejected":
                try:
                    self.update_hypothesis(
                        action.hypothesis_id, status="rejected",
                        confidence=0.0, action_id=action.id,
                    )
                except ValueError:
                    pass
            self.record(
                "system", "failed_path_added", failed_path_id=failed.id,
                failure_type=failure_type, resolution=failed.resolution,
            )
        self.record(
            "system", "action_finished", action_id=action.id,
            status=status, result_valid=result_valid,
        )
        return failed

    def execution_context(self, *, limit: int = 8) -> dict[str, Any]:
        """供决策 Prompt 使用的有界摘要，避免注入完整历史。"""
        active = [h for h in self.hypotheses if h.status not in {"rejected", "confirmed"}]
        return {
            "hypotheses": [asdict(h) for h in active[-limit:]],
            "failed_paths": [asdict(item) for item in self.failed_paths[-limit:]],
        }

    def context_layers(self, *, limit: int = 8) -> dict[str, Any]:
        """返回 Core/Working/Historical 三层有界上下文。

        Historical 只提供引用与计数；需要完整记录时由状态工具/持久化层查询，
        不在每轮 LLM 请求中重复注入。
        """
        active_hypotheses = [
            item for item in self.hypotheses
            if item.status not in {"rejected", "confirmed"}
        ][-limit:]
        current_plans = [
            item for item in self.plan_items
            if item.get("status") in {"pending", "in_progress"}
        ][:limit]
        recent_actions = self.action_history[-limit:]
        recent_evidence = self.evidence_records[-limit:]
        recent_failures = self.failed_paths[-limit:]
        terminal_hypotheses = [
            item for item in self.hypotheses
            if item.status in {"rejected", "confirmed"}
        ][-limit:]
        return {
            "core_state": {
                "task": self.goal,
                "target": self.target,
                "phase": self.phase.value,
                "authorized": self.authorized,
                "approval": self.exploitation_approved,
                "hypotheses": [
                    {
                        "id": item.id, "statement": item.statement[:800],
                        "status": item.status, "confidence": item.confidence,
                        "next_validation": item.next_validation[:500],
                    }
                    for item in active_hypotheses
                ],
                "facts": [
                    {
                        "id": item.id, "content": item.content[:800],
                        "confidence": item.confidence,
                        "evidence_ids": item.evidence_ids,
                    }
                    for item in self.facts[-limit:]
                ],
            },
            "working_context": {
                "knowledge_reference": {
                    "label": "仅供参考，不能作为已验证 Facts/Evidence",
                    "query": str(self.knowledge_context.get("query") or "")[:1200],
                    "reason": str(self.knowledge_context.get("reason") or "")[:500],
                    "phase": str(self.knowledge_context.get("phase") or ""),
                    "context": str(self.knowledge_context.get("context") or "")[:3600],
                    "sources": list(self.knowledge_context.get("sources") or [])[:4],
                } if self.knowledge_context.get("context") else {},
                "plan_items": _bounded_data(current_plans),
                "evidence": [
                    {
                        "id": item.id, "source": item.source, "kind": item.kind,
                        "summary": item.summary[:800], "artifact": item.artifact,
                    }
                    for item in recent_evidence
                ],
                "recent_actions": [
                    {
                        "id": item.id, "tool": item.tool, "status": item.status,
                        "context": item.context[:400],
                        "result": item.result_summary[:600],
                    }
                    for item in recent_actions
                ],
                "recent_failed_paths": [
                    {
                        "id": item.id, "tool": item.tool,
                        "failure_type": item.failure_type,
                        "reason": item.failure_reason[:500],
                        "resolution": item.resolution,
                        "hypothesis": item.related_hypothesis,
                    }
                    for item in recent_failures
                ],
            },
            "historical_context": {
                "counts": {
                    "facts": len(self.facts), "evidence": len(self.evidence_records),
                    "actions": len(self.action_history),
                    "failed_paths": len(self.failed_paths),
                    "hypotheses": len(self.hypotheses),
                },
                "terminal_hypotheses": [
                    {"id": item.id, "status": item.status}
                    for item in terminal_hypotheses
                ],
                "agent_context_refs": dict(self.agent_context_refs),
            },
        }

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phase"] = self.phase.value
        return data


# MissionStore 持久化 schema 版本。旧文件缺字段时由 load() 自动迁移，
# 不回写（保持旧任务只读兼容）。
SCHEMA_VERSION = 8

# v1: 初始字段（target/goal/phase/plan/findings/attack_chain/flag/...）
# v2: v0.2.0 新增 target_spec/category_decision/category_history/
#     authorization_evidence/exploitation_approved/approved_attack_plan/
#     authorized_scope/plan_items/nss_submit
# v3: v0.3.0 Workspace v2 新增 workspace_id/checkpoint_seq/resume_status/
#     active_plan_item/pending_action/last_action_fingerprint/
#     retry_counters/agent_context_refs
# v4: v0.4.0 最小优化闭环新增 facts/evidence_records/attempts/
#     complexity（历史 action_budget/tool_budget 字段加载时丢弃）
# v5: 第二批执行闭环新增 hypotheses/action_history/failed_paths 及序列号
# v6: RAG 有界 Knowledge Context、查询指纹与共享缓存状态
# v7: 人工利用审批改为可恢复的多态状态，不再以 false 代表所有未批准情况
# v8: 任务模式、声明/有效范围及独立范围审批状态


class MissionStoreCorruptedError(OSError):
    """任务状态 JSON 损坏（解析失败 / 缺必填字段 / 类型错误）。"""

    def __init__(self, path: str | Path, reason: str) -> None:
        super().__init__(f"任务状态文件损坏: {path} — {reason}")
        self.path = str(path)
        self.reason = reason


class MissionStore:
    """使用原子替换持久化当前任务状态。"""

    def __init__(self, path: str | Path = ".TaskMemory/current_mission.json") -> None:
        self.path = Path(path)
        self._checkpoint_path: Path | None = None

    def bind_checkpoint_path(self, path: str | Path) -> None:
        """绑定工作区内的 checkpoint.json 目标路径（由调用方设置）。"""
        self._checkpoint_path = Path(path)

    @classmethod
    def for_session(cls, session_id: str, base_dir: str | Path = ".TaskMemory/sessions") -> "MissionStore":
        """为指定会话创建独立的持久化存储路径。"""
        path = Path(base_dir) / f"{session_id}.json"
        return cls(path)

    def save(self, state: MissionState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                data = state.to_dict()
                data["schema_version"] = SCHEMA_VERSION
                json.dump(
                    data, handle, ensure_ascii=False, separators=(",", ":"),
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def load(self) -> MissionState | None:
        """读取并迁移任务状态；文件不存在返回 None，损坏抛异常。

        Schema 迁移规则：旧文件缺失的字段用当前默认值补齐（不回写，
        保持旧任务只读兼容）。损坏检测覆盖 JSON 解析失败、非 dict 根、
        缺必填字段（target/goal/authorized）与 phase 类型错误。
        """
        if not self.path.is_file():
            return None
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise MissionStoreCorruptedError(self.path, f"读取失败: {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MissionStoreCorruptedError(self.path, f"JSON 解析失败: {exc}") from exc
        if not isinstance(data, dict):
            raise MissionStoreCorruptedError(self.path, "根节点不是 JSON 对象")

        # ── 必填字段校验 ──
        for required in ("target", "goal", "authorized"):
            if required not in data:
                raise MissionStoreCorruptedError(self.path, f"缺少必填字段 {required!r}")

        # ── phase 校验（容忍旧值/非法值） ──
        phase_value = data.get("phase", Phase.PLANNING.value)
        try:
            data["phase"] = Phase(phase_value)
        except ValueError:
            raise MissionStoreCorruptedError(
                self.path,
                f"非法 phase 值: {phase_value!r}",
            ) from None

        # ── schema 迁移：缺失字段用默认值补齐 ──
        defaults = MissionState(
            target=data["target"],
            goal=data["goal"],
            authorized=data["authorized"],
        ).to_dict()
        defaults.pop("schema_version", None)
        data.pop("schema_version", None)
        merged = {**defaults, **data}
        if "exploitation_approval_status" not in data:
            merged["exploitation_approval_status"] = infer_exploitation_approval_status(data)
        # events 恢复为 AuditEvent 对象（dict 形式的事件转为带哈希的对象）
        merged["events"] = [
            ev if isinstance(ev, AuditEvent) else AuditEvent(**ev)
            for ev in merged.get("events") or []
        ]
        merged["facts"] = [
            item if isinstance(item, FactRecord) else FactRecord(**item)
            for item in merged.get("facts") or []
        ]
        merged["evidence_records"] = [
            item if isinstance(item, EvidenceRecord) else EvidenceRecord(**item)
            for item in merged.get("evidence_records") or []
        ]
        merged["attempts"] = [
            item if isinstance(item, AttemptRecord) else AttemptRecord(**item)
            for item in merged.get("attempts") or []
        ]
        merged["hypotheses"] = [
            item if isinstance(item, HypothesisRecord) else HypothesisRecord(**item)
            for item in merged.get("hypotheses") or []
        ]
        merged["action_history"] = [
            item if isinstance(item, ActionRecord) else ActionRecord(**item)
            for item in merged.get("action_history") or []
        ]
        merged["failed_paths"] = [
            item if isinstance(item, FailedPathRecord) else FailedPathRecord(**item)
            for item in merged.get("failed_paths") or []
        ]
        # 防御早期 v5 快照缺少/丢失序列号，避免裁剪后生成重复 ID。
        def _max_numeric_id(items: list[Any], prefix: str) -> int:
            values = []
            for item in items:
                value = str(getattr(item, "id", ""))
                if value.startswith(prefix) and value[len(prefix):].isdigit():
                    values.append(int(value[len(prefix):]))
            return max(values, default=0)

        merged["hypothesis_sequence"] = max(
            int(merged.get("hypothesis_sequence") or 0),
            _max_numeric_id(merged["hypotheses"], "h"),
        )
        merged["action_sequence"] = max(
            int(merged.get("action_sequence") or 0),
            _max_numeric_id(merged["action_history"], "x"),
        )
        merged["failed_path_sequence"] = max(
            int(merged.get("failed_path_sequence") or 0),
            _max_numeric_id(merged["failed_paths"], "fp"),
        )
        # v4/v5 历史任务可能带有预算字段。预算机制已取消；加载时显式
        # 丢弃，避免旧的耗尽状态影响恢复，也保持旧快照可读。
        merged.pop("action_budget", None)
        merged.pop("tool_budget", None)

        try:
            return MissionState(**merged)
        except TypeError as exc:
            raise MissionStoreCorruptedError(self.path, f"字段类型不匹配: {exc}") from exc


    def checkpoint(
        self,
        state: MissionState,
        reason: str,
        checkpoint_path: str | Path | None = None,
    ) -> Path:
        """写安全检查点：原子复制权威状态到工作区 mission/checkpoint.json。

        崩溃恢复以最近一次 checkpoint 为准（终态不重放；不确定动作需人工
        确认）。返回写入的 checkpoint 路径。
        """
        state.checkpoint_seq += 1
        if state.resume_status == "fresh":
            state.resume_status = "running"
        state.record("system", "checkpoint", seq=state.checkpoint_seq, reason=reason)
        self.save(state)

        target = Path(checkpoint_path) if checkpoint_path is not None else None
        if target is None and self._checkpoint_path is not None:
            target = self._checkpoint_path
        if target is None:
            target = self.path.with_suffix(".checkpoint.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                data = state.to_dict()
                data["schema_version"] = SCHEMA_VERSION
                json.dump(
                    data, handle, ensure_ascii=False, separators=(",", ":"),
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return target


_EXPLOITATION_APPROVAL_STATUSES = {
    "not_requested", "pending", "approved", "denied", "recon_requested",
    "unavailable", "cancelled", "legacy_unknown",
}


def infer_exploitation_approval_status(
    data: dict[str, Any],
    *,
    pending: bool = False,
    active: bool | None = None,
) -> str:
    """从新字段或旧审计记录推导审批状态，供迁移和 SQLite 投影复用。"""
    explicit = str(data.get("exploitation_approval_status") or "").strip().lower()
    if data.get("exploitation_approved") is True:
        return "approved"
    if explicit in _EXPLOITATION_APPROVAL_STATUSES:
        if explicit == "pending" and active is False:
            return "cancelled"
        return explicit
    if pending and active is not False:
        return "pending"
    for event in reversed(data.get("events") or []):
        if isinstance(event, AuditEvent):
            action, details = event.action, event.details
        elif isinstance(event, dict):
            action = str(event.get("action") or "")
            details = event.get("details") or {}
        else:
            continue
        if action == "exploitation_approval_unavailable":
            return "unavailable"
        if action != "exploitation_approval" or not isinstance(details, dict):
            continue
        if details.get("approved") is True:
            return "approved"
        decision = str(details.get("decision") or "").strip()
        return "recon_requested" if "补充侦察" in decision else "denied"
    return "not_requested"
