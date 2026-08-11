"""当前任务的结构化状态、持久化与审计日志。"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


class Phase(str, Enum):
    PLANNING = "planning"
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    COMPLETED = "completed"
    FAILED = "failed"


_ALLOWED_TRANSITIONS = {
    Phase.PLANNING: {Phase.RECON, Phase.FAILED},
    Phase.RECON: {Phase.RECON, Phase.ANALYSIS, Phase.FAILED},
    Phase.ANALYSIS: {Phase.RECON, Phase.ANALYSIS, Phase.EXPLOITATION, Phase.FAILED},
    Phase.EXPLOITATION: {
        Phase.RECON,
        Phase.ANALYSIS,
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.COMPLETED,
        Phase.FAILED,
    },
    Phase.POST_EXPLOITATION: {
        Phase.POST_EXPLOITATION,
        Phase.COMPLETED,
        Phase.FAILED,
    },
    Phase.COMPLETED: set(),
    Phase.FAILED: set(),
}


@dataclass
class AuditEvent:
    timestamp: str
    actor: str
    action: str
    phase: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class MissionState:
    target: str
    goal: str
    authorized: bool
    session_id: str = ""
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

    # 动态授权范围快照（ScopeRegistry.snapshot() 的输出），
    # 崩溃恢复时用于重建 ScopeRegistry
    authorized_scope: dict[str, Any] = field(default_factory=dict)

    # 作战计划清单：Brain 经 AddPlan 登记（笼统条目），
    # Orchestrator 经 AddPlan/UpdatePlan/DeletePlan/ListPlan 维护（Tools/Plan.py）
    # 每项: {id, content, phase, status, evidence, origin}
    #   status: pending | in_progress | completed | failed | skipped
    #   origin: brain | orchestrator
    plan_items: list[dict[str, Any]] = field(default_factory=list)

    # NSSCTF Agent Arena 提交结果（由 Orchestrator 的 submit_nss_flag 工具写入）：
    # {attempt_id, flag, correct, remaining_wrong_attempts}
    nss_submit: dict[str, Any] | None = None

    def record(self, actor: str, action: str, **details: Any) -> None:
        self.updated_at = _now()
        self.events.append(
            AuditEvent(
                timestamp=self.updated_at,
                actor=actor,
                action=action,
                phase=self.phase.value,
                details=details,
            ),
        )

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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phase"] = self.phase.value
        return data


class MissionStore:
    """使用原子替换持久化当前任务状态。"""

    def __init__(self, path: str | Path = ".TaskMemory/current_mission.json") -> None:
        self.path = Path(path)

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
                json.dump(state.to_dict(), handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
