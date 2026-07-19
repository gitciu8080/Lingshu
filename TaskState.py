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

    def add_attack_step(self, objective: str, report: str) -> None:
        self.attack_chain.append(
            {"timestamp": _now(), "objective": objective, "report": report},
        )
        self.record("Orchestrator", "attack_step_added", objective=objective)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phase"] = self.phase.value
        return data


class MissionStore:
    """使用原子替换持久化当前任务状态。"""

    def __init__(self, path: str | Path = ".TaskMemory/current_mission.json") -> None:
        self.path = Path(path)

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
