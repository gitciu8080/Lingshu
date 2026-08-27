"""P0-B 任务确定性收敛回归测试（c5ca9b2b 复盘）。

覆盖 MissionState.finalize_as_failed：
- 计划项 in_progress→failed、pending→skipped，completed 不动；
- success 置 False；summary 为空时写入原因，非空时保留；
- 审计链记录 mission_force_failed（含未决假设数）与 phase_transition→FAILED；
- 已是终态时不重复迁移；假设记录保持原状。
"""

from __future__ import annotations

import unittest

from core.TaskState import HypothesisRecord, MissionState, Phase


def _mission() -> MissionState:
    return MissionState(target="127.0.0.1", goal="获取 Flag", authorized=True)


class FinalizeAsFailedTest(unittest.TestCase):
    def test_plan_items_finalized_and_phase_converged(self) -> None:
        m = _mission()
        m.plan_items = [
            {"id": "p1", "status": "completed"},
            {"id": "p2", "status": "in_progress"},
            {"id": "p3", "status": "pending"},
        ]
        m.hypotheses = [HypothesisRecord(id="h1", statement="s", status="testing")]
        m.transition(Phase.RECON, "正常推进")
        m.transition(Phase.ANALYSIS, "分析中")

        m.finalize_as_failed("停止且无显式收尾")

        statuses = {item["id"]: item["status"] for item in m.plan_items}
        self.assertEqual(statuses, {"p1": "completed", "p2": "failed", "p3": "skipped"})
        self.assertIs(m.success, False)
        self.assertEqual(m.phase, Phase.FAILED)
        self.assertIn("停止且无显式收尾", m.summary)
        actions = [e.action for e in m.events]
        self.assertIn("mission_force_failed", actions)
        self.assertIn("phase_transition", actions)

    def test_existing_summary_preserved(self) -> None:
        m = _mission()
        m.summary = "专家已有结论文本"
        m.finalize_as_failed("强制失败原因")
        self.assertEqual(m.summary, "专家已有结论文本")
        # 原因仍保留在审计事件中
        event = next(e for e in m.events if e.action == "mission_force_failed")
        self.assertEqual(event.details["reason"], "强制失败原因")

    def test_no_double_transition_from_terminal(self) -> None:
        m = _mission()
        m.transition(Phase.FAILED, "已经失败")
        before_events = len(m.events)
        m.finalize_as_failed("重复调用")
        self.assertEqual(m.phase, Phase.FAILED)
        transitions = [
            e for e in m.events[before_events:] if e.action == "phase_transition"
        ]
        self.assertEqual(transitions, [])

    def test_unresolved_hypotheses_counted_not_mutated(self) -> None:
        m = _mission()
        m.hypotheses = [
            HypothesisRecord(id="h1", statement="a", status="testing"),
            HypothesisRecord(id="h2", statement="b", status="confirmed"),
            HypothesisRecord(id="h3", statement="c", status="proposed"),
        ]
        m.finalize_as_failed("停摆")
        statuses = {h.id: h.status for h in m.hypotheses}
        self.assertEqual(
            statuses, {"h1": "testing", "h2": "confirmed", "h3": "proposed"},
        )
        event = next(e for e in m.events if e.action == "mission_force_failed")
        self.assertEqual(event.details["unresolved_hypotheses"], 2)


if __name__ == "__main__":
    unittest.main()
