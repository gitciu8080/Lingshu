"""TaskState v0.3.0 扩展测试：CANCELLED 终态、新字段、load/迁移/损坏检测/checkpoint。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.TaskState import (
    MissionState,
    MissionStore,
    MissionStoreCorruptedError,
    Phase,
)


class CancelledTerminalTest(unittest.TestCase):
    def test_cancelled_is_terminal(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.transition(Phase.CANCELLED, "用户取消")
        self.assertEqual(mission.phase, Phase.CANCELLED)
        # 终态不可再迁移
        with self.assertRaises(ValueError):
            mission.transition(Phase.COMPLETED, "不能从取消恢复")

    def test_cancelled_reachable_from_any_active_phase(self) -> None:
        for phase in (
            Phase.PLANNING,
            Phase.RECON,
            Phase.ANALYSIS,
            Phase.EXPLOITATION,
            Phase.POST_EXPLOITATION,
        ):
            mission = MissionState(target="t", goal="g", authorized=True)
            mission.phase = phase
            mission.transition(Phase.CANCELLED, "取消")
            self.assertEqual(mission.phase, Phase.CANCELLED)


class MissionStateFieldsTest(unittest.TestCase):
    def test_v3_defaults(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        self.assertEqual(mission.workspace_id, "")
        self.assertEqual(mission.checkpoint_seq, 0)
        self.assertEqual(mission.resume_status, "fresh")
        self.assertIsNone(mission.active_plan_item)
        self.assertIsNone(mission.pending_action)
        self.assertEqual(mission.last_action_fingerprint, "")
        self.assertEqual(mission.retry_counters, {})
        self.assertEqual(mission.agent_context_refs, {})
        self.assertEqual(mission.scope_approval_status, "not_required")
        self.assertEqual(mission.declared_scope, {})

    def test_plan_status_interrupted_is_representable(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.plan_items.append(
            {"id": "p1", "content": "侦察", "phase": "recon",
             "status": "interrupted", "evidence": [], "origin": "brain"},
        )
        self.assertEqual(mission.plan_items[0]["status"], "interrupted")


class MissionStoreRoundTripTest(unittest.TestCase):
    def _store(self) -> tuple[MissionStore, Path]:
        path = Path(tempfile.mkdtemp(prefix="lingshu-store-")) / "mission.json"
        return MissionStore(path), path

    def test_save_then_load_roundtrip(self) -> None:
        store, _ = self._store()
        mission = MissionState(
            target="127.0.0.1:8080",
            goal="获取 Flag",
            authorized=True,
            session_id="abc",
        )
        mission.workspace_id = "u7-abc"
        mission.resume_status = "running"
        mission.checkpoint_seq = 3
        mission.record("Brain", "plan_drafted", items=2)
        store.save(mission)

        loaded = store.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.target, "127.0.0.1:8080")
        self.assertEqual(loaded.workspace_id, "u7-abc")
        self.assertEqual(loaded.resume_status, "running")
        self.assertEqual(loaded.checkpoint_seq, 3)
        self.assertEqual(loaded.phase, Phase.PLANNING)
        self.assertEqual(len(loaded.events), 1)

    def test_load_missing_file_returns_none(self) -> None:
        store, _ = self._store()
        self.assertIsNone(store.load())

    def test_load_migrates_legacy_v1_file(self) -> None:
        """v1 旧文件（无 v2/v3 字段）也能读，缺字段用默认值补齐。"""
        store, path = self._store()
        legacy = {
            "target": "example.invalid",
            "goal": "获取 Flag",
            "authorized": True,
            "phase": "recon",
            "plan": "旧计划",
            "findings": [],
            "attack_chain": [],
            "flag": None,
            "success": None,
            "summary": "",
            "created_at": "2026-01-01T00:00:00+08:00",
            "updated_at": "2026-01-01T00:00:00+08:00",
            "events": [],
            "session_id": "",
            "title": "",
        }
        path.write_text(json.dumps(legacy, ensure_ascii=False), encoding="utf-8")

        loaded = store.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.phase, Phase.RECON)
        self.assertEqual(loaded.workspace_id, "")  # v3 默认值
        self.assertEqual(loaded.resume_status, "fresh")
        self.assertEqual(loaded.scope_approval_status, "not_required")
        self.assertEqual(loaded.plan_items, [])  # v2 默认值


class MissionStoreCorruptionTest(unittest.TestCase):
    def _store(self, content: str) -> tuple[MissionStore, Path]:
        path = Path(tempfile.mkdtemp(prefix="lingshu-corrupt-")) / "mission.json"
        path.write_text(content, encoding="utf-8")
        return MissionStore(path), path

    def test_invalid_json_raises(self) -> None:
        store, _ = self._store("{ not json")
        with self.assertRaises(MissionStoreCorruptedError):
            store.load()

    def test_non_dict_root_raises(self) -> None:
        store, _ = self._store("[1, 2, 3]")
        with self.assertRaises(MissionStoreCorruptedError):
            store.load()

    def test_missing_required_field_raises(self) -> None:
        store, _ = self._store(json.dumps({"goal": "g", "authorized": True}))
        with self.assertRaises(MissionStoreCorruptedError) as ctx:
            store.load()
        self.assertIn("target", str(ctx.exception))

    def test_invalid_phase_raises(self) -> None:
        store, _ = self._store(
            json.dumps(
                {"target": "t", "goal": "g", "authorized": True,
                 "phase": "not-a-phase"},
            ),
        )
        with self.assertRaises(MissionStoreCorruptedError):
            store.load()


class CheckpointTest(unittest.TestCase):
    def test_checkpoint_increments_seq_and_writes_file(self) -> None:
        store, _ = MissionStore(
            Path(tempfile.mkdtemp(prefix="lingshu-cp-")) / "mission.json",
        ), None
        checkpoint_target = (
            Path(tempfile.mkdtemp(prefix="lingshu-cp-dst-")) / "checkpoint.json"
        )
        mission = MissionState(target="t", goal="g", authorized=True)

        target = store.checkpoint(mission, "侦察完成", checkpoint_target)

        self.assertTrue(target.is_file())
        self.assertEqual(mission.checkpoint_seq, 1)
        self.assertEqual(mission.resume_status, "running")
        data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(data["checkpoint_seq"], 1)
        self.assertEqual(data["resume_status"], "running")
        self.assertIn("schema_version", data)

    def test_checkpoint_keeps_terminal_status(self) -> None:
        store = MissionStore(Path(tempfile.mkdtemp()) / "mission.json")
        checkpoint_target = Path(tempfile.mkdtemp()) / "checkpoint.json"
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.transition(Phase.RECON, "开始侦察")
        mission.transition(Phase.ANALYSIS, "侦察完成")
        mission.transition(Phase.COMPLETED, "拿到 Flag")
        mission.resume_status = "terminal"

        store.checkpoint(mission, "终态", checkpoint_target)

        data = json.loads(checkpoint_target.read_text(encoding="utf-8"))
        self.assertEqual(data["resume_status"], "terminal")
        self.assertEqual(data["phase"], "completed")


if __name__ == "__main__":
    unittest.main()
