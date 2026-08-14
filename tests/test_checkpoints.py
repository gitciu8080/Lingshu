"""安全检查点测试：计划变更 / 派遣 / 审批 / 终态写 checkpoint.json。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from TaskState import MissionState, MissionStore, Phase
from Tools.Plan import create_add_plan_tool, create_update_plan_tool


def _fixture() -> tuple[MissionStore, MissionState, Path]:
    base = Path(tempfile.mkdtemp(prefix="lingshu-cp-"))
    store = MissionStore(base / "mission.json")
    cp = base / "workspace" / "mission" / "checkpoint.json"
    store.bind_checkpoint_path(cp)
    mission = MissionState(target="127.0.0.1", goal="g", authorized=True)
    return store, mission, cp


class PlanCheckpointTest(unittest.IsolatedAsyncioTestCase):
    async def test_add_plan_writes_checkpoint(self) -> None:
        store, mission, cp = _fixture()
        tool = create_add_plan_tool(mission, store, None)
        result = await tool(
            id=1, content="侦察端口", phase="recon",
        )
        self.assertIn("p1", str(result))
        self.assertTrue(cp.is_file(), "AddPlan 后必须写 checkpoint.json")
        data = json.loads(cp.read_text(encoding="utf-8"))
        self.assertGreaterEqual(data["checkpoint_seq"], 1)
        self.assertEqual(data["resume_status"], "running")
        self.assertEqual(len(data["plan_items"]), 1)
        # 权威 JSON 也更新
        self.assertTrue(store.path.is_file())

    async def test_update_plan_advances_checkpoint_seq(self) -> None:
        store, mission, cp = _fixture()
        add = create_add_plan_tool(mission, store, None)
        await add(id=1, content="侦察", phase="recon")
        seq_after_add = json.loads(cp.read_text(encoding="utf-8"))["checkpoint_seq"]

        update = create_update_plan_tool(mission, store, None)
        await update(id="p1", status="completed", evidence="nmap 结果")

        data = json.loads(cp.read_text(encoding="utf-8"))
        self.assertGreater(data["checkpoint_seq"], seq_after_add)
        self.assertEqual(data["plan_items"][0]["status"], "completed")
        self.assertEqual(data["plan_items"][0]["evidence"], "nmap 结果")


class OrchestratorCheckpointTest(unittest.IsolatedAsyncioTestCase):
    async def test_terminal_checkpoint_is_resumable_proof(self) -> None:
        """终态 checkpoint：resume 时能直接判定 terminal 不重放。"""
        store, mission, cp = _fixture()
        mission.transition(Phase.RECON, "开始")
        mission.transition(Phase.ANALYSIS, "分析")
        mission.transition(Phase.COMPLETED, "拿到 Flag")
        mission.success = True
        mission.flag = "flag{ok}"
        mission.resume_status = "terminal"
        store.checkpoint(mission, "mission_terminal")

        loaded = store.load()
        self.assertEqual(loaded.phase, Phase.COMPLETED)
        self.assertEqual(loaded.resume_status, "terminal")
        self.assertEqual(loaded.flag, "flag{ok}")
        # checkpoint.json 镜像一致
        data = json.loads(cp.read_text(encoding="utf-8"))
        self.assertEqual(data["phase"], "completed")
        self.assertEqual(data["resume_status"], "terminal")


if __name__ == "__main__":
    unittest.main()
