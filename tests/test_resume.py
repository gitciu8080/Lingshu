"""run_mission resume 语义测试（阶段 2 API 闸门部分）。

覆盖计划恢复规则：
- 终态任务不重复执行（直接返回，不创建模型/不进入主循环）。
- uncertain 存在不确定动作时禁止自动重放（抛 RuntimeError）。
- 无状态文件时拒绝恢复。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.TaskState import MissionState, MissionStore, Phase

SESSION_ID = "resume-test-session"


def _store() -> MissionStore:
    base = Path(tempfile.mkdtemp(prefix="lingshu-resume-"))
    return MissionStore.for_session(SESSION_ID, base_dir=base)


class ResumeTerminalTest(unittest.IsolatedAsyncioTestCase):
    async def test_terminal_mission_is_returned_without_replay(self) -> None:
        store = _store()
        mission = MissionState(
            target="127.0.0.1:8080",
            goal="获取 Flag",
            authorized=True,
            session_id=SESSION_ID,
        )
        mission.transition(Phase.RECON, "开始")
        mission.transition(Phase.ANALYSIS, "分析")
        mission.transition(Phase.COMPLETED, "拿到 Flag")
        mission.success = True
        mission.flag = "flag{ok}"
        mission.resume_status = "terminal"
        store.save(mission)

        from main import run_mission

        # 终态恢复：不创建模型、不进入主循环 → 无需 API key
        with patch("main.Path") as _mock_path, patch(
            "main.MissionStore.for_session", return_value=store,
        ):
            result = await run_mission(
                target="127.0.0.1:8080",
                goal="获取 Flag",
                session_id=SESSION_ID,
                resume=True,
            )
        self.assertEqual(result.phase, Phase.COMPLETED)
        self.assertEqual(result.flag, "flag{ok}")

    async def test_cancelled_mission_is_terminal(self) -> None:
        store = _store()
        mission = MissionState(
            target="127.0.0.1", goal="g", authorized=True, session_id=SESSION_ID,
        )
        mission.transition(Phase.CANCELLED, "用户取消")
        mission.resume_status = "terminal"
        store.save(mission)

        from main import run_mission

        with patch("main.MissionStore.for_session", return_value=store):
            result = await run_mission(
                target="127.0.0.1", goal="g", session_id=SESSION_ID, resume=True,
            )
        self.assertEqual(result.phase, Phase.CANCELLED)


class ResumeUncertainTest(unittest.IsolatedAsyncioTestCase):
    async def test_uncertain_refuses_auto_replay(self) -> None:
        store = _store()
        mission = MissionState(
            target="127.0.0.1", goal="g", authorized=True, session_id=SESSION_ID,
        )
        mission.resume_status = "uncertain"
        mission.pending_action = {
            "tool": "scoped_shell",
            "args": {"command": "rm something"},
        }
        store.save(mission)

        from main import run_mission

        with patch("main.MissionStore.for_session", return_value=store):
            with self.assertRaises(RuntimeError) as ctx:
                await run_mission(
                    target="127.0.0.1", goal="g",
                    session_id=SESSION_ID, resume=True,
                )
        self.assertIn("不确定", str(ctx.exception))

    async def test_missing_state_refuses_resume(self) -> None:
        store = _store()  # 未 save 任何状态
        from main import run_mission

        with patch("main.MissionStore.for_session", return_value=store):
            with self.assertRaises(RuntimeError):
                await run_mission(
                    target="127.0.0.1", goal="g",
                    session_id=SESSION_ID, resume=True,
                )


class ResumeRunningTest(unittest.IsolatedAsyncioTestCase):
    async def test_running_status_is_promoted(self) -> None:
        """非终态恢复：resume 检查通过后会进入主循环（用 mock 模型创建
        抛错来证明已越过恢复闸门，且错误不是恢复检查类错误）。"""
        store = _store()
        mission = MissionState(
            target="127.0.0.1", goal="g", authorized=True, session_id=SESSION_ID,
        )
        mission.resume_status = "resumable"
        mission.checkpoint_seq = 3
        mission.workspace_id = "u1-resume-test-session"
        store.save(mission)

        from main import run_mission

        with patch("main.MissionStore.for_session", return_value=store), patch(
            "main.create_model", side_effect=RuntimeError("mock 模型不可用"),
        ), patch("main.get_rag_service") as mock_rag:
            mock_rag.return_value.middleware.return_value = None
            mock_rag.return_value.start = _noop_async
            try:
                await run_mission(
                    target="127.0.0.1", goal="g",
                    session_id=SESSION_ID, resume=True,
                )
                self.fail("mock 模型创建应抛错")
            except RuntimeError as exc:
                # 错误必须来自主循环的模型创建，而非恢复闸门
                self.assertEqual(str(exc), "mock 模型不可用")


async def _noop_async() -> None:
    return None


if __name__ == "__main__":
    unittest.main()
