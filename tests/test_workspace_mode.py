"""阶段 5 测试：LINGSHU_WORKSPACE_MODE=local 默认，legacy 保留旧行为。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import RuntimeConfig


class WorkspaceModeConfigTest(unittest.TestCase):
    def test_default_is_local(self) -> None:
        with patch.dict("os.environ", {}, clear=False):
            # 移除可能存在的环境变量
            saved = RuntimeConfig
            import os

            old = os.environ.pop("LINGSHU_WORKSPACE_MODE", None)
            try:
                cfg = RuntimeConfig.from_env()
                self.assertEqual(cfg.workspace_mode, "local")
            finally:
                if old is not None:
                    os.environ["LINGSHU_WORKSPACE_MODE"] = old

    def test_explicit_legacy(self) -> None:
        with patch.dict("os.environ", {"LINGSHU_WORKSPACE_MODE": "legacy"}, clear=False):
            cfg = RuntimeConfig.from_env()
            self.assertEqual(cfg.workspace_mode, "legacy")

    def test_unknown_value_falls_back_to_local(self) -> None:
        with patch.dict("os.environ", {"LINGSHU_WORKSPACE_MODE": "bogus"}, clear=False):
            cfg = RuntimeConfig.from_env()
            self.assertEqual(cfg.workspace_mode, "local")


class LegacyModeNoWorkspaceTest(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_mode_skips_workspace_creation(self) -> None:
        """legacy 模式下 run_mission 不调用 workspace get（mock 模型抛错前验证）。"""
        import main as main_module
        from TaskState import MissionState, MissionStore, Phase

        base = Path(tempfile.mkdtemp(prefix="lingshu-legacy-"))
        store = MissionStore(base / "mission.json")
        mission = MissionState(target="127.0.0.1", goal="g", authorized=True, session_id="legacy-sess")
        store.save(mission)

        calls: list[str] = []

        async def fake_get(*args, **kwargs):
            calls.append("get")
            raise AssertionError("legacy 模式不应创建 Workspace")

        with patch.object(main_module, "get_workspace_service") as mock_svc, patch(
            "main.MissionStore.for_session", return_value=store,
        ), patch("main.create_model", side_effect=RuntimeError("mock 模型")), patch(
            "main.get_rag_service",
        ) as mock_rag, patch.dict("os.environ", {"LINGSHU_WORKSPACE_MODE": "legacy"}):
            mock_svc.return_value.get = fake_get
            mock_rag.return_value.start = _noop
            mock_rag.return_value.middleware.return_value = None
            try:
                await main_module.run_mission(
                    target="127.0.0.1", goal="g",
                    session_id="legacy-sess", resume=True,
                )
            except RuntimeError as exc:
                self.assertEqual(str(exc), "mock 模型")
        self.assertEqual(calls, [], "legacy 模式不得创建 Workspace")

    async def test_local_mode_creates_workspace(self) -> None:
        import main as main_module
        from TaskState import MissionState, MissionStore

        base = Path(tempfile.mkdtemp(prefix="lingshu-local-"))
        store = MissionStore(base / "mission.json")
        mission = MissionState(target="127.0.0.1", goal="g", authorized=True, session_id="local-sess")
        store.save(mission)

        created: list[str] = []

        async def fake_get(user_id, session_id, **kwargs):
            created.append(session_id)
            from agentscope.workspace import LocalWorkspace

            ws = LocalWorkspace(workdir=str(base / "ws"))
            await ws.initialize()
            return ws

        async def fake_close_one(*args, **kwargs):
            return None

        with patch.object(main_module, "get_workspace_service") as mock_svc, patch(
            "main.MissionStore.for_session", return_value=store,
        ), patch("main.create_model", side_effect=RuntimeError("mock 模型")), patch(
            "main.get_rag_service",
        ) as mock_rag, patch.dict("os.environ", {"LINGSHU_WORKSPACE_MODE": "local"}):
            svc = mock_svc.return_value
            svc.get = fake_get
            svc.close_one = fake_close_one
            svc.workspace_id = lambda u, s: f"u{u}-{s}"
            svc.workspace_dir = lambda u, s: base / s
            svc.checkpoint_path = lambda u, s: base / s / "mission" / "checkpoint.json"
            mock_rag.return_value.start = _noop
            mock_rag.return_value.middleware.return_value = None
            try:
                await main_module.run_mission(
                    target="127.0.0.1", goal="g",
                    session_id="local-sess", resume=True,
                )
            except RuntimeError as exc:
                self.assertEqual(str(exc), "mock 模型")
        self.assertEqual(created, ["local-sess"], "local 模式应创建会话 Workspace")


async def _noop() -> None:
    return None


if __name__ == "__main__":
    unittest.main()
