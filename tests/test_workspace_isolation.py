"""阶段 2 集成测试：跨会话产物隔离 + 归档输入隔离 + 删除后产物不可见。

覆盖计划验收项：
- 隔离测试：同一用户两个会话、不同用户同一目标均得到不同物理目录，
  不能通过 Workspace 文件工具访问彼此产物。
- 归档测试：同一附件创建两个会话，输入一致但修改和分析产物互不影响。
- 删除测试：删除会话后 artifacts 接口不再返回产物。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from workspace_service import WorkspaceService
from api_workspace import list_artifacts, resolve_artifact_path, workspace_summary
from Tools.workspace_tools import create_workspace_tools


def _text(result) -> str:
    blocks = getattr(result, "content", None)
    if isinstance(blocks, list):
        return "\n".join(b.text for b in blocks if hasattr(b, "text"))
    return str(result)


class CrossSessionIsolationTest(unittest.IsolatedAsyncioTestCase):
    async def _session(self, svc, user_id, session_id):
        ws = await svc.get(user_id, session_id)
        tools = {t.name: t for t in create_workspace_tools(svc.workspace_dir(user_id, session_id))}
        return ws, tools

    async def test_workspace_tools_cannot_see_other_session_artifacts(self) -> None:
        svc = WorkspaceService(Path(tempfile.mkdtemp(prefix="lingshu-iso-")), mode="local")
        try:
            _, tools_a = await self._session(svc, 1, "sess-a")
            await self._session(svc, 1, "sess-b")

            # 会话 A 写一个产物，会话 B 写另一个
            artifact_a = svc.artifacts_dir(1, "sess-a") / "recon" / "tool-0001"
            artifact_a.mkdir(parents=True)
            (artifact_a / "stdout.txt").write_text("session-a-secret", encoding="utf-8")
            artifact_b = svc.artifacts_dir(1, "sess-b") / "recon" / "tool-0001"
            artifact_b.mkdir(parents=True)
            (artifact_b / "stdout.txt").write_text("session-b-secret", encoding="utf-8")

            # 会话 A 的工具看不到会话 B 的产物
            glob_result = _text(await tools_a["workspace_glob"](pattern="**/*.txt"))
            self.assertIn("artifacts/recon/tool-0001/stdout.txt", glob_result)
            self.assertNotIn("session-b-secret", glob_result)
            self.assertIn("session-a-secret", _text(await tools_a["workspace_read"](path="artifacts/recon/tool-0001/stdout.txt")))
            with self.assertRaises(PermissionError):
                await tools_a["workspace_read"](path="../u1/sess-b/artifacts/recon/tool-0001/stdout.txt")
        finally:
            await svc.close_all()

    async def test_same_attachment_inputs_are_isolated(self) -> None:
        """同一附件 blob 链接到两个会话：输入内容一致但修改互不影响。"""
        svc = WorkspaceService(Path(tempfile.mkdtemp(prefix="lingshu-arch-")), mode="local")
        try:
            digest = svc.put_blob(b"attachment-content")
            in_a = svc.link_input(1, "sess-a", digest, "task.zip")
            in_b = svc.link_input(2, "sess-b", digest, "task.zip")
            self.assertEqual(in_a.read_bytes(), in_b.read_bytes())

            # 会话 A 修改自己的 input（分析过程），B 与 blob 不受影响
            in_a.write_bytes(b"modified-by-a")
            self.assertEqual(in_b.read_bytes(), b"attachment-content")
            self.assertEqual(svc.blob_path(digest).read_bytes(), b"attachment-content")

            # 会话 A 的 workspace 摘要只统计自身产物
            await svc.get(1, "sess-a")
            summary_a = workspace_summary(svc, 1, "sess-a")
            self.assertIsNotNone(summary_a)
            self.assertEqual(summary_a["workspace_id"], "u1-sess-a")
        finally:
            await svc.close_all()


class DeleteVisibilityTest(unittest.IsolatedAsyncioTestCase):
    async def test_artifacts_gone_after_delete(self) -> None:
        svc = WorkspaceService(Path(tempfile.mkdtemp(prefix="lingshu-del-")), mode="local")
        try:
            await svc.get(1, "sess-del")
            art = svc.artifacts_dir(1, "sess-del") / "recon" / "tool-0001"
            art.mkdir(parents=True)
            (art / "stdout.txt").write_text("x" * 100, encoding="utf-8")

            before = list_artifacts(svc, 1, "sess-del")
            self.assertGreater(len(before), 0)

            await svc.delete(1, "sess-del")

            after = list_artifacts(svc, 1, "sess-del")
            self.assertEqual(after, [])
            self.assertIsNone(workspace_summary(svc, 1, "sess-del"))
            with self.assertRaises(FileNotFoundError):
                resolve_artifact_path(svc, 1, "sess-del", "artifacts/recon/tool-0001/stdout.txt")
        finally:
            await svc.close_all()

    async def test_artifact_path_escape_rejected(self) -> None:
        svc = WorkspaceService(Path(tempfile.mkdtemp(prefix="lingshu-esc-")), mode="local")
        try:
            await svc.get(1, "sess-esc")
            with self.assertRaises(PermissionError):
                resolve_artifact_path(svc, 1, "sess-esc", "../../../etc/passwd")
        finally:
            await svc.close_all()


if __name__ == "__main__":
    unittest.main()
