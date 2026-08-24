"""Workspace 服务测试：目录隔离、blob 隔离、TTL、删除语义。

覆盖计划验收项：
- 隔离测试：同一用户两个会话、不同用户同一目标均得到不同物理目录，
  不能通过 Workspace 文件工具访问彼此产物。
- 删除测试：删除只影响所属 Workspace；共享 blob 保留。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.workspace_service import WorkspaceService


def _service() -> WorkspaceService:
    return WorkspaceService(Path(tempfile.mkdtemp(prefix="lingshu-ws-test-")))


class WorkspaceIdTest(unittest.TestCase):
    def test_user_session_id_is_deterministic(self) -> None:
        svc = _service()
        self.assertEqual(svc.workspace_id(7, "abc123"), "u7-abc123")
        self.assertEqual(svc.workspace_id(7, "abc123"), "u7-abc123")

    def test_cli_session_uses_cli_namespace(self) -> None:
        svc = _service()
        self.assertEqual(svc.workspace_id(None, "abc123"), "cli-abc123")

    def test_same_session_same_user_shares_physical_dir(self) -> None:
        svc = _service()
        self.assertEqual(
            svc.workspace_dir(7, "abc123"),
            svc.root / "sessions" / "u7" / "abc123",
        )
        self.assertEqual(
            svc.workspace_dir(None, "abc123"),
            svc.root / "sessions" / "cli" / "abc123",
        )

    def test_same_user_two_sessions_get_different_dirs(self) -> None:
        svc = _service()
        self.assertNotEqual(
            svc.workspace_dir(7, "session-a"),
            svc.workspace_dir(7, "session-b"),
        )

    def test_different_users_same_session_get_different_dirs(self) -> None:
        svc = _service()
        self.assertNotEqual(
            svc.workspace_dir(1, "abc123"),
            svc.workspace_dir(2, "abc123"),
        )


class WorkspaceLifecycleTest(unittest.IsolatedAsyncioTestCase):
    async def test_local_workspace_uses_deterministic_service_id(self) -> None:
        svc = _service()
        try:
            ws = await svc.get(12, "stable-session")
            self.assertEqual(ws.workspace_id, "u12-stable-session")
        finally:
            await svc.close_all()

    async def test_get_initializes_and_caches(self) -> None:
        svc = _service()
        ws1 = await svc.get(7, "sess-1")
        ws2 = await svc.get(7, "sess-1")
        self.assertIs(ws1, ws2)  # 缓存命中返回同一实例
        workdir = svc.workspace_dir(7, "sess-1")
        self.assertTrue(workdir.is_dir())
        for sub in ("input", "artifacts", "reports", "mission"):
            self.assertTrue((workdir / sub).is_dir(), f"缺少业务目录 {sub}")
        await svc.close_all()

    async def test_offload_writes_into_session_dir(self) -> None:
        from agentscope.message import AssistantMsg

        svc = _service()
        ws = await svc.get(3, "sess-1")
        try:
            await ws.offload_context(
                "mission-1-recon",
                [AssistantMsg(name="recon", content="探测结果")],
            )
            jsonl = (
                svc.workspace_dir(3, "sess-1")
                / "sessions" / "mission-1-recon" / "context.jsonl"
            )
            self.assertTrue(jsonl.is_file())
        finally:
            await svc.close_all()

    async def test_close_idle_keeps_disk_data(self) -> None:
        from agentscope.message import AssistantMsg

        svc = WorkspaceService(
            Path(tempfile.mkdtemp(prefix="lingshu-ws-ttl-")),
            idle_ttl_seconds=0.0,
        )
        ws = await svc.get(3, "sess-ttl")
        await ws.offload_context("probe", [AssistantMsg(name="p", content="x")])
        workdir = svc.workspace_dir(3, "sess-ttl")
        jsonl = workdir / "sessions" / "probe" / "context.jsonl"
        self.assertTrue(jsonl.is_file())

        closed = await svc.close_idle()
        self.assertEqual(closed, 1)  # TTL=0 → 立即过期并关闭
        self.assertTrue(jsonl.is_file(), "TTL close 不得删除磁盘文件")
        self.assertEqual(len(svc._cache), 0)
        await svc.close_all()


class BlobStoreTest(unittest.IsolatedAsyncioTestCase):
    async def test_put_blob_is_content_addressed(self) -> None:
        svc = _service()
        d1 = svc.put_blob(b"hello world")
        d2 = svc.put_blob(b"hello world")
        self.assertEqual(d1, d2)
        self.assertTrue(svc.blob_path(d1).is_file())
        await svc.close_all()

    async def test_link_input_isolates_writes(self) -> None:
        svc = _service()
        digest = svc.put_blob(b"attachment-bytes")
        target_a = svc.link_input(1, "sess-a", digest, "task.zip")
        target_b = svc.link_input(2, "sess-b", digest, "task.zip")
        # 不同会话得到不同物理文件
        self.assertNotEqual(target_a, target_b)
        self.assertTrue(target_a.is_file())
        self.assertTrue(target_b.is_file())
        # 会话 A 的写入不影响会话 B（隔离写）
        target_a.write_bytes(b"modified-in-a")
        self.assertEqual(target_b.read_bytes(), b"attachment-bytes")
        # blob 本身不受影响
        self.assertEqual(svc.blob_path(digest).read_bytes(), b"attachment-bytes")
        await svc.close_all()

    async def test_link_input_strips_path_components(self) -> None:
        svc = _service()
        digest = svc.put_blob(b"data")
        target = svc.link_input(1, "s", digest, "../../evil.sh")
        self.assertEqual(target.name, f"{digest[:12]}_evil.sh")
        self.assertTrue(target.is_file())
        await svc.close_all()

    async def test_remove_blob_respects_reference(self) -> None:
        svc = _service()
        digest = svc.put_blob(b"shared")
        svc.remove_blob_if_unreferenced(digest, referenced=True)
        self.assertTrue(svc.blob_path(digest).is_file(), "有引用不得删除")
        svc.remove_blob_if_unreferenced(digest, referenced=False)
        self.assertFalse(svc.blob_path(digest).exists(), "无引用应删除")
        await svc.close_all()


class DeleteSemanticsTest(unittest.IsolatedAsyncioTestCase):
    async def test_delete_moves_only_own_workspace_to_trash(self) -> None:
        svc = _service()
        await svc.get(7, "sess-keep")
        await svc.get(7, "sess-del")

        trash_path = await svc.delete(7, "sess-del")
        # 原目录已不在，trash 中有原子移动后的副本
        self.assertFalse(svc.workspace_dir(7, "sess-del").exists())
        self.assertTrue(trash_path.is_dir())
        self.assertTrue(trash_path.parent == svc.root / "trash")
        # 其他会话不受影响
        self.assertTrue(svc.workspace_dir(7, "sess-keep").exists())
        # 缓存条目已移除
        self.assertNotIn("u7-sess-del", svc._cache)
        await svc.close_all()

    async def test_delete_unknown_workspace_raises(self) -> None:
        svc = _service()
        with self.assertRaises(FileNotFoundError):
            await svc.delete(7, "no-such-session")


if __name__ == "__main__":
    unittest.main()
