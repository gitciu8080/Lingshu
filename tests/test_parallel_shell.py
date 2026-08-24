"""parallel_scoped_shell 测试：并行聚合、单条超时隔离、整体范围校验、manifest 审计。

覆盖 P0-A 验收项：
- 互不依赖的只读命令并行执行并合并为 <cmd-N> 分节结果；
- 单条命令超时只终止自身，不影响其余命令；
- 任一命令越界则整体拒绝，不启动任何子进程；
- manifest 记录 tool=parallel_scoped_shell 与 command_index 供审计；
- 空列表 / 超上限的安全降级。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.tooling import create_parallel_scoped_shell_tool


def _text(result) -> str:
    blocks = getattr(result, "content", None)
    if isinstance(blocks, list):
        return "\n".join(b.text for b in blocks if hasattr(b, "text"))
    return str(result)


class ParallelScopedShellTest(unittest.IsolatedAsyncioTestCase):
    async def _tool(self, artifact_root: Path, timeout: int = 30, **kwargs):
        return create_parallel_scoped_shell_tool(
            "127.0.0.1",
            cwd=str(artifact_root),
            timeout=timeout,
            role="recon",
            artifact_root=artifact_root,
            **kwargs,
        )

    async def test_parallel_aggregates_results(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-par-"))
        tool = await self._tool(root)
        result = _text(await tool(commands=["echo alpha", "echo beta"]))

        self.assertIn("<cmd-0", result)
        self.assertIn("<cmd-1", result)
        self.assertIn("alpha", result)
        self.assertIn("beta", result)
        self.assertIn("<returncode>0</returncode>", result)

    async def test_single_timeout_does_not_block_others(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-par-"))
        tool = await self._tool(root, timeout=5)
        result = _text(
            await tool(commands=["sleep 3", "echo quick"], per_command_timeout=1),
        )

        # 慢命令超时被终止（-1），快命令不受影响
        self.assertIn("<returncode>-1</returncode>", result)
        self.assertIn("quick", result)
        self.assertIn("<cmd-1", result)

    async def test_unauthorized_command_rejects_whole_batch(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-par-"))
        tool = await self._tool(root)
        with self.assertRaises(PermissionError):
            await tool(commands=["echo ok", "nmap -Pn unrelated.example"])

        # 整体拒绝：不应启动任何子进程（无 manifest 记录）
        manifest = root / "artifacts" / "manifest.jsonl"
        self.assertFalse(manifest.is_file())

    async def test_manifest_records_command_index(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-par-"))
        tool = await self._tool(root)
        await tool(commands=["echo one", "echo two"])

        manifest = root / "artifacts" / "manifest.jsonl"
        entries = [
            json.loads(line)
            for line in manifest.read_text(encoding="utf-8").strip().splitlines()
        ]
        self.assertEqual(len(entries), 2)
        self.assertTrue(
            all(entry["tool"] == "parallel_scoped_shell" for entry in entries),
        )
        self.assertEqual({entry["command_index"] for entry in entries}, {0, 1})
        self.assertEqual(
            {entry["command"] for entry in entries}, {"echo one", "echo two"},
        )

    async def test_empty_and_oversized_commands(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-par-"))
        tool = await self._tool(root, max_commands=8)

        empty = _text(await tool(commands=[]))
        self.assertIn("空命令列表", empty)

        oversized = _text(await tool(commands=[f"echo {i}" for i in range(9)]))
        self.assertTrue(oversized.startswith("[拒绝]"))
        self.assertIn("超过上限", oversized)
        # 超上限也应拒绝执行，不留 manifest
        self.assertFalse((root / "artifacts" / "manifest.jsonl").is_file())

    async def test_legacy_mode_no_disk_write(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-par-"))
        tool = create_parallel_scoped_shell_tool(
            "127.0.0.1", cwd=str(root), timeout=30,
        )
        result = _text(await tool(commands=["echo legacy-par"]))
        self.assertIn("legacy-par", result)
        self.assertFalse((root / "artifacts").exists())


if __name__ == "__main__":
    unittest.main()
