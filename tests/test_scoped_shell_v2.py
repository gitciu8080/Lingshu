"""scoped_shell v2 流式 artifacts 测试：完整输出落盘、manifest、超时语义。

覆盖计划验收项：
- 长输出测试：生成超过 100KB 输出，返回值只含摘要，磁盘文件内容与哈希完整。
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from Tools.tooling import create_scoped_shell_tool


def _text(result) -> str:
    blocks = getattr(result, "content", None)
    if isinstance(blocks, list):
        return "\n".join(b.text for b in blocks if hasattr(b, "text"))
    return str(result)


class ScopedShellArtifactTest(unittest.IsolatedAsyncioTestCase):
    async def _shell(self, artifact_root: Path, timeout: int = 30):
        return create_scoped_shell_tool(
            "127.0.0.1",
            cwd=str(artifact_root),
            timeout=timeout,
            role="recon",
            artifact_root=artifact_root,
        )

    async def test_long_output_streams_to_disk(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-shell-"))
        shell = await self._shell(root)
        # 生成 120KB 输出
        command = "python3 -c \"print('A' * 120000)\""
        result = _text(await shell(command=command))

        self.assertIn("<returncode>0</returncode>", result)
        # 返回值不携带完整 120KB，只含尾部 + 引用
        self.assertLess(len(result), 20000, "返回值不应内嵌完整大输出")
        self.assertIn("stdout_artifact", result)
        self.assertIn("bytes=120001", result)

        # 磁盘文件完整且哈希正确
        stdout_file = root / "artifacts" / "recon" / "tool-0001" / "stdout.txt"
        self.assertTrue(stdout_file.is_file())
        content = stdout_file.read_text(encoding="utf-8")
        self.assertEqual(len(content), 120001)  # 120000 + 换行
        self.assertEqual(
            hashlib.sha256(content.encode()).hexdigest(),
            hashlib.sha256(("A" * 120000 + "\n").encode()).hexdigest(),
        )

    async def test_manifest_records_entry(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-shell-"))
        shell = await self._shell(root)
        await shell(command="echo hello-lingshu")

        manifest = root / "artifacts" / "manifest.jsonl"
        self.assertTrue(manifest.is_file())
        lines = manifest.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["tool"], "scoped_shell")
        self.assertEqual(entry["role"], "recon")
        self.assertEqual(entry["returncode"], 0)
        self.assertEqual(entry["timed_out"], False)
        self.assertIn("sha256", entry["stdout"])
        self.assertEqual(entry["stdout"]["bytes"], len("hello-lingshu\n"))
        # 路径是相对引用，不暴露宿主绝对路径
        self.assertNotIn(str(root), entry["stdout"]["path"])

    async def test_timeout_kills_and_records(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-shell-"))
        shell = await self._shell(root, timeout=1)
        result = _text(await shell(command="sleep 10"))

        self.assertIn("<returncode>-1</returncode>", result)
        self.assertIn("已终止", result)
        manifest = root / "artifacts" / "manifest.jsonl"
        entry = json.loads(manifest.read_text(encoding="utf-8").strip().splitlines()[0])
        self.assertTrue(entry["timed_out"])
        self.assertEqual(entry["returncode"], -1)

    async def test_stderr_also_streamed(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-shell-"))
        shell = await self._shell(root)
        await shell(command="echo err-out >&2")

        stderr_file = root / "artifacts" / "recon" / "tool-0001" / "stderr.txt"
        self.assertTrue(stderr_file.is_file())
        self.assertIn("err-out", stderr_file.read_text(encoding="utf-8"))

    async def test_legacy_mode_still_works(self) -> None:
        """不传 artifact_root 时保持旧行为（内存截断，无磁盘写入）。"""
        root = Path(tempfile.mkdtemp(prefix="lingshu-shell-"))
        shell = create_scoped_shell_tool("127.0.0.1", cwd=str(root), timeout=30)
        result = _text(await shell(command="echo legacy-ok"))
        self.assertIn("<returncode>0</returncode>", result)
        self.assertIn("legacy-ok", result)
        self.assertFalse((root / "artifacts").exists())


if __name__ == "__main__":
    unittest.main()
