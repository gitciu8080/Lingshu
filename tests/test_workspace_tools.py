"""Workspace 受限工具测试：Read/Glob/Grep 的功能与路径逃逸防护。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.workspace_tools import create_workspace_tools, _resolve_within


def _text(result) -> str:
    """从 ToolChunk 中提取文本内容（2.0.6 工具统一返回 ToolChunk）。"""
    blocks = getattr(result, "content", None)
    if isinstance(blocks, list):
        return "\n".join(b.text for b in blocks if hasattr(b, "text"))
    return str(result)


def _workspace() -> tuple[Path, list]:
    workdir = Path(tempfile.mkdtemp(prefix="lingshu-wtools-"))
    (workdir / "input").mkdir()
    (workdir / "input" / "note.txt").write_text("hello 灵枢\nflag{test}\n", encoding="utf-8")
    (workdir / "input" / "data.bin").write_bytes(b"\x00\x01\x02binary")
    tools = {t.name: t for t in create_workspace_tools(workdir)}
    return workdir, tools


class WorkspaceReadTest(unittest.IsolatedAsyncioTestCase):
    async def test_read_relative_file(self) -> None:
        _, tools = _workspace()
        result = _text(await tools["workspace_read"](path="input/note.txt"))
        self.assertIn("hello 灵枢", result)
        self.assertIn("flag{test}", result)

    async def test_read_absolute_path_escape_rejected(self) -> None:
        _, tools = _workspace()
        with self.assertRaises(PermissionError):
            await tools["workspace_read"](path="/etc/passwd")

    async def test_read_dotdot_escape_rejected(self) -> None:
        _, tools = _workspace()
        with self.assertRaises(PermissionError):
            await tools["workspace_read"](path="../../etc/passwd")

    async def test_read_symlink_escape_rejected(self) -> None:
        workdir, tools = _workspace()
        # 工作区内创建指向 /etc/passwd 的符号链接
        (workdir / "input" / "evil_link.txt").symlink_to("/etc/passwd")
        with self.assertRaises(PermissionError):
            await tools["workspace_read"](path="input/evil_link.txt")

    async def test_read_missing_file_raises(self) -> None:
        _, tools = _workspace()
        with self.assertRaises(FileNotFoundError):
            await tools["workspace_read"](path="no/such.txt")


class WorkspaceGlobTest(unittest.IsolatedAsyncioTestCase):
    async def test_glob_returns_relative_paths(self) -> None:
        _, tools = _workspace()
        result = _text(await tools["workspace_glob"](pattern="input/*.txt"))
        self.assertIn("input/note.txt", result)
        self.assertNotIn(str(Path("input/note.txt").resolve()), result)  # 非绝对路径

    async def test_glob_absolute_pattern_rejected(self) -> None:
        _, tools = _workspace()
        with self.assertRaises(PermissionError):
            await tools["workspace_glob"](pattern="/etc/*")

    async def test_glob_no_match(self) -> None:
        _, tools = _workspace()
        self.assertEqual(_text(await tools["workspace_glob"](pattern="*.none")), "(无匹配)")


class WorkspaceGrepTest(unittest.IsolatedAsyncioTestCase):
    async def test_grep_finds_line_with_location(self) -> None:
        _, tools = _workspace()
        result = _text(await tools["workspace_grep"](pattern="flag\\{test\\}"))
        self.assertIn("input/note.txt:2:flag{test}", result)

    async def test_grep_skips_binary(self) -> None:
        _, tools = _workspace()
        result = _text(await tools["workspace_grep"](pattern="binary"))
        self.assertEqual(result, "(无匹配)")

    async def test_grep_escape_rejected(self) -> None:
        _, tools = _workspace()
        with self.assertRaises(PermissionError):
            await tools["workspace_grep"](pattern="x", path="../..")


class ResolveWithinTest(unittest.TestCase):
    def test_resolve_keeps_inside_root(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-resolve-"))
        (root / "sub").mkdir()
        target = _resolve_within(root, "sub")
        self.assertTrue(target.is_relative_to(root.resolve()))

    def test_resolve_rejects_outside(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-resolve-"))
        with self.assertRaises(PermissionError):
            _resolve_within(root, "..")


if __name__ == "__main__":
    unittest.main()
