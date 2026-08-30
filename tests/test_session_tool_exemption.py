"""会话型 MCP 工具豁免动作去重回放的回归测试（e8d94cdd / 9a045e1f 复盘）。

故障机制：Reserve 上一轮按规范 idb_close 关闭会话后，下一轮的
ida_open_binary 因签名相同被动作去重缓存拦截，回放携带已销毁 session_id
的旧成功结果 → 真实 MCP 调用全部 "Session not found" → 死循环烧尽迭代。

修复语义：会话生命周期/状态工具必须每次真实执行（仍记录动作与失败路径），
只有缓存回放被跳过；IDA 只读分析工具继续享受去重。
"""

from __future__ import annotations

import unittest

from main import _is_session_lifecycle_tool


class SessionLifecycleToolPredicateTest(unittest.TestCase):
    def test_incident_tools_are_exempt(self) -> None:
        # 复盘中的事故工具：本地包装 + IDA MCP 会话管理
        self.assertTrue(_is_session_lifecycle_tool("ida_open_binary"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__IDA_Tool__idb_close"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__IDA_Tool__idb_list"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__IDA_Tool__server_health"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__IDA_Tool__idb_open"))

    def test_gdb_session_tools_are_exempt(self) -> None:
        self.assertTrue(_is_session_lifecycle_tool("mcp__GDB_Tool__create_session"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__GDB_Tool__close_session"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__GDB_Tool__list_sessions"))
        self.assertTrue(_is_session_lifecycle_tool("mcp__GDB_Tool__load_core"))

    def test_readonly_analysis_tools_still_deduplicated(self) -> None:
        # 只读分析工具不受影响，继续走去重缓存
        self.assertFalse(_is_session_lifecycle_tool("mcp__IDA_Tool__decompile"))
        self.assertFalse(_is_session_lifecycle_tool("mcp__IDA_Tool__survey_binary"))
        self.assertFalse(_is_session_lifecycle_tool("mcp__IDA_Tool__get_bytes"))
        self.assertFalse(_is_session_lifecycle_tool("mcp__IDA_Tool__xrefs_to"))

    def test_unrelated_tools_not_exempt(self) -> None:
        self.assertFalse(_is_session_lifecycle_tool("scoped_shell"))
        self.assertFalse(_is_session_lifecycle_tool("Skill"))
        self.assertFalse(_is_session_lifecycle_tool("QueryMemory"))
        self.assertFalse(_is_session_lifecycle_tool(""))
        self.assertFalse(_is_session_lifecycle_tool(None))  # type: ignore[arg-type]

    def test_case_insensitive_matching(self) -> None:
        self.assertTrue(_is_session_lifecycle_tool("MCP__IDA_TOOL__IDB_CLOSE"))
        self.assertTrue(_is_session_lifecycle_tool("IDA_Open_Binary"))


if __name__ == "__main__":
    unittest.main()
