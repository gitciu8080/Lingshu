"""记忆闭环测试：脱敏、techniques 放宽、lessons 注入、打分检索、损坏恢复。

不触碰真实 .LongMemory 文件——通过 monkeypatch 重定向 _MEMORY_FILE。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import Tools.AgenticMemory as am


def _isolated_memory(missions: list[dict], techniques: dict | None = None):
    """把 AgenticMemory 的存储重定向到临时文件并返回路径。"""
    tmp = tempfile.mkdtemp(prefix="lingshu-memory-test-")
    path = Path(tmp) / "agentic_memory.json"
    path.write_text(json.dumps(
        {"missions": missions, "techniques": techniques or {}},
        ensure_ascii=False), encoding="utf-8")
    return path


FLAG = "flag{secret_flag_value}"
MISSIONS = [
    {
        "timestamp": "2026-10-01T10:00:00",
        "target": "10.1.2.3",
        "goal": "Apache 中间件渗透评估 http://vuln.example.com",
        "plan": "侦察 Apache 路径穿越",
        "attack_chain": [{"service": "Apache 2.4.49", "cve": "CVE-2021-41773",
                          "objective": "路径穿越读取"}],
        "success": True,
        "summary": "利用路径穿越确认信息泄露",
        "flag": FLAG,
        "lessons": ["方法失效: 路径穿越需开启 cgi 模块才可 RCE，普通部署仅文件读取"],
    },
    {
        "timestamp": "2026-10-02T11:00:00",
        "target": "10.4.5.6",
        "goal": "UPX 加壳逆向分析",
        "plan": "脱壳后 strings 提取",
        "attack_chain": [{"technique": "UPX 脱壳", "objective": "静态分析"}],
        "success": True,
        "summary": "upx -d 后直接 strings 命中 flag 特征",
        "flag": None,
        "lessons": [],
    },
]


class SanitizeTest(unittest.TestCase):
    def test_format_experience_never_leaks_flag_or_raw_target(self) -> None:
        path = _isolated_memory(MISSIONS)
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            text = am._format_experience(am.query_experience(service=None), "")
            self.assertNotIn(FLAG, text)
            self.assertNotIn("10.1.2.3", text)
            self.assertIn("Apache", text)          # 技术词保留

    def test_format_experience_service_branch_sanitized(self) -> None:
        path = _isolated_memory(MISSIONS)
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            text = am._format_experience(
                am.query_experience(service="Apache 2.4.49"), "Apache 2.4.49")
            self.assertNotIn(FLAG, text)
            self.assertNotIn("vuln.example.com", text)


class TechniquesWidenTest(unittest.TestCase):
    def test_technique_only_step_is_recorded(self) -> None:
        # 旧逻辑要求 service+cve 同键；technique-only 步骤此前不落 techniques
        path = _isolated_memory([])
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            am.save_mission(
                target="1.1.1.1", goal="g", plan="p",
                attack_chain=[{"technique": "UPX 脱壳", "objective": "静态分析"}],
                success=True, summary="s",
            )
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(any("UPX" in key for key in data["techniques"]))

    def test_cve_only_step_is_recorded(self) -> None:
        path = _isolated_memory([])
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            am.save_mission(
                target="1.1.1.1", goal="g", plan="p",
                attack_chain=[{"cve": "CVE-2021-41773", "objective": "穿越"}],
                success=True, summary="s",
            )
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["techniques"]), 1)


class ExperienceHintTest(unittest.TestCase):
    def test_hint_includes_lessons_and_no_flag(self) -> None:
        path = _isolated_memory(MISSIONS)
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            hint = am.get_experience_hint()
        self.assertIn("历史失败教训", hint)
        self.assertIn("cgi", hint)
        self.assertNotIn(FLAG, hint)
        self.assertNotIn("10.1.2.3", hint)

    def test_hint_empty_memory_returns_empty(self) -> None:
        path = _isolated_memory([])
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            self.assertEqual(am.get_experience_hint(), "")


class ScoringTest(unittest.TestCase):
    def test_token_overlap_matches_paraphrased_mission(self) -> None:
        # 措辞不同但技术重叠（旧 plan 包含匹配命中不了）
        missions = [{
            "timestamp": "2026-10-03T09:00:00", "target": "10.9.9.9",
            "goal": "对 shiro 反序列化利用评估",
            "plan": "shiro key 爆破与利用",
            "attack_chain": [], "success": False,
            "summary": "shiro rememberme cookie 反序列化", "flag": None,
        }]
        path = _isolated_memory(missions)
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            result = am.query_experience(service="shiro 反序列化")
        self.assertEqual(len(result["related_missions"]), 1)

    def test_no_overlap_excluded(self) -> None:
        path = _isolated_memory(MISSIONS)
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            result = am.query_experience(service="windows 域渗透 kerberos")
        self.assertEqual(result["related_missions"], [])


class CorruptionRecoveryTest(unittest.TestCase):
    def test_corrupt_file_isolated_with_warning(self) -> None:
        tmp = tempfile.mkdtemp(prefix="lingshu-memory-corrupt-")
        path = Path(tmp) / "agentic_memory.json"
        path.write_text("{ broken json !!!", encoding="utf-8")
        with mock.patch.object(am, "_MEMORY_FILE", str(path)):
            with mock.patch("builtins.print") as printed:
                data = am._load()
        self.assertEqual(data, {"missions": [], "techniques": {}})
        warnings = [str(call.args[0]) for call in printed.call_args_list
                    if str(call.args[0]).startswith("[memory]")]
        self.assertEqual(len(warnings), 1)
        quarantined = list(Path(tmp).glob("agentic_memory.json.corrupt.*"))
        self.assertEqual(len(quarantined), 1)
        self.assertFalse(path.exists())   # 原文件已移走


if __name__ == "__main__":
    unittest.main()
