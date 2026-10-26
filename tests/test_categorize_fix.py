"""分类修复测试：词边界、扩展名强信号、Recon 后重分类。

覆盖计划验收项：
- 分类测试：附件路径中的 aicreate 不再命中 AI；RSA、PE、ELF、PCAP
  和 Web 题正确路由。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.target import TargetSpec, normalize_target
from agent.categorize import (
    CategoryDecision,
    _keyword_matches,
    classify,
    reclassify,
)


def _zip_file(name: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix="lingshu-cat-")) / name
    path.write_bytes(b"PKfake")
    return path


def _target(kind: str, path: str | None = None) -> TargetSpec:
    if path is not None:
        spec = normalize_target(path)
        return spec
    return normalize_target("127.0.0.1")


class KeywordBoundaryTest(unittest.TestCase):
    def test_ai_does_not_match_aicreate(self) -> None:
        self.assertFalse(_keyword_matches("ai", "aicreate challenge"))
        self.assertFalse(_keyword_matches("ai", "attach/aicreate/arena"))

    def test_ai_matches_standalone_word(self) -> None:
        self.assertTrue(_keyword_matches("ai", "ai model attack"))
        self.assertTrue(_keyword_matches("ai", "对抗样本 ai"))

    def test_rsa_matches_and_des_word_boundary(self) -> None:
        self.assertTrue(_keyword_matches("rsa", "rsa 公钥"))
        self.assertFalse(_keyword_matches("des", "desktop"))
        self.assertTrue(_keyword_matches("des", "des 加密"))

    def test_long_keywords_still_substring(self) -> None:
        self.assertTrue(_keyword_matches("prompt injection", "prompt injection 攻击"))
        self.assertTrue(_keyword_matches("reverse engineering", "reverse engineering 题"))


class ClassifyRoutingTest(unittest.TestCase):
    def test_attachment_path_with_aicreate_not_ai(self) -> None:
        """附件路径含 aicreate 不应命中 ai-ml（词边界修复）。"""
        goal = "分析附件并恢复数据"
        manifest = {"file_count": 1, "total_bytes": 10, "files": ["data.bin"]}
        path = Path(tempfile.mkdtemp()) / "aicreate" / "arena" / "challenge.zip"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"PK")
        spec = normalize_target(str(path))
        decision = classify(spec, goal, manifest)
        self.assertNotEqual(decision.primary, "ai-ml")

    def test_rsa_routes_to_crypto(self) -> None:
        path = _zip_file("rsa_challenge.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 2, "total_bytes": 100,
                    "files": ["flag.enc", "pub.pem", "task.py"]}
        decision = classify(spec, "分析 RSA 并解密", manifest)
        self.assertEqual(decision.primary, "crypto")

    def test_elf_without_remote_routes_to_reverse(self) -> None:
        # ELF 条件归属：.elf 文件且无远程服务线索 → reverse（纯静态逆向）
        path = _zip_file("elf_challenge.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 1, "total_bytes": 200,
                    "files": ["challenge.elf"]}
        decision = classify(spec, "分析程序", manifest)
        self.assertEqual(decision.primary, "reverse")

    def test_elf_with_remote_service_routes_to_pwn(self) -> None:
        # ELF + nc 远程服务线索 → pwn（二进制利用）
        path = _zip_file("pwn_challenge.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 1, "total_bytes": 200,
                    "files": ["challenge.elf"]}
        decision = classify(spec, "分析程序并打通 nc 10.0.0.5 9999 远程服务", manifest)
        self.assertEqual(decision.primary, "pwn")

    def test_elf_magic_after_recon_routes_to_reverse(self) -> None:
        """无扩展名 ELF：初始 unknown，Recon 的 file 魔法输出后 reclassify 到 reverse。"""
        path = _zip_file("elf_challenge.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 1, "total_bytes": 200, "files": ["challenge"]}
        initial = classify(spec, "分析程序", manifest)
        self.assertNotEqual(initial.primary, "pwn")  # 初始无 ELF 证据

        decision = reclassify(
            initial,
            ["challenge: ELF 64-bit LSB executable, x86-64"],
        )
        self.assertEqual(decision.primary, "reverse")

    def test_elf_magic_with_remote_after_recon_routes_to_pwn(self) -> None:
        """ELF 魔法 + 报告中的远程服务地址 → reclassify 到 pwn。"""
        path = _zip_file("pwn_challenge.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 1, "total_bytes": 200, "files": ["challenge"]}
        initial = classify(spec, "分析程序", manifest)
        decision = reclassify(
            initial,
            [
                "challenge: ELF 64-bit LSB executable, x86-64",
                "题面提示：nc 192.168.1.10 8888 连接远程服务",
            ],
        )
        self.assertEqual(decision.primary, "pwn")

    def test_pcap_routes_to_forensics(self) -> None:
        path = _zip_file("pcap_task.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 3, "total_bytes": 300,
                    "files": ["capture.pcapng", "README.txt"]}
        decision = classify(spec, "分析网络流量", manifest)
        self.assertEqual(decision.primary, "forensics")

    def test_memory_dump_routes_to_forensics(self) -> None:
        path = _zip_file("memory_task.zip")
        spec = normalize_target(str(path))
        manifest = {
            "file_count": 2,
            "total_bytes": 4096,
            "files": ["host-memory.dmp", "notes.txt"],
        }
        decision = classify(spec, "分析附件并恢复取证证据", manifest)
        self.assertEqual(decision.primary, "forensics")

    def test_web_goal_routes_to_web(self) -> None:
        spec = normalize_target("http://10.0.0.1:8080")
        decision = classify(spec, "枚举 HTTP 路由并验证 Web 漏洞")
        self.assertEqual(decision.primary, "web")

    def test_pe_routes_to_reverse(self) -> None:
        path = _zip_file("pe_task.zip")
        spec = normalize_target(str(path))
        manifest = {"file_count": 1, "total_bytes": 400,
                    "files": ["crackme.exe"]}
        decision = classify(spec, "分析程序", manifest)
        self.assertEqual(decision.primary, "reverse")


class ReclassifyTest(unittest.TestCase):
    def test_recon_evidence_uses_word_boundary(self) -> None:
        """Recon 证据含 aicreate 路径不命中 ai-ml。"""
        previous = CategoryDecision(
            primary="unknown", secondary=[], confidence=0.0,
            scores={}, evidence=[], stage="initial",
        )
        decision = reclassify(
            previous,
            ["解压路径 /tmp/attach/aicreate/arena 下的文件"],
        )
        self.assertNotEqual(decision.primary, "ai-ml")

    def test_recon_evidence_can_promote_category(self) -> None:
        previous = CategoryDecision(
            primary="unknown", secondary=[], confidence=0.0,
            scores={"web": 0.5}, evidence=["初始无结论"], stage="initial",
        )
        decision = reclassify(
            previous,
            ["目标开放 80 端口，返回 HTTP 响应，存在 SQL 注入点 sqli"],
        )
        self.assertEqual(decision.primary, "web")


if __name__ == "__main__":
    unittest.main()
