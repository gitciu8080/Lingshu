"""ELF 归属规则测试：pwn 需远程服务线索，纯 ELF 归 reverse。

领域规则（CTF 惯例）：
- pwn = ELF ∧ 远程服务（nc host port / 远程地址等连接方式）
- reverse = 单纯一个 ELF，无远程服务
辅助偏置：libc/ld 附件 → 偏 pwn；UPX/壳/license/序列号 → 偏 reverse。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.target import normalize_target
from agent.categorize import (
    CategoryDecision,
    _REMOTE_SERVICE_RE,
    classify,
    evaluate_reclassification,
    extract_recon_signals,
    reclassify,
)


def _zip(name: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix="lingshu-elf-")) / name
    path.write_bytes(b"PKfake")
    return path


def _spec(name: str):
    return normalize_target(str(_zip(name)))


ELF_MAGIC_REPORT = "challenge: ELF 64-bit LSB executable, x86-64, dynamically linked"


class RemoteServicePatternTest(unittest.TestCase):
    def test_patterns(self) -> None:
        hits = [
            "nc 1.2.3.4 8888",
            "ncat challenge.ctf.pro 9999",
            "请连接远程服务器 10.0.0.5:6666 执行攻击",
            "remote service provided",
            "telnet 10.1.1.1:2345",
        ]
        for text in hits:
            self.assertIsNotNone(
                _REMOTE_SERVICE_RE.search(text.lower()), text,
            )
        misses = [
            "这是一个 flag calculator 程序",
            "分析程序逻辑并还原算法",
            "web 服务 http://10.0.0.1:8080 存在注入",
        ]
        for text in misses:
            self.assertIsNone(_REMOTE_SERVICE_RE.search(text.lower()), text)


class ElfAttributionTest(unittest.TestCase):
    def test_plain_elf_routes_to_reverse(self) -> None:
        """纯 ELF 附件（无远程线索）→ reverse。"""
        decision = classify(
            _spec("time-travel.zip"),
            "获取本题 Flag，仅测试本题环境和附件。This flag calculator.",
            {"file_count": 1, "total_bytes": 500, "files": ["challenge"]},
        )
        self.assertEqual(decision.primary, "unknown")  # 初始无 ELF 证据

        decision = reclassify(decision, [ELF_MAGIC_REPORT])
        self.assertEqual(decision.primary, "reverse")
        self.assertGreater(decision.scores.get("reverse", 0), decision.scores.get("pwn", 0))

    def test_elf_with_nc_routes_to_pwn(self) -> None:
        """ELF + nc 远程服务 → pwn。"""
        decision = classify(
            _spec("pwn_two.zip"),
            "打通 nc 192.168.1.10 8888 远程服务获取 Flag",
            {"file_count": 1, "total_bytes": 500, "files": ["challenge.elf"]},
        )
        self.assertEqual(decision.primary, "pwn")

    def test_libc_attachment_biases_pwn(self) -> None:
        """ELF + libc 附件 → pwn 偏置胜出。"""
        decision = classify(
            _spec("heap.zip"),
            "分析程序",
            {"file_count": 2, "total_bytes": 2000,
             "files": ["challenge.elf", "libc.so.6"]},
        )
        self.assertEqual(decision.primary, "pwn")

    def test_packer_keywords_bias_reverse(self) -> None:
        """ELF + 加壳/license 词 → reverse 偏置加强。"""
        decision = classify(
            _spec("crack.zip"),
            "分析加壳程序并找出注册码",
            {"file_count": 1, "total_bytes": 500, "files": ["challenge.elf"]},
        )
        self.assertEqual(decision.primary, "reverse")
        self.assertGreaterEqual(
            decision.scores.get("reverse", 0), 10 + 6,
        )


class ReconSignalAttributionTest(unittest.TestCase):
    def test_plain_elf_report_yields_reverse_signal(self) -> None:
        signals = extract_recon_signals([ELF_MAGIC_REPORT])
        elf = [s for s in signals if "ELF" in s.content]
        self.assertTrue(elf)
        self.assertEqual(elf[0].category, "reverse")

    def test_elf_with_remote_yields_pwn_signal(self) -> None:
        signals = extract_recon_signals([
            ELF_MAGIC_REPORT,
            "题面提供远程实例：nc 1.2.3.4 9999",
        ])
        elf = [s for s in signals if "ELF" in s.content]
        self.assertTrue(elf)
        self.assertEqual(elf[0].category, "pwn")


class ReclassificationThresholdTest(unittest.TestCase):
    def test_pwn_reverse_flips_with_3_point_lead(self) -> None:
        """pwn↔reverse 互翻门槛放宽为 3 分。

        previous pwn=7，新证据纯 ELF → reverse +10（含 Recon 关键词小加成），
        reverse 领先 3~5 分之间：旧 5 分门槛会拒绝，新 3 分门槛应接受。
        """
        previous = CategoryDecision(
            primary="pwn", secondary=[], confidence=0.6,
            scores={"pwn": 7.0}, evidence=[], stage="post_recon",
        )
        result = evaluate_reclassification(
            previous, [ELF_MAGIC_REPORT], seen_evidence_fingerprints=set(),
        )
        self.assertEqual(result.candidate.primary, "reverse")
        self.assertTrue(result.accepted, f"领先 3~5 分应接受翻转: {result.reason}")

    def test_pwn_reverse_tie_follows_new_evidence(self) -> None:
        """平分时由新证据方向决定（reverse 按排序胜出并可翻转）。"""
        previous = CategoryDecision(
            primary="pwn", secondary=[], confidence=0.6,
            scores={"pwn": 10.0}, evidence=[], stage="post_recon",
        )
        result = evaluate_reclassification(
            previous, [ELF_MAGIC_REPORT], seen_evidence_fingerprints=set(),
        )
        self.assertEqual(result.candidate.primary, "reverse")

    def test_other_categories_still_need_5_point_lead(self) -> None:
        """web→crypto 等其他类别对维持 5 分门槛。"""
        previous = CategoryDecision(
            primary="web", secondary=[], confidence=0.6,
            scores={"web": 8.0}, evidence=[], stage="post_recon",
        )
        # crypto 强信号 +8 → crypto 8.x vs web 8：领先远不足 5 分 → 拒绝
        result = evaluate_reclassification(
            previous,
            ["发现 BEGIN RSA PRIVATE KEY 密钥材料"],
            seen_evidence_fingerprints=set(),
        )
        if result.candidate.primary == "crypto":
            self.assertFalse(result.accepted, "领先不足 5 分应拒绝")


class A8f4bc98ReplayTest(unittest.TestCase):
    """复盘真实会话 a8f4bc98（逆向题被误判 pwn 20.5 : reverse 1.0）。"""

    def test_replay_time_travel_challenge(self) -> None:
        goal = (
            "获取本题 Flag，仅测试本题环境和附件。输出精确 Flag，不调用平台提交接口。"
            "time-travel This flag calculator has been running for a while..."
        )
        decision = classify(
            _spec("time-travel.zip"), goal,
            {"file_count": 1, "total_bytes": 500, "files": ["challenge"]},
        )
        decision = reclassify(decision, [ELF_MAGIC_REPORT])
        self.assertEqual(decision.primary, "reverse")
        self.assertNotIn("pwn", decision.scores)  # pwn 不再白得 ELF 分


if __name__ == "__main__":
    unittest.main()
