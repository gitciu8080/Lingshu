"""normalize_flag_key 与 MissionState.nss_rejected_keys 的变体拦截单测。

依据 2026-11-15 通宵压测复盘（attempt#13561 六连错 / #13549 误拒）：
NSSCTF Arena 按题目原生格式校验 flag（不限定 NSSCTF{} 前缀），
包装壳与大小写不影响判定内容——同内容换壳变体应归一化同键，
供 submit_nss_flag 在提交层拦截，避免重复消耗平台错误次数。
"""
import unittest

from core.TaskState import MissionState, normalize_flag_key


class NormalizeFlagKeyTest(unittest.TestCase):
    BASE = "NSSCTF{Y0u_know_broadca5t_att4ck}"

    def test_case_variant_shares_key(self):
        """大小写变体（真实复盘案例：Y0u… 与 y0u…）应归一化同键。"""
        self.assertEqual(
            normalize_flag_key(self.BASE),
            normalize_flag_key("NSSCTF{y0u_know_broadca5t_att4ck}"),
        )

    def test_nested_wrapper_stripped(self):
        """双重包裹（真实复盘案例：NSSCTF{LitCTF{...}}）应剥到内层内容。"""
        self.assertEqual(
            normalize_flag_key(self.BASE),
            normalize_flag_key("NSSCTF{LitCTF{Y0u_know_broadca5t_att4ck}}"),
        )

    def test_native_prefix_shares_key(self):
        """原生前缀（LitCTF{...}）与换壳版本同键。"""
        self.assertEqual(
            normalize_flag_key(self.BASE),
            normalize_flag_key("LitCTF{Y0u_know_broadca5t_att4ck}"),
        )

    def test_leet_difference_is_different_key(self):
        """内容实质不同（leet 改写：broadca5t → broadcast）不算变体。"""
        self.assertNotEqual(
            normalize_flag_key(self.BASE),
            normalize_flag_key("NSSCTF{You_know_broadcast_attack}"),
        )

    def test_bare_text_matches_content(self):
        """裸文本与带壳版本同键（内容相同）。"""
        self.assertEqual(
            normalize_flag_key("NSSCTF{abc_def}"),
            normalize_flag_key("abc_def"),
        )

    def test_empty_and_plain(self):
        """空串与纯文本安全返回（纯文本去空白后归一化）。"""
        self.assertEqual(normalize_flag_key(""), "")
        self.assertEqual(normalize_flag_key("plain text"), "plaintext")
        self.assertEqual(normalize_flag_key(None), "")


class MissionStateRejectedKeysTest(unittest.TestCase):
    def _mission(self) -> MissionState:
        return MissionState(target="10.0.0.1", goal="获取 Flag", authorized=True)

    def test_default_empty_list(self):
        self.assertEqual(self._mission().nss_rejected_keys, [])

    def test_append_and_case_insensitive_hit(self):
        mission = self._mission()
        mission.nss_rejected_keys.append(normalize_flag_key("NSSCTF{Wrong_Flag}"))
        self.assertIn(normalize_flag_key("nssctf{wrong_flag}"), mission.nss_rejected_keys)


if __name__ == "__main__":
    unittest.main()
