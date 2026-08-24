"""TonyEnc 识别、解码与任务目录边界测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.TonyDec import create_tonydec_tool
from Tools.third_party.tonydec.tonydec import (
    decrypt_content,
    tonyenc_header,
    tonyenc_key,
)


def _encode_fixture(plaintext: bytes) -> bytes:
    """TonyDec 的 XOR 变换是自反的，用相同状态生成测试密文。"""
    data = bytearray(plaintext)
    p = 0
    for i in range(1, len(data), 2):
        p = (p + tonyenc_key[p] + i) % len(tonyenc_key)
        data[i] = data[i] ^ tonyenc_key[p] ^ 0xFF
    return tonyenc_header + bytes(data)


class TonyDecAlgorithmTest(unittest.TestCase):
    def test_known_header_and_roundtrip(self) -> None:
        self.assertEqual(tonyenc_header.hex(), "6688ff4f6886005611611618")
        plaintext = b"PK\x03\x04fixture-content\x00\xff"
        self.assertEqual(bytes(decrypt_content(_encode_fixture(plaintext))), plaintext)

    def test_non_tonyenc_returns_none(self) -> None:
        self.assertIsNone(decrypt_content(b"ordinary file"))


class TonyDecToolTest(unittest.IsolatedAsyncioTestCase):
    async def test_file_decode_returns_hash_and_writes_output(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-tonydec-"))
        plaintext = b"\x7fELFdecoded-fixture"
        (root / "sample.enc").write_bytes(_encode_fixture(plaintext))
        tool = create_tonydec_tool(root)

        result = await tool(input_path="sample.enc", output_path="sample.dec")

        self.assertEqual((root / "sample.dec").read_bytes(), plaintext)
        self.assertIn('"decoded": 1', str(result))
        self.assertIn("sha256", str(result))

    async def test_rejects_output_outside_task_root(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-tonydec-root-"))
        outside = Path(tempfile.mkdtemp(prefix="lingshu-tonydec-outside-"))
        (root / "sample.enc").write_bytes(_encode_fixture(b"data"))
        tool = create_tonydec_tool(root)
        with self.assertRaises(PermissionError):
            await tool(
                input_path="sample.enc",
                output_path=str(outside / "sample.dec"),
            )

    async def test_rejects_overwrite(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-tonydec-overwrite-"))
        (root / "sample.enc").write_bytes(_encode_fixture(b"data"))
        (root / "sample.dec").write_bytes(b"existing")
        tool = create_tonydec_tool(root)
        with self.assertRaises(FileExistsError):
            await tool(input_path="sample.enc", output_path="sample.dec")


if __name__ == "__main__":
    unittest.main()
