from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from Tools.archive import SafeExtractError, safe_extract
from Tools.target import normalize_target


@unittest.skipUnless(shutil.which("7z"), "需要 7z 命令")
class SevenZipExtractionTest(unittest.TestCase):
    def test_normalize_and_extract_7z(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "flag.txt").write_text("NSSCTF{test}", encoding="utf-8")
            archive = root / "challenge.7z"
            subprocess.run(
                [shutil.which("7z"), "a", str(archive), "flag.txt"],
                cwd=source,
                check=True,
                capture_output=True,
            )

            self.assertEqual(normalize_target(str(archive)).kind, "archive")
            output = root / "output"
            manifest = safe_extract(archive, output)

            self.assertEqual(manifest.file_count, 1)
            self.assertEqual((output / "flag.txt").read_text(encoding="utf-8"), "NSSCTF{test}")

    def test_encrypted_7z_is_nonfatal_and_keeps_archive_as_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            archive = root / "encrypted.7z"
            subprocess.run(
                [shutil.which("7z"), "a", "-pknown-password", str(archive), source.name],
                cwd=root,
                check=True,
                capture_output=True,
            )

            output = root / "output"
            manifest = safe_extract(archive, output)

            self.assertTrue(manifest.encrypted)
            self.assertFalse(output.exists())

    def test_magic_detects_extensionless_7z(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "data.txt"
            source.write_text("data", encoding="utf-8")
            generated = root / "payload.7z"
            subprocess.run(
                [shutil.which("7z"), "a", "-t7z", str(generated), source.name],
                cwd=root,
                check=True,
                capture_output=True,
            )
            archive = root / "payload"
            generated.rename(archive)
            self.assertEqual(normalize_target(str(archive)).kind, "archive")


class ArchiveSafetyTest(unittest.TestCase):
    def test_corrupt_archive_is_normalized_and_leaves_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "broken.zip"
            archive.write_bytes(b"not a zip")
            output = root / "output"
            with self.assertRaises(SafeExtractError):
                safe_extract(archive, output)
            self.assertFalse(output.exists())

    def test_backslash_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "traversal.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(r"..\evil.txt", "bad")
            with self.assertRaises(SafeExtractError):
                safe_extract(archive, root / "output")
            self.assertFalse((root / "evil.txt").exists())

    def test_duplicate_zip_member_is_rejected_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "duplicate.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("same.txt", "one")
                zf.writestr("same.txt", "two")
            output = root / "output"
            with self.assertRaises(SafeExtractError):
                safe_extract(archive, output)
            self.assertFalse(output.exists())

    def test_zip_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "symlink.zip"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(info, "target")
            with self.assertRaises(SafeExtractError):
                safe_extract(archive, root / "output")

    def test_tar_symlink_is_rejected_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "symlink.tar"
            with tarfile.open(archive, "w") as tf:
                regular = tarfile.TarInfo("safe.txt")
                regular.size = 4
                tf.addfile(regular, io.BytesIO(b"safe"))
                link = tarfile.TarInfo("link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                tf.addfile(link)
            output = root / "output"
            with self.assertRaises(SafeExtractError):
                safe_extract(archive, output)
            self.assertFalse(output.exists())

    def test_extension_mismatch_uses_magic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "actually-zip.7z"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("data.txt", "data")
            output = root / "output"
            manifest = safe_extract(archive, output)
            self.assertEqual(manifest.file_count, 1)
            self.assertEqual((output / "data.txt").read_text(), "data")


if __name__ == "__main__":
    unittest.main()
