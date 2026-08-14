"""受工作目录约束的 TonyEnc 识别与解码工具。"""
from __future__ import annotations

import hashlib
from pathlib import Path

from Tools.tooling import AllowedFunctionTool
from Tools.third_party.tonydec.tonydec import decrypt_content, tonyenc_header


def _within(root: Path, value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if candidate != root and root not in candidate.parents:
        raise PermissionError("路径超出本次任务工作目录")
    return candidate


def create_tonydec_tool(allowed_root: str | Path) -> AllowedFunctionTool:
    """创建只能读取和写入任务工作目录的 TonyEnc 解码工具。"""
    root = Path(allowed_root).resolve()

    def tonydec(input_path: str, output_path: str) -> dict:
        """识别并解码 TonyEnc 文件或目录。

        当文件以十六进制头 ``6688ff4f6886005611611618`` 开始时执行
        TonyDec；目录模式会递归处理，并原样复制未命中 TonyEnc 头的普通文件。

        Args:
            input_path: 待检查文件或目录；必须位于任务工作目录内。
            output_path: 新的输出文件或目录；不得覆盖输入，也不得位于输入目录内。
        """
        source = _within(root, input_path)
        destination = _within(root, output_path)
        if not source.exists():
            raise FileNotFoundError(f"输入不存在: {source}")
        if destination.exists():
            raise FileExistsError(f"输出已存在，拒绝覆盖: {destination}")
        if destination == source or (source.is_dir() and source in destination.parents):
            raise ValueError("输出不能等于输入或位于输入目录内部")

        decoded = copied = 0
        outputs: list[dict[str, str | int | bool]] = []

        def process_file(current: Path, target: Path) -> None:
            nonlocal decoded, copied
            raw = current.read_bytes()
            plaintext = decrypt_content(raw)
            target.parent.mkdir(parents=True, exist_ok=True)
            matched = plaintext is not None
            payload = bytes(plaintext) if matched else raw
            target.write_bytes(payload)
            if matched:
                decoded += 1
            else:
                copied += 1
            outputs.append({
                "source": current.relative_to(root).as_posix(),
                "output": target.relative_to(root).as_posix(),
                "tonyenc": matched,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })

        if source.is_file():
            process_file(source, destination)
        elif source.is_dir():
            for current in sorted(source.rglob("*")):
                if current.is_symlink():
                    continue
                if current.is_file():
                    process_file(current, destination / current.relative_to(source))
        else:
            raise ValueError("输入必须是普通文件或目录")

        return {
            "signature": tonyenc_header.hex(),
            "decoded": decoded,
            "copied": copied,
            "files": outputs,
            "next_step": "对解码输出执行 file/哈希/字符串检查，确认恢复后的真实格式与内容。",
        }

    return AllowedFunctionTool(tonydec, is_concurrency_safe=False)
