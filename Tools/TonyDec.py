"""受工作目录约束的 TonyEnc 识别与解码工具。"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

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


def create_tonydec_tool(
    allowed_root: str | Path,
    *,
    executor: Any | None = None,
) -> AllowedFunctionTool:
    """创建只能读取和写入任务工作目录的 TonyEnc 解码工具。

    Args:
        allowed_root: 任务工作目录根。
        executor: LingshuDockerExecutor 实例。提供时文件读写通过容器执行；
            解码逻辑仍在宿主机运行（依赖本地 tonydec Python 模块）。
    """
    root = Path(allowed_root).resolve()

    async def _read_file_bytes(path: Path) -> bytes:
        if executor is not None:
            container_path = executor.map_path(str(path))
            return await executor.read_bytes(container_path)
        return path.read_bytes()

    async def _write_file_bytes(path: Path, data: bytes) -> None:
        if executor is not None:
            container_path = executor.map_path(str(path))
            await executor.write_bytes(container_path, data)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    async def _list_files(directory: Path) -> list[Path]:
        """列出目录下的普通文件列表。"""
        if executor is not None:
            container_path = executor.map_path(str(directory))
            entries = await executor.list_dir(container_path)
            return [directory / name for name in entries]
        return sorted(f for f in directory.rglob("*") if f.is_file() and not f.is_symlink())

    async def tonydec(input_path: str, output_path: str) -> dict:
        """识别并解码 TonyEnc 文件或目录。

        当文件以十六进制头 ``6688ff4f6886005611611618`` 开始时执行
        TonyDec；目录模式会递归处理，并原样复制未命中 TonyEnc 头的普通文件。

        Args:
            input_path: 待检查文件或目录；必须位于任务工作目录内。
            output_path: 新的输出文件或目录；不得覆盖输入，也不得位于输入目录内。
        """
        source = _within(root, input_path)
        destination = _within(root, output_path)

        # Docker 模式：通过 executor 检查存在性
        if executor is not None:
            container_src = executor.map_path(str(source))
            check = await executor.exec_shell(
                f"test -e {_shell_quote(container_src)} && echo exists || echo missing",
            )
            exists = b"exists" in check.stdout
        else:
            exists = source.exists()

        if not exists:
            raise FileNotFoundError(f"输入不存在: {source}")

        if destination == source or (source.is_dir() and source in destination.parents):
            raise ValueError("输出不能等于输入或位于输入目录内部")

        decoded = copied = 0
        outputs: list[dict[str, str | int | bool]] = []

        async def process_file(current: Path, target: Path) -> None:
            nonlocal decoded, copied
            raw = await _read_file_bytes(current)
            plaintext = decrypt_content(raw)
            matched = plaintext is not None
            payload = bytes(plaintext) if matched else raw
            await _write_file_bytes(target, payload)
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

        # 判断是否为目录（Docker 模式下通过 exec 检查）
        is_dir = False
        if executor is not None:
            container_src = executor.map_path(str(source))
            check = await executor.exec_shell(
                f"test -d {_shell_quote(container_src)} && echo dir || echo file",
            )
            is_dir = b"dir" in check.stdout
        else:
            is_dir = source.is_dir()

        if not is_dir:
            await process_file(source, destination)
        else:
            # Docker 模式下递归列出文件
            if executor is not None:
                container_src = executor.map_path(str(source))
                result = await executor.exec_shell(
                    f"cd {_shell_quote(container_src)} && find . -type f -printf '%P\\n'",
                )
                file_list = [
                    line for line in
                    result.stdout.decode("utf-8", errors="replace").splitlines()
                    if line
                ]
                for rel in sorted(file_list):
                    current = source / rel
                    await process_file(current, destination / rel)
            else:
                for current in sorted(source.rglob("*")):
                    if current.is_symlink():
                        continue
                    if current.is_file():
                        await process_file(current, destination / current.relative_to(source))

        return {
            "signature": tonyenc_header.hex(),
            "decoded": decoded,
            "copied": copied,
            "files": outputs,
            "next_step": "对解码输出执行 file/哈希/字符串检查，确认恢复后的真实格式与内容。",
        }

    return AllowedFunctionTool(tonydec, is_concurrency_safe=False)


def _shell_quote(value: str) -> str:
    """单引号包裹 shell 参数，内部单引号转义。"""
    return "'" + value.replace("'", "'\\''") + "'"
