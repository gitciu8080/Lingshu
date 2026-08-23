"""受限的 Tesseract OCR 工具。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from Tools.tooling import AllowedFunctionTool

_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff", ".gif"}
_LANGUAGE_RE = re.compile(r"^[A-Za-z0-9_+-]{1,64}$")


def create_tesseract_ocr_tool(
    allowed_root: str | Path,
    timeout: int = 90,
    *,
    executor: Any,
) -> AllowedFunctionTool:
    """创建只能读取指定根目录内图片的 OCR 工具（在 Docker 容器内执行）。

    Args:
        allowed_root: 允许读取图片的根目录。
        timeout: Tesseract 超时秒数。
        executor: LingshuDockerExecutor 实例。OCR 在 Docker 容器内执行
            （图片路径自动映射到 /workspace）。
    """
    root = Path(allowed_root).resolve()

    async def ocr_image(image_path: str, language: str = "eng", page_segmentation_mode: int = 6) -> str:
        """使用 Tesseract 提取图片文本。

        Args:
            image_path: 项目工作区内的图片绝对路径或相对路径。
            language: Tesseract 语言包，如 eng、chi_sim 或 eng+chi_sim。
            page_segmentation_mode: 页面分割模式（0-13），普通文本图片建议 6。
        """
        if not _LANGUAGE_RE.fullmatch(language):
            return "[OCR 拒绝] language 只能包含字母、数字、下划线、加号或连字符。"
        if not 0 <= page_segmentation_mode <= 13:
            return "[OCR 拒绝] page_segmentation_mode 必须位于 0-13。"

        candidate = Path(image_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve()
        if candidate != root and root not in candidate.parents:
            return f"[OCR 拒绝] 图片必须位于授权工作区：{root}"
        if candidate.suffix.lower() not in _IMAGE_SUFFIXES:
            return f"[OCR 拒绝] 不支持的图片格式：{candidate.suffix or '无扩展名'}"

        # ── 在容器内执行 tesseract ──
        container_path = executor.map_path(str(candidate))
        cmd = (
            f"tesseract {_shell_quote(container_path)} stdout"
            f" -l {_shell_quote(language)}"
            f" --psm {int(page_segmentation_mode)}"
        )
        outcome = await executor.exec_shell(cmd, timeout=max(10, timeout))
        if outcome.timed_out:
            return f"[OCR 超时] Tesseract 超过 {max(10, timeout)} 秒未完成。"
        text = outcome.stdout.decode("utf-8", errors="replace").strip()
        error = outcome.stderr.decode("utf-8", errors="replace").strip()
        if outcome.exit_code != 0:
            return f"[OCR 失败] {error or f'Tesseract 退出码 {outcome.exit_code}'}"
        return text or f"[OCR 完成] 未识别到文本。{(' 提示：' + error) if error else ''}"

    return AllowedFunctionTool(ocr_image, is_read_only=True)


def _shell_quote(value: str) -> str:
    """单引号包裹 shell 参数，内部单引号转义。"""
    return "'" + value.replace("'", "'\\''") + "'"
