"""受控的 DeepSeek 视觉分析工具。

工具只接受当前任务授权目录内的本地图片。路径、真实图片格式、尺寸和大小
均在调用模型前校验，避免模型通过工具读取任意系统文件。
"""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from agentscope.message import DataBlock, TextBlock, URLSource, UserMsg

from Tools.tooling import AllowedFunctionTool


_FORMAT_TO_MEDIA_TYPE = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "GIF": "image/gif",
    "WEBP": "image/webp",
}
_MAX_IMAGE_BYTES = 32 * 1024 * 1024
_MAX_IMAGE_DIMENSION = 8192


def _resolve_authorized_image(
    image_path: str,
    allowed_roots: tuple[Path, ...],
) -> tuple[Path, str, tuple[int, int]]:
    candidate = Path(image_path).expanduser()
    if not candidate.is_absolute():
        candidate = allowed_roots[0] / candidate
    candidate = candidate.resolve()
    if not any(candidate == root or candidate.is_relative_to(root) for root in allowed_roots):
        raise PermissionError("图片不在本任务授权工作区内")
    if not candidate.is_file():
        raise FileNotFoundError(f"图片不存在：{candidate}")
    if candidate.stat().st_size > _MAX_IMAGE_BYTES:
        raise ValueError("单张图片不能超过 32 MiB")

    try:
        with Image.open(candidate) as image:
            image_format = str(image.format or "").upper()
            dimensions = image.size
            image.verify()
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("文件内容不是有效图片") from exc
    media_type = _FORMAT_TO_MEDIA_TYPE.get(image_format)
    if media_type is None:
        raise ValueError("仅支持 JPEG、PNG、GIF 和 WebP 图片")
    if max(dimensions) > _MAX_IMAGE_DIMENSION:
        raise ValueError("图片任一边不能超过 8192 像素")
    return candidate, media_type, dimensions


def _response_text(response) -> str:
    return "\n".join(
        block.text
        for block in getattr(response, "content", [])
        if isinstance(block, TextBlock) and block.text
    ).strip()


def create_vision_analysis_tool(
    vision_model,
    allowed_roots: Iterable[str | Path],
) -> AllowedFunctionTool:
    """创建只读取本任务目录、使用 DeepSeek Vision 的分析工具。"""
    roots = tuple(dict.fromkeys(Path(root).expanduser().resolve() for root in allowed_roots))
    if not roots:
        raise ValueError("视觉工具至少需要一个授权目录")

    async def analyze_image(
        image_path: str,
        question: str = "请完整分析这张图片，提取与当前授权安全测试或 CTF 解题有关的可验证信息与线索。",
    ) -> str:
        """理解授权任务中的本地图片、截图、图表或视觉题目。

        Args:
            image_path: 当前任务授权工作区内图片的绝对路径或相对路径。
            question: 希望视觉模型重点回答的问题；应包含当前题目背景和分析目标。
        """
        try:
            candidate, media_type, dimensions = _resolve_authorized_image(
                image_path,
                roots,
            )
        except (PermissionError, FileNotFoundError, ValueError) as exc:
            return f"[视觉分析拒绝] {exc}"

        prompt = question.strip() or (
            "请完整分析这张图片，提取与当前授权安全测试或 CTF 解题有关的"
            "可验证信息与线索。"
        )
        message = UserMsg(
            name="VisionTool",
            content=[
                TextBlock(
                    text=(
                        f"{prompt}\n\n"
                        "请区分图片中直接可见的事实与推测；不要虚构无法辨认的文字。"
                    ),
                ),
                DataBlock(
                    source=URLSource(
                        url=candidate.as_uri(),
                        media_type=media_type,
                    ),
                    name=candidate.name,
                ),
            ],
        )

        result = await vision_model([message])
        final_response = None
        if hasattr(result, "__aiter__"):
            async for chunk in result:
                final_response = chunk
        else:
            final_response = result
        text = _response_text(final_response) if final_response is not None else ""
        if not text:
            return "[视觉分析失败] 模型未返回可读文本"
        width, height = dimensions
        return (
            f"[视觉分析完成] 文件={candidate.name}，格式={media_type}，"
            f"尺寸={width}x{height}\n{text}"
        )

    return AllowedFunctionTool(analyze_image, is_read_only=True)
