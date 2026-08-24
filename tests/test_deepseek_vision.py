"""DeepSeek V4 Flash Vision 模型与任务级图片权限测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from PIL import Image
from pydantic import SecretStr

from agentscope.credential import OpenAICredential
from agentscope.message import DataBlock, TextBlock, URLSource, UserMsg
from agentscope.model import ChatResponse

from LLM.model import (
    DeepSeekResponsesModel,
    VISION_MODEL,
    resolve_thinking_intensity,
)
from Tools.Vision import create_vision_analysis_tool


def _image_message(path: Path) -> UserMsg:
    return UserMsg(
        name="user",
        content=[
            TextBlock(text="分析图片"),
            DataBlock(
                source=URLSource(url=path.as_uri(), media_type="image/png"),
                name=path.name,
            ),
        ],
    )


def _model(name: str, *, vision: bool) -> DeepSeekResponsesModel:
    return DeepSeekResponsesModel(
        credential=OpenAICredential(
            api_key=SecretStr("test-key"),
            base_url="https://api.deepseek.invalid/v1",
        ),
        model=name,
        parameters=DeepSeekResponsesModel.Parameters(
            thinking_enable=True,
            reasoning_effort="high",
        ),
        vision=vision,
        stream=False,
    )


class DeepSeekVisionRequestTest(unittest.IsolatedAsyncioTestCase):
    def test_web_thinking_intensity_mapping(self) -> None:
        self.assertEqual(resolve_thinking_intensity("off"), (False, "none"))
        self.assertEqual(resolve_thinking_intensity("medium"), (True, "high"))
        self.assertEqual(resolve_thinking_intensity("high"), (True, "max"))

    async def test_vision_message_is_encoded_as_responses_input_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "evidence.png"
            Image.new("RGB", (8, 6), "white").save(image_path)
            model = _model(VISION_MODEL, vision=True)
            model.client.post = AsyncMock(return_value=SimpleNamespace())
            sentinel = object()
            with patch.object(
                model,
                "_parse_completion_response",
                return_value=sentinel,
            ):
                result = await model._call_api(VISION_MODEL, [_image_message(image_path)])

            self.assertIs(result, sentinel)
            body = model.client.post.await_args.kwargs["body"]
            image_block = body["input"][0]["content"][1]
            self.assertEqual(image_block["type"], "input_image")
            self.assertTrue(image_block["image_url"].startswith("data:image/png;base64,"))
            self.assertEqual(body["reasoning"], {"effort": "high"})

    async def test_non_vision_model_rejects_image_before_http_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "evidence.png"
            Image.new("RGB", (2, 2)).save(image_path)
            model = _model("deepseek-v4-flash", vision=False)
            model.client.post = AsyncMock()
            with self.assertRaisesRegex(ValueError, "图片输入仅支持"):
                await model._call_api("deepseek-v4-flash", [_image_message(image_path)])
            model.client.post.assert_not_awaited()


class VisionToolTest(unittest.IsolatedAsyncioTestCase):
    async def test_tool_reads_only_authorized_valid_images(self) -> None:
        class FakeVisionModel:
            async def __call__(self, messages):
                self.messages = messages

                async def chunks():
                    yield ChatResponse(
                        content=[TextBlock(text="图片中存在二维码和登录表单")],
                        is_last=True,
                    )

                return chunks()

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            image_path = root / "screen.webp"
            Image.new("RGB", (16, 12), "red").save(image_path)
            outside_path = Path(outside) / "secret.png"
            Image.new("RGB", (1, 1)).save(outside_path)
            fake = FakeVisionModel()
            tool = create_vision_analysis_tool(fake, [root])

            result = await tool._func(image_path="screen.webp", question="寻找视觉线索")
            self.assertIn("尺寸=16x12", result)
            self.assertIn("二维码和登录表单", result)
            denied = await tool._func(image_path=str(outside_path))
            self.assertIn("视觉分析拒绝", denied)
            self.assertIn("不在本任务授权工作区", denied)

    async def test_tool_checks_real_format_instead_of_extension(self) -> None:
        class UnusedModel:
            async def __call__(self, messages):  # pragma: no cover
                raise AssertionError("无效图片不应调用模型")

        with tempfile.TemporaryDirectory() as tmp:
            fake_image = Path(tmp) / "fake.png"
            fake_image.write_text("not an image", encoding="utf-8")
            tool = create_vision_analysis_tool(UnusedModel(), [tmp])
            result = await tool._func(image_path="fake.png")
            self.assertIn("文件内容不是有效图片", result)


if __name__ == "__main__":
    unittest.main()
