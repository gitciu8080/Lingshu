"""AgentScope 2.x 模型工厂 — DeepSeek（含视觉）Responses API。

选型流程（已剔除 Low/Min/Max 三个固定层级）：
    选择模型供应商 → 选择模型 → 选择思考强度 → 确认

思考强度（thinking_intensity）：
    off    → 关闭思考链
    low    → 低推理深度
    medium → 平衡（默认）
    high   → 深度推理 / 强思考链

DeepSeek 走 Responses API（联网搜索工具仅在该 API 下可用），
通过 web_search 参数（或环境变量 DEEPSEEK_WEB_SEARCH）开启/关闭
服务端内置联网搜索。

视觉（vision）：deepseek-v4-flash-vision-exp 支持在文本之外输入图片，
图片以 Responses ``input_image`` 内容块承载（JPEG/PNG/GIF/WebP），
可内联 Base64 data URL 或公开 http(s) 链接。
"""
import logging
from typing import Any, AsyncGenerator, Literal, Union

from agentscope.formatter import OpenAIResponseFormatter
from pydantic import Field, SecretStr
from openai import AsyncOpenAI

from agentscope.credential import OpenAICredential
from agentscope.model import OpenAIResponseModel, OpenAIChatModel
from agentscope.model import ChatResponse
from agentscope.message import ThinkingBlock

from core.config import RuntimeConfig


logger = logging.getLogger(__name__)

# 思考强度：前端可选的思考深度，映射到 DeepSeek 的 reasoning_effort。
THINKING_INTENSITIES: tuple[str, ...] = ("off", "low", "medium", "high")
_INTENSITY_TO_EFFORT: dict[str, str] = {
    "off": "none",
    "low": "low",
    "medium": "high",
    # DeepSeek Responses API 接受的取值：none/minimal/low/medium/high/xhigh；
    # 不含 "max"（会导致 400 校验失败），最高档应为 xhigh。
    "high": "xhigh",
}

# DeepSeek 视觉模型名。
VISION_MODEL = "deepseek-v4-flash-vision-exp"


class DeepSeekResponseFormatter(OpenAIResponseFormatter):
    """Formatter that ensures ThinkingBlock carries a reasoning_item_id.

    DeepSeek's Responses API uses ``reasoning_text.delta`` (mapped to
    ``reasoning_summary_text.delta``) but may not populate a reasoning
    item in ``response.completed.output``.  Without a
    ``reasoning_item_id`` the upstream ``OpenAIResponseFormatter`` skips
    the thinking block silently, so the next request omits the reasoning
    text and DeepSeek returns 400.

    This formatter patches any ``ThinkingBlock`` that has content but
    no ``reasoning_item_id`` before delegating to the parent formatter.
    """

    async def format(self, msgs):
        """Ensure every non-empty ThinkingBlock has a reasoning_item_id."""
        from agentscope._utils._common import _generate_id

        for msg in msgs:
            for block in msg.get_content_blocks():
                if isinstance(block, ThinkingBlock) and block.thinking:
                    if not getattr(block, "reasoning_item_id", None):
                        block.reasoning_item_id = _generate_id()
        return await super().format(msgs)


class _ResponseEventAlias:
    """Expose a compatible event type while preserving the original payload."""

    def __init__(self, event: Any, event_type: str) -> None:
        self._event = event
        self.type = event_type

    def __getattr__(self, name: str) -> Any:
        return getattr(self._event, name)


class _SyntheticResponseEvent:
    """由 response.completed 的完整输出补出的兼容流事件。"""

    def __init__(self, event_type: str, **payload: Any) -> None:
        self.type = event_type
        for key, value in payload.items():
            setattr(self, key, value)


class DeepSeekResponsesModel(OpenAIResponseModel):
    """DeepSeek Responses API 模型，内置服务端联网搜索 (web_search) 开关。

    DeepSeek 的 Responses API 支持服务端联网搜索工具
    ``{"type": "web_search"}``：搜索由服务端执行，结果自动拼回上下文，
    无需本地实现函数。``web_search=True`` 时每次请求都会在 ``tools``
    中注入该工具，由模型自主决定是否联网；``web_search=False`` 时不注入。

    ``vision=True`` 时指向视觉模型（``deepseek-v4-flash-vision-exp``），
    消息内容块中的图片会以 ``input_image`` 形式传入。
    """

    class Parameters(OpenAIResponseModel.Parameters):
        """DeepSeek Responses API 参数。

        ``reasoning_effort`` 支持 DeepSeek 的取值：``none`` / ``low`` /
        ``high`` / ``max``（``none`` 表示关闭思考模式）。
        """

        reasoning_effort: Literal[
            "none", "minimal", "low", "medium", "high", "xhigh", "max",
        ] | None = Field(
            default=None,
            title="Reasoning Effort",
            description=(
                "Controls the depth of reasoning. Supported values: "
                "none (disable), low, high, max."
            ),
        )

    def __init__(
        self,
        credential: OpenAICredential,
        model: str,
        parameters: "DeepSeekResponsesModel.Parameters | None" = None,
        web_search: bool = False,
        gateway_mode: str = "base_url",
        native_tools: list[dict[str, Any]] | None = None,
        reasoning_wire_format: str = "responses",
        vision: bool = False,
        **kwargs,
    ) -> None:
        """初始化 DeepSeek Responses API 模型。

        Args:
            credential: OpenAI 兼容凭证（指向 DeepSeek base_url）。
            model: DeepSeek 模型名（默认支持 deepseek-v4-flash / V4 Pro / 视觉模型）。
            parameters: Responses API 参数。
            web_search: 是否注入服务端联网搜索工具。
            gateway_mode: 网关端点模式。
            native_tools: 模型原生工具列表。
            reasoning_wire_format: 推理线协议（responses / zhipu，保留兼容）。
            vision: 是否启用视觉（使用 ``input_image`` 内容块）。
            **kwargs: 透传给 OpenAIResponseModel 的其他参数。
        """
        # 默认为 DeepSeek 使用能补全 reasoning_item_id 的 formatter
        kwargs.setdefault("formatter", DeepSeekResponseFormatter())
        super().__init__(
            credential=credential,
            model=model,
            parameters=parameters or self.Parameters(),
            **kwargs,
        )
        self.web_search_enabled = web_search
        self.native_tools = list(native_tools or [])
        if reasoning_wire_format not in {"responses", "zhipu"}:
            raise ValueError("reasoning_wire_format 仅支持 responses 或 zhipu")
        self.reasoning_wire_format = reasoning_wire_format
        if gateway_mode not in {"base_url", "full_endpoint"}:
            raise ValueError("DeepSeek gateway_mode 仅支持 base_url 或 full_endpoint")
        self.gateway_mode = gateway_mode
        self.vision = vision

    async def _call_api(
        self,
        model_name: str,
        messages,
        tools=None,
        tool_choice=None,
        **generate_kwargs: Any,
    ):
        """调用 Responses API，并支持完整资源端点网关。

        平台若以 ``https://api.deepseek.com/responses`` 注册渠道，网关根
        路径已映射到上游 Responses 资源。此时不能再请求 ``/responses``，
        否则会形成重复路径；通过 OpenAI 客户端底层 post 保留同一请求体，
        仅切换请求路径。
        """
        formatted_messages = await self.formatter.format(messages)
        api_kwargs: dict[str, Any] = {
            "model": model_name,
            "input": formatted_messages,
            "stream": self.stream,
        }
        if self.parameters.max_tokens is not None:
            api_kwargs["max_output_tokens"] = self.parameters.max_tokens
        if self.parameters.temperature is not None:
            api_kwargs["temperature"] = self.parameters.temperature
        if self.parameters.thinking_enable and self.parameters.reasoning_effort:
            api_kwargs["reasoning"] = {"effort": self.parameters.reasoning_effort}
        api_kwargs.update({
            k: v for k, v in generate_kwargs.items()
            if k not in {"modalities", "audio"}
        })
        fmt_tools, fmt_tool_choice = self._format_tools(tools, tool_choice)
        if fmt_tools is not None:
            api_kwargs["tools"] = fmt_tools
        # thinking 模式下 DeepSeek/Zhipu 不支持 tool_choice 参数；
        # 省略时语义等价于 "auto"，模型自主决定是否调用工具。
        if fmt_tool_choice is not None and not self.parameters.thinking_enable:
            api_kwargs["tool_choice"] = fmt_tool_choice

        from datetime import datetime
        from openai.types.responses import Response, ResponseStreamEvent
        from openai import AsyncStream

        start_datetime = datetime.now()
        request_path = "/" if self.gateway_mode == "full_endpoint" else "/responses"
        response = await self.client.post(
            request_path,
            cast_to=Response,
            body=api_kwargs,
            stream=self.stream,
            stream_cls=AsyncStream[ResponseStreamEvent] if self.stream else None,
        )
        if self.stream:
            return self._parse_stream_response(start_datetime, response)
        return self._parse_completion_response(start_datetime, response)

    def _format_tools(self, tools, tool_choice):
        """保留 AgentScope 函数工具，并在无函数工具时注入模型原生工具。"""
        fmt_tools, fmt_tool_choice = super()._format_tools(tools, tool_choice)
        if fmt_tools:
            return fmt_tools, fmt_tool_choice
        native = list(self.native_tools)
        if self.web_search_enabled and not native:
            native = [{"type": "web_search"}]
        if native:
            return native, fmt_tool_choice or "auto"
        return fmt_tools, fmt_tool_choice

    async def _parse_stream_response(
        self,
        start_datetime,
        response,
    ) -> AsyncGenerator[ChatResponse, None]:
        """Accept DeepSeek's current reasoning_text streaming event name."""

        async def normalized_events():
            saw_text_delta = False
            saw_reasoning_delta = False
            added_tool_items: set[str] = set()
            argument_tool_items: set[str] = set()
            async for event in response:
                event_type = getattr(event, "type", "")
                if event_type in {
                    "response.reasoning_text.delta",
                    "response.reasoning.delta",
                    "response.reasoning_content.delta",
                    "response.thinking.delta",
                }:
                    saw_reasoning_delta = True
                    yield _ResponseEventAlias(
                        event,
                        "response.reasoning_summary_text.delta",
                    )
                elif event_type in {
                    "response.text.delta",
                    "response.message.delta",
                    "response.content.delta",
                }:
                    saw_text_delta = True
                    yield _ResponseEventAlias(event, "response.output_text.delta")
                elif event_type == "response.output_text.delta":
                    saw_text_delta = True
                    yield event
                elif event_type == "response.reasoning_summary_text.delta":
                    saw_reasoning_delta = True
                    yield event
                elif event_type == "response.output_item.added":
                    item = getattr(event, "item", None)
                    item_id = str(getattr(item, "id", "") or "")
                    if item_id:
                        added_tool_items.add(item_id)
                    yield event
                elif event_type == "response.function_call_arguments.delta":
                    item_id = str(getattr(event, "item_id", "") or "")
                    if item_id:
                        argument_tool_items.add(item_id)
                    yield event
                elif event_type == "response.completed":
                    # 部分 GLM Responses 兼容网关只发送 completed，未发送
                    # output_text/function arguments 增量。AgentScope 原解析器
                    # 只从增量构建最终 Msg，因此在 completed 前补齐缺失块。
                    completed = getattr(event, "response", None)
                    for item in getattr(completed, "output", []) or []:
                        item_type = getattr(item, "type", None)
                        if item_type == "message" and not saw_text_delta:
                            for part in getattr(item, "content", []) or []:
                                text = str(getattr(part, "text", "") or "")
                                if text:
                                    yield _SyntheticResponseEvent(
                                        "response.output_text.delta", delta=text,
                                    )
                                    saw_text_delta = True
                        elif item_type == "reasoning" and not saw_reasoning_delta:
                            summary = " ".join(
                                str(getattr(part, "text", "") or "")
                                for part in getattr(item, "summary", []) or []
                                if getattr(part, "text", "")
                            )
                            if summary:
                                yield _SyntheticResponseEvent(
                                    "response.reasoning_summary_text.delta",
                                    delta=summary,
                                )
                                saw_reasoning_delta = True
                        elif item_type == "function_call":
                            item_id = str(getattr(item, "id", "") or "")
                            if item_id and item_id not in added_tool_items:
                                yield _SyntheticResponseEvent(
                                    "response.output_item.added", item=item,
                                )
                                added_tool_items.add(item_id)
                            arguments = str(getattr(item, "arguments", "") or "")
                            if item_id and arguments and item_id not in argument_tool_items:
                                yield _SyntheticResponseEvent(
                                    "response.function_call_arguments.delta",
                                    item_id=item_id,
                                    delta=arguments,
                                )
                                argument_tool_items.add(item_id)
                    yield event
                else:
                    yield event

        async for chunk in super()._parse_stream_response(
            start_datetime,
            normalized_events(),
        ):
            yield chunk


def resolve_thinking_intensity(intensity: str | None) -> tuple[bool, str | None]:
    """把思考强度映射为 ``(thinking_enable, reasoning_effort)``。

    Args:
        intensity: off / low / medium / high；None 时按 medium 处理。
    Returns:
        ``(思考是否启用, reasoning_effort)``。
    """
    intensity = (intensity or "medium").strip().lower()
    if intensity not in _INTENSITY_TO_EFFORT:
        raise ValueError(
            f"不支持的思考强度: {intensity}，可选 "
            + ", ".join(THINKING_INTENSITIES),
        )
    effort = _INTENSITY_TO_EFFORT.get(intensity)
    return (intensity != "off"), effort


def DeepSeek(
        model: str | None = None,
        thinking_intensity: str = "medium",
        temperature: float | None = None,
        web_search: bool | None = None,
        vision: bool = False,
        config: RuntimeConfig | None = None,
) -> DeepSeekResponsesModel:
    """创建 DeepSeek 模型，自带联网搜索开关（可开关）与视觉支持。

    选型流程：选择模型供应商 → 选择模型 → 选择思考强度 → 确认。
    ``model`` 为空时回退到提供商默认模型（视觉请求时回退到视觉模型）。

    Args:
        model: 具体模型名。None 时读取提供商默认。
        thinking_intensity: 思考强度（off/low/medium/high）。
        temperature: 温度参数（思考模式下被服务端忽略）。
        web_search: 是否启用服务端联网搜索。None 时读取环境变量
            DEEPSEEK_WEB_SEARCH（1/true/yes/on 视为开启），默认关闭。
        vision: 是否启用视觉（使用视觉模型并允许图片内容块）。
        config: 运行时配置。

    Returns:
        DeepSeekResponsesModel 实例。
    """
    runtime = config or RuntimeConfig.from_env()
    settings = runtime.model_settings("deepseek")
    temperature = float(settings.get("temperature", 0.7)) if temperature is None else temperature
    max_tokens = int(settings.get("max_tokens", 0) or 0) or None
    max_retries = int(settings.get("max_retries", 3))
    context_size = int(settings.get("context_size", 128000))
    timeout_seconds = float(settings.get("timeout_seconds", 600))
    think, effort = resolve_thinking_intensity(thinking_intensity)
    if web_search is None:
        web_search = runtime.deepseek_web_search

    if vision:
        model_name = model or VISION_MODEL
    else:
        model_name = model or runtime.default_model("deepseek")

    return DeepSeekResponsesModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("deepseek")),
            base_url=runtime.get_base_url("deepseek"),
        ),
        model=model_name,
        parameters=DeepSeekResponsesModel.Parameters(
            thinking_enable=think,
            reasoning_effort=effort,
            temperature=temperature,
            max_tokens=max_tokens,
        ),
        web_search=web_search,
        gateway_mode=runtime.deepseek_gateway_mode,
        native_tools=[{"type": name} for name in runtime.deepseek_native_tools],
        vision=vision,
        stream=True,
        max_retries=max_retries,
        context_size=context_size,
        client_kwargs={"timeout": timeout_seconds},
    )


def OpenAICompatible(
        provider: str,
        model: str | None = None,
        thinking_intensity: str = "medium",
        temperature: float | None = None,
        config: RuntimeConfig | None = None,
) -> OpenAIChatModel:
    """创建 Superadmin 注册的通用 OpenAI-compatible Chat Model。

    统一走 Chat Completions，思考强度经 ``resolve_thinking_intensity``
    映射后作为 ``reasoning_effort`` 传递。
    """
    runtime = config or RuntimeConfig.from_env()
    provider_config = runtime.custom_llm_configs.get(provider)
    if not provider_config:
        raise ValueError(f"模型提供商未启用或不存在: {provider}")
    settings = runtime.model_settings(provider)
    temperature = float(settings.get("temperature", 0.7)) if temperature is None else temperature
    think, effort = resolve_thinking_intensity(thinking_intensity)
    max_tokens = int(settings.get("max_tokens", 0) or 0) or None
    credential = OpenAICredential(
        api_key=SecretStr(runtime.get_api_key(provider)),
        base_url=runtime.get_base_url(provider),
    )
    return OpenAIChatModel(
        credential=credential,
        model=model or provider_config.get("model_name") or "",
        parameters=OpenAIChatModel.Parameters(
            temperature=temperature,
            top_p=float(settings.get("top_p", 0.95)),
            thinking_enable=think,
            reasoning_effort=effort,
            max_tokens=max_tokens,
            parallel_tool_calls=False,
        ),
        stream=True,
        max_retries=int(settings.get("max_retries", 3)),
        context_size=int(settings.get("context_size", 128000)),
        client_kwargs={"timeout": float(settings.get("timeout_seconds", 600))},
    )


def create_model(
        provider: str = "deepseek",
        model: str | None = None,
        thinking_intensity: str = "medium",
        temperature: float | None = None,
        web_search: bool | None = None,
        vision: bool = False,
        config: RuntimeConfig | None = None,
) -> Any:
    """统一的模型工厂入口。

    Args:
        provider: 提供商 — "deepseek" 或自定义 OpenAI-compatible 标识。
        model: 具体模型名；None 时使用提供商默认模型。
        thinking_intensity: 思考强度（off/low/medium/high）。
        temperature: 温度参数。
        web_search: 是否启用 DeepSeek 服务端联网搜索（仅 deepseek 生效，
            None 时读取 DEEPSEEK_WEB_SEARCH 环境变量，默认关闭）。
        config: 运行时配置。

    Returns:
        DeepSeekResponsesModel 或 OpenAIChatModel 实例。
    """
    if provider == "deepseek":
        return DeepSeek(
            model=model, thinking_intensity=thinking_intensity,
            temperature=temperature, web_search=web_search, vision=vision,
            config=config,
        )
    return OpenAICompatible(
        provider=provider, model=model,
        thinking_intensity=thinking_intensity, temperature=temperature,
        config=config,
    )
