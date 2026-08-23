"""AgentScope 2.x 模型工厂 — DeepSeek Responses（含视觉）+ Qwen/GLM。

思考级别:
  Low → 快速响应 / 低推理深度
  Min → 默认平衡（默认）
  Max → 深度推理 / 强思考链

DeepSeek 走 Responses API（联网搜索工具仅在该 API 下可用），
通过 web_search 参数（或环境变量 DEEPSEEK_WEB_SEARCH）开启/关闭
服务端内置联网搜索。``deepseek-v4-flash-vision-exp`` 额外接受图片输入。
"""
import logging
from typing import Any, AsyncGenerator, Literal, Union

from agentscope.formatter import (
    OpenAIResponseFormatter,
    OpenAIMultiAgentFormatter,
)
from pydantic import Field, SecretStr
from openai import AsyncOpenAI

from agentscope.credential import DeepSeekCredential, OpenAICredential
from agentscope.model import DeepSeekChatModel, OpenAIResponseModel, OpenAIChatModel
from agentscope.model import ChatResponse
from agentscope.message import ThinkingBlock

from core.config import RuntimeConfig


logger = logging.getLogger(__name__)

THINKING_INTENSITIES: tuple[str, ...] = ("off", "low", "medium", "high")
_INTENSITY_TO_EFFORT: dict[str, str] = {
    "off": "none",
    "low": "low",
    "medium": "high",
    "high": "max",
}
VISION_MODEL = "deepseek-v4-flash-vision-exp"


def resolve_thinking_intensity(intensity: str | None) -> tuple[bool, str]:
    """把 Web 思考强度映射为 DeepSeek Responses 的开关与 effort。"""
    normalized = (intensity or "medium").strip().lower()
    if normalized not in _INTENSITY_TO_EFFORT:
        raise ValueError(
            f"不支持的思考强度: {intensity}，可选 "
            + ", ".join(THINKING_INTENSITIES),
        )
    return normalized != "off", _INTENSITY_TO_EFFORT[normalized]


class QwenModelUnavailableError(RuntimeError):
    """Qwen 服务端没有可安全选择的已加载模型。"""


async def resolve_qwen_model(runtime: RuntimeConfig) -> tuple[str, bool]:
    """读取 llama.cpp ``/v1/models`` 并解析实际模型名。

    配置模型存在时原样使用；配置不存在且服务端仅加载一个模型时采用该
    唯一模型。零个模型、多个无法判定的模型或模型接口不可用都拒绝启动，
    避免请求被服务端隐式路由到不可审计的模型。

    Returns:
        ``(实际模型名, 是否发生别名解析)``。
    """
    client = AsyncOpenAI(
        api_key=runtime.get_api_key("qwen"),
        base_url=runtime.get_base_url("qwen"),
        timeout=15.0,
        max_retries=1,
    )
    try:
        response = await client.models.list()
    except Exception as exc:  # noqa: BLE001 - 转为任务启动的稳定错误类型
        raise QwenModelUnavailableError(
            f"无法读取 Qwen 模型列表 {runtime.get_base_url('qwen')}/models: {exc}",
        ) from exc
    finally:
        await client.close()

    model_ids = list(dict.fromkeys(
        str(getattr(item, "id", "")).strip()
        for item in getattr(response, "data", [])
        if str(getattr(item, "id", "")).strip()
    ))
    configured = runtime.qwen_model.strip()
    if configured in model_ids:
        return configured, False
    if len(model_ids) == 1:
        resolved = model_ids[0]
        logger.info("Qwen 模型别名解析: %s -> %s", configured, resolved)
        return resolved, True
    if not model_ids:
        raise QwenModelUnavailableError("Qwen 服务端当前没有已加载模型，拒绝启动任务")
    raise QwenModelUnavailableError(
        "配置的 Qwen 模型不存在，且服务端加载了多个模型，无法安全选择: "
        + ", ".join(model_ids),
    )


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


class DeepSeekResponsesModel(OpenAIResponseModel):
    """DeepSeek Responses API 模型，内置服务端联网搜索 (web_search) 开关。

    DeepSeek 的 Responses API 支持服务端联网搜索工具
    ``{"type": "web_search"}``：搜索由服务端执行，结果自动拼回上下文，
    无需本地实现函数。``web_search=True`` 时每次请求都会在 ``tools``
    中注入该工具，由模型自主决定是否联网；``web_search=False`` 时不注入。
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
            model: DeepSeek 模型名（含 deepseek-v4-flash-vision-exp）。
            parameters: Responses API 参数。
            web_search: 是否注入服务端联网搜索工具。
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
        self.vision = bool(vision or model == VISION_MODEL)

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
        has_images = any(
            part.get("type") == "input_image"
            for item in formatted_messages
            if isinstance(item, dict)
            for part in (
                item.get("content", [])
                if isinstance(item.get("content"), list)
                else []
            )
            if isinstance(part, dict)
        )
        if has_images and not self.vision:
            raise ValueError(
                "图片输入仅支持 deepseek-v4-flash-vision-exp，"
                f"当前模型为 {model_name}",
            )
        api_kwargs: dict[str, Any] = {
            "model": model_name,
            "input": formatted_messages,
            "stream": self.stream,
        }
        if self.parameters.max_tokens is not None:
            api_kwargs["max_output_tokens"] = self.parameters.max_tokens
        if self.parameters.temperature is not None:
            api_kwargs["temperature"] = self.parameters.temperature
        if self.reasoning_wire_format == "zhipu":
            # GLM Responses 仍沿用智谱原生推理参数：thinking + 顶层
            # reasoning_effort；请求主体则保持 OpenAI Responses 的 input。
            api_kwargs["thinking"] = {
                "type": "enabled" if self.parameters.thinking_enable else "disabled",
            }
            if self.parameters.thinking_enable and self.parameters.reasoning_effort:
                api_kwargs["reasoning_effort"] = self.parameters.reasoning_effort
        elif self.parameters.reasoning_effort:
            # DeepSeek Responses 默认开启思考；关闭时必须显式传 none，
            # 不能仅省略 reasoning，否则服务端会重新启用默认 high。
            api_kwargs["reasoning"] = {"effort": self.parameters.reasoning_effort}
        api_kwargs.update({
            k: v for k, v in generate_kwargs.items()
            if k not in {"modalities", "audio"}
        })
        fmt_tools, fmt_tool_choice = self._format_tools(tools, tool_choice)
        if fmt_tools is not None:
            api_kwargs["tools"] = fmt_tools
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

def DeepSeek(
        Ver: str = "Min",
        think: bool = True,
        temperature: float | None = None,
        web_search: bool | None = None,
        model_name: str | None = None,
        thinking_intensity: str | None = None,
        vision: bool = False,
        config: RuntimeConfig | None = None,
) -> Union[DeepSeekResponsesModel, DeepSeekChatModel]:
    """创建 DeepSeek 模型，自带联网搜索开关（可开关）。

    模型选择：
      - 模型名在 ``deepseek_responses_models`` 内（默认包含 V4 Flash / V4 Pro）
        → 走 Responses API（``DeepSeekResponsesModel``），联网搜索可用；
      - 其他模型 → 自动回退到普通
        ``DeepSeekChatModel``（Chat Completions），联网搜索不可用。

    Args:
        Ver: 思考级别（Low/Min/Max）。
        think: 是否启用思考链（False 时关闭思考）。
        temperature: 温度参数（思考模式下被服务端忽略）。
        web_search: 是否启用服务端联网搜索。None 时读取环境变量
            DEEPSEEK_WEB_SEARCH（1/true/yes/on 视为开启），默认关闭。
            仅 Responses API 模型生效，回退到 Chat Completions 时忽略。
        model_name: 显式选择的模型；为空时继续使用 Low/Min/Max 映射。
        thinking_intensity: Web 新版思考强度 off/low/medium/high；为空时
            保留旧版 Low/Min/Max 行为。
        vision: 强制选择 DeepSeek 实验视觉模型。
        config: 运行时配置。

    Returns:
        DeepSeekResponsesModel（默认 Flash / Pro）或 DeepSeekChatModel 实例。
    """
    runtime = config or RuntimeConfig.from_env()
    settings = runtime.model_settings("deepseek")
    temperature = float(settings.get("temperature", 0.7)) if temperature is None else temperature
    max_tokens = int(settings.get("max_tokens", 0) or 0) or None
    max_retries = int(settings.get("max_retries", 3))
    context_size = int(settings.get("context_size", 128000))
    timeout_seconds = float(settings.get("timeout_seconds", 600))
    if thinking_intensity is not None:
        think, _effort = resolve_thinking_intensity(thinking_intensity)
    else:
        if not think:
            _effort = "none"
        elif Ver == "Low":
            _effort = "low"
        elif Ver == "Min":
            _effort = "high"
        else:
            _effort = "max"
    think = think and bool(settings.get("thinking_enabled", True))
    if not think:
        _effort = "none"
    if web_search is None:
        web_search = runtime.deepseek_web_search

    selected_model = (
        runtime.deepseek_vision_model
        if vision
        else (str(model_name or "").strip() or runtime.model_name(Ver, provider="deepseek"))
    )
    is_vision = selected_model == runtime.deepseek_vision_model or selected_model == VISION_MODEL

    # 未被配置为 Responses API 的模型回退到 Chat Completions；联网搜索
    # 仅 Responses API 提供，此处忽略 web_search 开关。
    if selected_model not in runtime.deepseek_responses_models and not is_vision:
        return DeepSeekChatModel(
            credential=DeepSeekCredential(
                api_key=SecretStr(runtime.get_api_key("deepseek")),
                base_url=runtime.get_base_url("deepseek"),
            ),
            model=selected_model,
            parameters=DeepSeekChatModel.Parameters(
                thinking_enable=think,
                reasoning_effort=None if _effort == "none" else _effort,
                temperature=temperature,
                top_p=float(settings.get("top_p", 0.95)),
                max_tokens=max_tokens,
            ),
            stream=True,
            max_retries=max_retries,
            context_size=context_size,
            client_kwargs={"timeout": timeout_seconds},
        )

    return DeepSeekResponsesModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("deepseek")),
            base_url=runtime.get_base_url("deepseek"),
        ),
        model=selected_model,
        parameters=DeepSeekResponsesModel.Parameters(
            thinking_enable=think,
            reasoning_effort=_effort,
            temperature=temperature,
            max_tokens=max_tokens,
        ),
        web_search=web_search,
        gateway_mode=runtime.deepseek_gateway_mode,
        native_tools=[{"type": name} for name in runtime.deepseek_native_tools],
        vision=is_vision,
        stream=True,
        max_retries=max_retries,
        context_size=context_size,
        client_kwargs={"timeout": timeout_seconds},
    )


class ZhipuChatModel(OpenAIChatModel):
    """智谱 GLM Chat Completions 适配器。

    智谱通过 OpenAI 兼容端点承载 GLM 的 thinking、reasoning_effort、函数
    调用和 web_search 原生工具。完整代理 URL 不做拼接或重写。
    """

    class Parameters(OpenAIChatModel.Parameters):
        reasoning_effort: Literal[
            "none", "low", "medium", "high", "max",
        ] | None = None

    def __init__(self, *args, web_search: bool = False, native_tools=None,
                 gateway_mode: str = "base_url", **kwargs):
        self.web_search_enabled = web_search
        self.native_tools = list(native_tools or [])
        if gateway_mode not in {"base_url", "full_endpoint"}:
            raise ValueError("Zhipu gateway_mode 仅支持 base_url 或 full_endpoint")
        self.gateway_mode = gateway_mode
        super().__init__(*args, **kwargs)

    def _format_tools(self, tools, tool_choice):
        fmt_tools, fmt_tool_choice = super()._format_tools(tools, tool_choice)
        # 智谱文档规定函数、知识库、联网搜索能力互斥；已有函数工具优先。
        if fmt_tools:
            return fmt_tools, fmt_tool_choice
        if self.web_search_enabled or "web_search" in self.native_tools:
            return [{
                "type": "web_search",
                "web_search": {
                    "enable": True,
                    "search_engine": "search_pro",
                    "search_result": True,
                    "count": 10,
                    "content_size": "medium",
                },
            }], fmt_tool_choice or "auto"
        return fmt_tools, fmt_tool_choice

    async def _call_api(self, model_name, messages, tools=None, tool_choice=None,
                        **generate_kwargs):
        """在完整代理 URL 模式下请求网关根路径，避免重复追加资源路径。"""
        if self.gateway_mode != "full_endpoint":
            return await super()._call_api(
                model_name, messages, tools, tool_choice, **generate_kwargs,
            )
        # 与 AgentScope OpenAIChatModel 保持同一请求体和解析流程，只将
        # ``chat.completions.create`` 替换为客户端根路径 POST。
        from datetime import datetime
        from openai.types.chat import ChatCompletion, ChatCompletionChunk
        from openai import AsyncStream

        formatted_messages = await self.formatter.format(messages)
        kwargs = {"model": model_name, "messages": formatted_messages, "stream": self.stream}
        if self.parameters.max_tokens is not None:
            kwargs["max_completion_tokens"] = self.parameters.max_tokens
        if self.parameters.temperature is not None:
            kwargs["temperature"] = self.parameters.temperature
        if self.parameters.top_p is not None:
            kwargs["top_p"] = self.parameters.top_p
        if self.parameters.thinking_enable and self.parameters.reasoning_effort:
            kwargs["reasoning_effort"] = self.parameters.reasoning_effort
        if self.extra_body:
            kwargs.update(self.extra_body)
        kwargs.update(generate_kwargs)
        fmt_tools, fmt_tool_choice = self._format_tools(tools, tool_choice)
        if fmt_tools:
            kwargs["tools"] = fmt_tools
            if not self.parameters.parallel_tool_calls:
                kwargs["parallel_tool_calls"] = False
        if fmt_tool_choice is not None:
            kwargs["tool_choice"] = fmt_tool_choice
        if self.stream:
            kwargs["stream_options"] = {"include_usage": True}
        started = datetime.now()
        response = await self.client.post(
            "/", cast_to=ChatCompletion,
            body=kwargs, stream=self.stream,
            stream_cls=AsyncStream[ChatCompletionChunk] if self.stream else None,
        )
        if self.stream:
            return self._parse_stream_response(started, response)
        return self._parse_completion_response(started, response)


class ZhipuResponsesModel(DeepSeekResponsesModel):
    """GLM Responses API 适配器。

    使用 OpenAI Responses 的 ``input``、原生工具和流式事件协议，同时按
    智谱模型要求传递 ``thinking`` 与顶层 ``reasoning_effort``。
    """

    def __init__(self, *args, **kwargs):
        kwargs["reasoning_wire_format"] = "zhipu"
        super().__init__(*args, **kwargs)


def Zhipu(
        Ver: str = "Min",
        temperature: float | None = None,
        config: RuntimeConfig | None = None,
):
    """创建智谱 GLM 模型，按 Low/Min/Max 控制 thinking 与推理强度。"""
    runtime = config or RuntimeConfig.from_env()
    settings = runtime.model_settings("zhipu")
    model_name = runtime.model_name(Ver, provider="zhipu")
    temperature = float(settings.get("temperature", 0.7)) if temperature is None else temperature
    max_tokens = int(settings.get("max_tokens", 0) or 0) or None
    thinking_enabled = Ver != "Low" and bool(settings.get("thinking_enabled", True))
    effort = {"Low": "none", "Min": "high", "Max": "max"}[Ver]
    native_tools = [{"type": name} for name in runtime.zhipu_native_tools]
    # 内置 zhipu Provider 统一使用 Responses，避免网页选择、JSON 注册表和
    # 环境变量配置之间出现协议漂移。需要 Chat Completions 时应注册一个
    # 自定义 Provider 标识，由 OpenAICompatible 处理。
    return ZhipuResponsesModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("zhipu")),
            base_url=runtime.get_base_url("zhipu"),
        ),
        model=model_name,
        parameters=DeepSeekResponsesModel.Parameters(
            thinking_enable=thinking_enabled,
            reasoning_effort=effort,
            temperature=temperature,
            max_tokens=max_tokens,
        ),
        native_tools=native_tools,
        gateway_mode=runtime.zhipu_gateway_mode,
        stream=True,
        max_retries=int(settings.get("max_retries", 3)),
        context_size=int(settings.get("context_size", 200000)),
        client_kwargs={"timeout": float(settings.get("timeout_seconds", 600))},
    )


def Qwen(
        Ver: str = "Min",
        temperature: float | None = None,
        config: RuntimeConfig | None = None,
) -> OpenAIChatModel:
    """创建 Qwen 模型（llama.cpp OpenAI 兼容 API）。

    思考级别通过 ``chat_template_kwargs.enable_thinking`` 传递给 llama.cpp:
      Low  → 所有调用关闭 thinking
      Min  → 纯文本开启 thinking
      Max  → 纯文本开启 thinking + max_tokens=8192
        任意带 tools 的调用 → 强制关闭 thinking；simple 模式温度固定 0.1

    Args:
        Ver: 思考级别（Low/Min/Max）。
        temperature: 温度参数。
        config: 运行时配置。
    """
    runtime = config or RuntimeConfig.from_env()
    settings = runtime.model_settings("qwen")
    temperature = float(settings.get("temperature", 0.3)) if temperature is None else temperature
    max_tokens = int(settings.get("max_tokens", 0) or 0) or None
    model_name = runtime.model_name(Ver, provider="qwen")

    thinking_enable = Ver != "Low" and bool(settings.get("thinking_enabled", True))

    return OpenAIChatModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("qwen")),
            base_url=runtime.get_base_url("qwen"),
        ),
        model=model_name,
        parameters=OpenAIChatModel.Parameters(
            temperature=0.6,
            reasoning_effort="medium",
            thinking_enable=thinking_enable,
            top_p=0.95,
            max_tokens=max_tokens,



        ),
        stream=True,
        max_retries=int(settings.get("max_retries", 3))
    )


def OpenAICompatible(
        provider: str,
        Ver: str = "Min",
        temperature: float | None = None,
        config: RuntimeConfig | None = None,
) -> Union[OpenAIResponseModel, OpenAIChatModel]:
    """创建 Superadmin 注册的通用 OpenAI-compatible Chat Model。"""
    runtime = config or RuntimeConfig.from_env()
    provider_config = runtime.custom_llm_configs.get(provider)
    if not provider_config:
        raise ValueError(f"模型提供商未启用或不存在: {provider}")
    settings = runtime.model_settings(provider)
    temperature = float(settings.get("temperature", 0.7)) if temperature is None else temperature
    thinking_enable = Ver != "Low" and bool(settings.get("thinking_enabled", True))
    effort = {"Low": "none", "Min": "medium", "Max": "high"}.get(Ver, "medium")
    max_tokens = int(settings.get("max_tokens", 0) or 0) or None
    if provider == "zhipu":
        return Zhipu(Ver=Ver, temperature=temperature, config=runtime)
    common = {
        "credential": OpenAICredential(
            api_key=SecretStr(runtime.get_api_key(provider)),
            base_url=runtime.get_base_url(provider),
        ),
        "model": runtime.model_name(Ver, provider=provider),
        "stream": True,
        "max_retries": int(settings.get("max_retries", 3)),
        "context_size": int(settings.get("context_size", 128000)),
        "client_kwargs": {"timeout": float(settings.get("timeout_seconds", 600))},
    }
    if provider_config.get("api_style") == "responses":
        return DeepSeekResponsesModel(
            **common,
            parameters=DeepSeekResponsesModel.Parameters(
                temperature=temperature,
                thinking_enable=thinking_enable,
                reasoning_effort=effort if thinking_enable else None,
                max_tokens=max_tokens,
            ),
            native_tools=[{"type": name} for name in (provider_config.get("native_tools") or [])],
            gateway_mode=str(provider_config.get("gateway_mode") or "base_url"),
        )
    return OpenAIChatModel(
        **common,
        parameters=OpenAIChatModel.Parameters(
            temperature=temperature,
            top_p=float(settings.get("top_p", 0.95)),
            thinking_enable=thinking_enable,
            reasoning_effort=effort if thinking_enable else None,
            max_tokens=max_tokens,
            parallel_tool_calls=False,
        ),
    )


def create_model(
        provider: str = "deepseek",
        Ver: str = "Min",
        temperature: float | None = None,
        web_search: bool | None = None,
        model_name: str | None = None,
        thinking_intensity: str | None = None,
        vision: bool = False,
        config: RuntimeConfig | None = None,
):
    """统一的模型工厂入口。

    Args:
        provider: 提供商 — "deepseek" 或 "qwen"。
        Ver: 思考级别 — "Low" / "Min" / "Max"。
        temperature: 温度参数。
        web_search: 是否启用 DeepSeek 服务端联网搜索（仅 deepseek 生效，
            None 时读取 DEEPSEEK_WEB_SEARCH 环境变量，默认关闭）。
        config: 运行时配置。

    Returns:
        DeepSeekResponsesModel 或 OpenAIChatModel 实例。
    """
    if provider == "qwen":
        return Qwen(Ver=Ver, temperature=temperature, config=config)
    if provider == "zhipu":
        return Zhipu(Ver=Ver, temperature=temperature, config=config)
    if provider != "deepseek":
        return OpenAICompatible(
            provider=provider, Ver=Ver, temperature=temperature, config=config,
        )
    return DeepSeek(
        Ver=Ver, think=True, temperature=temperature,
        web_search=web_search, model_name=model_name,
        thinking_intensity=thinking_intensity, vision=vision, config=config,
    )
