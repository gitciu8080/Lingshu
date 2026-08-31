"""AgentScope 2.x 多供应商模型工厂（供应商目录驱动）。

统一入口 :func:`create_model`：
    provider（或 provider::配置ID）→ 解析注册条目 → 按目录分发驱动。

驱动分发：
    anthropic / gemini / ollama / xai
                          → AgentScope 原生模型类 + 对应 Credential
    responses 协议        → DeepSeekResponsesModel（含 full_endpoint、
                            事件别名兼容、completed 补齐；智谱走 vendor
                            reasoning 线协议）
    chat_completions 协议 → GatewayChatModel（base_url / full_endpoint
                            双模式；按目录注入思考参数——智谱 thinking.type
                            使思考过程可见；原生工具线协议）

具体模型由注册表条目的 ``models`` 列表决定（Low/Min/Max 层级已废弃），
思考强度 off/low/medium/high 按供应商收敛。
"""
import logging
from typing import Any, AsyncGenerator, Literal
from urllib.parse import urlsplit

from agentscope.formatter import (
    OpenAIResponseFormatter,
    OpenAIMultiAgentFormatter,
)
from pydantic import Field, SecretStr
from openai import AsyncOpenAI

from agentscope.credential import (
    AnthropicCredential,
    GeminiCredential,
    OllamaCredential,
    OpenAICredential,
    XAICredential,
)
from agentscope.model import (
    AnthropicChatModel,
    GeminiChatModel,
    OllamaChatModel,
    OpenAIChatModel,
    OpenAIResponseModel,
    XAIChatModel,
)
from agentscope.model import ChatResponse
from agentscope.message import ThinkingBlock

from core.config import RuntimeConfig
from core.providers import (
    DEFAULT_LLM_SETTINGS,
    clamp_reasoning_effort,
    get_provider_spec,
    native_tool_wire_payloads,
    resolve_provider_thinking,
)


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


# 许多 OpenAI Responses 兼容网关会沿用不同的 delta 事件名（例如
# ``response.reasoning_content.delta``），而 AgentScope 2.0.6 的官方
# OpenAIResponseModel 仅消费标准 ``reasoning_summary_text`` / ``output_text``。
# 这里直接扩展该官方通用模型的输入流，不创建按厂商拆分的 Model 子类：只对
# 语义等价的事件名做标准化，既不修改请求体，也不修改 formatter/工具协议。
_OPENAI_RESPONSE_EVENT_ALIASES = {
    "response.reasoning_text.delta": "response.reasoning_summary_text.delta",
    "response.reasoning.delta": "response.reasoning_summary_text.delta",
    "response.reasoning_content.delta": "response.reasoning_summary_text.delta",
    "response.thinking.delta": "response.reasoning_summary_text.delta",
    "response.text.delta": "response.output_text.delta",
    "response.message.delta": "response.output_text.delta",
    "response.content.delta": "response.output_text.delta",
}


def _install_openai_responses_event_compatibility() -> None:
    """为 AgentScope 官方 ``OpenAIResponseModel`` 安装通用事件别名兼容。"""
    if getattr(OpenAIResponseModel, "_lingshu_event_compat_installed", False):
        return
    original = OpenAIResponseModel._parse_stream_response

    async def compatible_parse_stream_response(self, start_datetime, response):
        async def normalized_events():
            async for event in response:
                alias = _OPENAI_RESPONSE_EVENT_ALIASES.get(
                    str(getattr(event, "type", "")),
                )
                yield _ResponseEventAlias(event, alias) if alias else event

        async for chunk in original(self, start_datetime, normalized_events()):
            yield chunk

    OpenAIResponseModel._parse_stream_response = compatible_parse_stream_response
    OpenAIResponseModel._lingshu_event_compat_installed = True


_install_openai_responses_event_compatibility()


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

class GatewayChatModel(OpenAIChatModel):
    """统一 Chat Completions 网关驱动。

    - ``gateway_mode``：base_url → POST ``{base_url}/chat/completions``；
      full_endpoint → 平台把完整资源端点注册为网关，POST 根路径避免重复追加。
    - ``thinking_style``（来自供应商目录）：
      ``zhipu`` → 注入 ``thinking: {"type": enabled|disabled}``——这是
      chat_completions 思考过程可见性的关键：请求必须显式声明思考开关，
      服务端才会输出 reasoning_content 增量（AgentScope 解析器原生支持）；
      ``effort`` → 注入 ``reasoning_effort``（需 thinking_enable 且非空）；
      ``none`` → 不发送思考参数（本地 llama.cpp 等自行处理）。
    - ``native_tools``：目录层已按线协议整形好的原生工具负载，仅在无函数
      工具时注入（智谱规定函数与联网搜索互斥）。
    - ``extra_body``：附加请求体（DashScope enable_search 等）。
    """

    class Parameters(OpenAIChatModel.Parameters):
        reasoning_effort: Literal[
            "none", "minimal", "low", "medium", "high", "xhigh", "max",
        ] | None = None

    def __init__(
        self,
        *args,
        gateway_mode: str = "base_url",
        native_tools: list[dict[str, Any]] | None = None,
        thinking_style: str = "effort",
        extra_body: dict[str, Any] | None = None,
        **kwargs,
    ) -> None:
        if gateway_mode not in {"base_url", "full_endpoint"}:
            raise ValueError("gateway_mode 仅支持 base_url 或 full_endpoint")
        if thinking_style not in {"zhipu", "effort", "none"}:
            raise ValueError("thinking_style 仅支持 zhipu / effort / none")
        self.gateway_mode = gateway_mode
        self.native_tools = list(native_tools or [])
        self.thinking_style = thinking_style
        self.extra_body = dict(extra_body or {})
        super().__init__(*args, **kwargs)

    def _format_tools(self, tools, tool_choice):
        fmt_tools, fmt_tool_choice = super()._format_tools(tools, tool_choice)
        if fmt_tools:
            return fmt_tools, fmt_tool_choice
        if self.native_tools:
            return list(self.native_tools), fmt_tool_choice or "auto"
        return fmt_tools, fmt_tool_choice

    async def _call_api(self, model_name, messages, tools=None, tool_choice=None,
                        **generate_kwargs):
        """统一手动请求：保留 AgentScope 的请求体与解析流程，替换端点构造
        并按供应商目录注入思考参数。"""
        from datetime import datetime
        from openai.types.chat import ChatCompletion, ChatCompletionChunk
        from openai import AsyncStream

        formatted_messages = await self.formatter.format(messages)
        kwargs: dict[str, Any] = {
            "model": model_name, "messages": formatted_messages, "stream": self.stream,
        }
        if self.parameters.max_tokens is not None:
            kwargs["max_tokens"] = self.parameters.max_tokens
        if self.parameters.temperature is not None:
            kwargs["temperature"] = self.parameters.temperature
        if self.parameters.top_p is not None:
            kwargs["top_p"] = self.parameters.top_p
        if self.thinking_style == "zhipu":
            kwargs["thinking"] = {
                "type": "enabled" if self.parameters.thinking_enable else "disabled",
            }
            if self.parameters.thinking_enable and self.parameters.reasoning_effort:
                kwargs["reasoning_effort"] = self.parameters.reasoning_effort
        elif self.thinking_style == "effort":
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
        request_path = "/" if self.gateway_mode == "full_endpoint" else "/chat/completions"
        response = await self.client.post(
            request_path, cast_to=ChatCompletion,
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


# 兼容别名：历史代码与前端展示文案继续可用。
ZhipuChatModel = GatewayChatModel


def _merge_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    """条目 settings 与默认值合并，保证键完整。"""
    merged = dict(DEFAULT_LLM_SETTINGS)
    merged.update(settings or {})
    return merged


def _select_model_with_settings(
    entry: dict[str, Any],
    model: str | None,
    vision: bool,
    runtime: RuntimeConfig,
) -> tuple[str, dict[str, Any]]:
    """选择模型名与其超参数（每模型 settings 优先，缺失时用条目默认）。

    保留本地选择语义：qwen 走 llama.cpp 别名解析路径；请求视觉时优先
    选择条目登记的视觉模型。
    """
    models_detail = [
        dict(m) for m in (entry.get("models_detail") or []) if m.get("name")
    ]
    models = [str(m).strip() for m in (entry.get("models") or []) if str(m).strip()]
    vision_models = [
        str(m).strip() for m in (entry.get("vision_models") or []) if str(m).strip()
    ]
    provider_id = str(entry.get("provider") or "openai-compatible")
    if provider_id == "qwen":
        selected = runtime.qwen_model or (models[0] if models else "")
    else:
        selected = (
            str(model or "").strip()
            # 请求视觉且条目登记了多模态模型时，优先选择多模态模型
            or (vision_models[0] if vision and vision_models else "")
            or str(entry.get("model_name") or "").strip()
            or (models[0] if models else "")
        )
    if not selected:
        raise ValueError(
            f"模型配置 {entry.get('name') or provider_id} 未配置任何具体模型，"
            "请先在超级管理页添加模型",
        )
    detail = next((m for m in models_detail if m.get("name") == selected), None)
    settings = _merge_settings(
        detail.get("settings") if detail else entry.get("settings"),
    )
    return selected, settings


def _common_kwargs(settings: dict[str, Any]) -> dict[str, Any]:
    return dict(
        stream=True,
        max_retries=int(settings.get("max_retries") or 3),
        context_size=int(settings.get("context_size") or 128000),
        client_kwargs={"timeout": float(settings.get("timeout_seconds") or 600)},
    )


# ────────────────────────────────────────────────────────────────
# 原生驱动构建器（Anthropic / Gemini / Ollama / xAI）
# ────────────────────────────────────────────────────────────────

def _build_anthropic_model(
    entry: dict[str, Any],
    model_name: str,
    settings: dict[str, Any],
    think: bool,
    effort: str | None,
) -> AnthropicChatModel:
    parameters = AnthropicChatModel.Parameters(
        max_tokens=int(settings.get("max_tokens") or 0) or 8192,
        thinking_enable=think,
        thinking_budget=int(settings.get("thinking_budget") or 0) or None,
        reasoning_effort=effort,
    )
    return AnthropicChatModel(
        credential=AnthropicCredential(
            api_key=SecretStr(str(entry.get("api_key") or "")),
            base_url=str(entry.get("base_url") or "") or None,
        ),
        model=model_name,
        parameters=parameters,
        **_common_kwargs(settings),
    )


def _build_gemini_model(
    entry: dict[str, Any],
    model_name: str,
    settings: dict[str, Any],
    think: bool,
) -> GeminiChatModel:
    parameters = GeminiChatModel.Parameters(
        max_tokens=int(settings.get("max_tokens") or 0) or None,
        thinking_enable=think,
        thinking_budget=int(settings.get("thinking_budget") or 0) or None,
        temperature=float(settings.get("temperature") or 0.7),
        top_p=float(settings.get("top_p") or 0.95),
    )
    return GeminiChatModel(
        credential=GeminiCredential(api_key=SecretStr(str(entry.get("api_key") or ""))),
        model=model_name,
        parameters=parameters,
        # google-genai Client 不接受 timeout kwarg，改用 http_options（毫秒）。
        client_kwargs={
            "http_options": {
                "timeout": int(float(settings.get("timeout_seconds") or 600) * 1000),
            },
        },
        max_retries=int(settings.get("max_retries") or 3),
        context_size=int(settings.get("context_size") or 128000),
    )


def _build_ollama_model(
    entry: dict[str, Any],
    model_name: str,
    settings: dict[str, Any],
    think: bool,
) -> OllamaChatModel:
    parameters = OllamaChatModel.Parameters(
        max_tokens=int(settings.get("max_tokens") or 0) or None,
        thinking_enable=think,
        temperature=float(settings.get("temperature") or 0.7),
    )
    return OllamaChatModel(
        credential=OllamaCredential(
            host=str(entry.get("base_url") or "") or None,
        ),
        model=model_name,
        parameters=parameters,
        **_common_kwargs(settings),
    )


def _build_xai_model(
    entry: dict[str, Any],
    model_name: str,
    settings: dict[str, Any],
    think: bool,
    effort: str | None,
) -> XAIChatModel:
    parameters = XAIChatModel.Parameters(
        max_tokens=int(settings.get("max_tokens") or 0) or None,
        thinking_enable=think,
        reasoning_effort=effort,
        temperature=float(settings.get("temperature") or 0.7),
        top_p=float(settings.get("top_p") or 0.95),
    )
    api_host = ""
    base_url = str(entry.get("base_url") or "")
    if base_url:
        api_host = urlsplit(base_url).netloc or "api.x.ai"
    return XAIChatModel(
        credential=XAICredential(
            api_key=SecretStr(str(entry.get("api_key") or "")),
            api_host=api_host or "api.x.ai",
        ),
        model=model_name,
        parameters=parameters,
        **_common_kwargs(settings),
    )


def _build_model_from_entry(
    entry: dict[str, Any],
    model: str | None,
    thinking_intensity: str,
    temperature: float | None,
    web_search: bool | None,
    vision: bool,
    runtime: RuntimeConfig,
):
    """按供应商目录从统一条目构造模型实例（create_model 的执行体）。

    entry 由 ``RuntimeConfig.resolve_llm_entry`` 产生：注册表条目或内置
    provider 的 .env 合成条目，含 provider/api_style/base_url/api_key/
    gateway_mode/enabled_tools/settings/models/models_detail。驱动分发：
    anthropic/gemini/ollama/xai 走 AgentScope 原生模型类；其余（OpenAI
    兼容协议族）按条目 api_style 分发到 Responses / Chat 网关驱动。
    """
    provider_id = str(entry.get("provider") or "openai-compatible")
    spec = get_provider_spec(provider_id) or get_provider_spec("openai-compatible")
    assert spec is not None
    api_style = str(entry.get("api_style") or spec["default_api_style"])

    selected, settings = _select_model_with_settings(entry, model, vision, runtime)
    if temperature is not None:
        settings = {**settings, "temperature": float(temperature)}

    think, effort = resolve_provider_thinking(spec, thinking_intensity)
    think = think and bool(settings.get("thinking_enabled", True))
    if not think:
        effort = None
    elif provider_id == "deepseek" and api_style == "chat_completions":
        # DeepSeek Chat 协议仅接受 high/max 两档。
        effort = effort if effort in {"high", "max"} else (
            "max" if (thinking_intensity or "medium") == "high" else "high"
        )

    enabled_tools = [str(t) for t in (entry.get("native_tools") or entry.get("enabled_tools") or [])]
    if web_search is True:
        enabled_tools = list(dict.fromkeys([*enabled_tools, "web_search"]))
    elif web_search is False:
        enabled_tools = [t for t in enabled_tools if t != "web_search"]
    native_tools, extra_body = native_tool_wire_payloads(spec, api_style, enabled_tools)

    driver = str(spec.get("driver") or "")
    if driver == "anthropic":
        return _build_anthropic_model(entry, selected, settings, think, effort)
    if driver == "gemini":
        return _build_gemini_model(entry, selected, settings, think)
    if driver == "ollama":
        return _build_ollama_model(entry, selected, settings, think)
    if driver == "xai":
        return _build_xai_model(entry, selected, settings, think, effort)

    credential = OpenAICredential(
        api_key=SecretStr(str(entry.get("api_key") or "")),
        base_url=str(entry.get("base_url") or ""),
    )
    common = dict(
        stream=True,
        max_retries=int(settings["max_retries"] or 3),
        context_size=int(settings["context_size"] or 128000),
        client_kwargs={"timeout": float(settings["timeout_seconds"] or 600)},
    )
    gateway_mode = str(entry.get("gateway_mode") or "base_url")

    if api_style == "responses":
        return DeepSeekResponsesModel(
            credential=credential,
            model=selected,
            parameters=DeepSeekResponsesModel.Parameters(
                thinking_enable=think,
                reasoning_effort=effort,
                temperature=float(settings["temperature"]),
                max_tokens=int(settings["max_tokens"] or 0) or None,
            ),
            web_search=bool(web_search) if web_search is not None else False,
            gateway_mode=gateway_mode,
            native_tools=native_tools,
            reasoning_wire_format="zhipu" if provider_id == "zhipu" else "responses",
            vision=bool(vision or selected in (entry.get("vision_models") or [])),
            **common,
        )
    return GatewayChatModel(
        credential=credential,
        model=selected,
        parameters=GatewayChatModel.Parameters(
            temperature=float(settings["temperature"]),
            top_p=float(settings["top_p"] or 0.95),
            thinking_enable=think,
            reasoning_effort=effort,
            max_tokens=int(settings["max_tokens"] or 0) or None,
            parallel_tool_calls=False,
        ),
        gateway_mode=gateway_mode,
        native_tools=native_tools,
        thinking_style=str(spec.get("thinking_style") or "effort"),
        extra_body=extra_body or None,
        **common,
    )


_VER_TO_INTENSITY = {"Low": "off", "Min": "medium", "Max": "high"}


def create_model(
        provider: str = "deepseek",
        model: str | None = None,
        thinking_intensity: str | None = None,
        temperature: float | None = None,
        web_search: bool | None = None,
        vision: bool = False,
        config: RuntimeConfig | None = None,
        Ver: str | None = None,
        model_name: str | None = None,
):
    """统一的模型工厂入口（供应商目录驱动）。

    Args:
        provider: 运行时 key —— ``provider`` 或 ``provider::配置ID``（同一
            供应商多条启用时），必须是超级管理页已启用的配置；内置
            deepseek/zhipu/qwen 未在注册表启用时按 .env 合成条目回退。
        model: 具体模型名；为空时使用配置的默认（首个）模型。
        thinking_intensity: 思考强度 off/low/medium/high，按供应商目录收敛
            为 reasoning_effort 或 thinking.type 线协议。
        temperature: 温度覆盖（None 时使用配置的超参数）。
        web_search: 显式开关服务端联网搜索（None 时使用配置的原生工具开关）。
        vision: 是否请求视觉模型（仅对登记了视觉能力的供应商有意义）。
        config: 运行时配置。
        Ver: 已废弃的思考级别参数，仅为兼容保留（映射为思考强度）。
        model_name: ``model`` 的旧参数别名。

    Returns:
        DeepSeekResponsesModel（Responses 协议）或 GatewayChatModel
        （Chat Completions 协议）实例。
    """
    runtime = config or RuntimeConfig.from_env()
    entry = runtime.resolve_llm_entry(provider)
    if entry is None:
        raise ValueError(f"模型提供商未启用或不存在: {provider}")
    intensity = (
        (thinking_intensity or "").strip().lower()
        or _VER_TO_INTENSITY.get(str(Ver or "").strip(), "medium")
    )
    selected = str(model or model_name or "").strip() or None
    return _build_model_from_entry(
        entry, selected, intensity, temperature, web_search, vision, runtime,
    )


def create_vision_model(runtime: RuntimeConfig | None = None):
    """从模型注册表解析视觉模型并构建实例（多供应商通用）。

    仅当注册表中有启用配置登记了 ``vision_models``（如智谱 glm-5.3-flash
    被标记多模态）时返回视觉模型实例；否则返回 None——本部署即为纯文本
    大模型，调用方不挂载视觉工具。不存在 .env 回退。
    """
    runtime = runtime or RuntimeConfig.from_env()
    try:
        from core.model_registry import active_llm_providers

        for item in active_llm_providers(include_secrets=True):
            if item.get("api_key_status") == "invalid":
                continue
            vision_models = [
                str(m).strip() for m in (item.get("vision_models") or []) if str(m).strip()
            ]
            if not vision_models:
                continue
            entry = runtime.resolve_llm_entry(item["runtime_key"])
            if entry is None:
                continue
            return _build_model_from_entry(
                entry, vision_models[0], "medium", None, False, True, runtime,
            )
    except Exception as exc:  # noqa: BLE001 - 注册表故障不阻断任务启动
        logger.warning("从注册表解析视觉模型失败: %s", exc)
    # 无任何登记多模态模型的启用配置：本部署即为纯文本大模型，
    # 不支持视觉（返回 None，调用方不挂载视觉工具）。
    return None
