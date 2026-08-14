"""AgentScope 2.x 模型工厂 — DeepSeek + Qwen (llama.cpp 兼容)。

思考级别:
  Low → 快速响应 / 低推理深度
  Min → 默认平衡（默认）
  Max → 深度推理 / 强思考链

DeepSeek 走 Responses API（联网搜索工具仅在该 API 下可用），
通过 web_search 参数（或环境变量 DEEPSEEK_WEB_SEARCH）开启/关闭
服务端内置联网搜索。
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

from config import RuntimeConfig


logger = logging.getLogger(__name__)


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

        reasoning_effort: Literal["none", "low", "high", "max"] | None = Field(
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
        **kwargs,
    ) -> None:
        """初始化 DeepSeek Responses API 模型。

        Args:
            credential: OpenAI 兼容凭证（指向 DeepSeek base_url）。
            model: DeepSeek 模型名（默认支持 deepseek-v4-flash / deepseek-v4-pro）。
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

    async def _parse_stream_response(
        self,
        start_datetime,
        response,
    ) -> AsyncGenerator[ChatResponse, None]:
        """Accept DeepSeek's current reasoning_text streaming event name."""

        async def normalized_events():
            async for event in response:
                if event.type == "response.reasoning_text.delta":
                    yield _ResponseEventAlias(
                        event,
                        "response.reasoning_summary_text.delta",
                    )
                else:
                    yield event

        async for chunk in super()._parse_stream_response(
            start_datetime,
            normalized_events(),
        ):
            yield chunk

    def _format_tools(
        self,
        tools: list[dict] | None,
        tool_choice: object | None,
    ) -> tuple[list[dict] | None, object | None]:
        """在工具列表中注入服务端联网搜索工具（可开关）。"""
        fmt_tools, fmt_tool_choice = super()._format_tools(tools, tool_choice)
        if self.web_search_enabled:
            search_tool = [{"type": "web_search"}]
            fmt_tools = search_tool + (fmt_tools if fmt_tools else [])
        return fmt_tools, fmt_tool_choice


class QwenChatModel(OpenAIChatModel):
    """Qwen chat model that disables thinking on tool-calling turns.

    Qwen's llama.cpp tool parser can mix reasoning text into function
    arguments when thinking is enabled, producing malformed JSON. Pure text
    calls retain the configured thinking level.
    """

    async def _call_api(
        self,
        model_name: str,
        messages: list,
        tools: list[dict] | None = None,
        tool_choice=None,
        **generate_kwargs: Any,
    ):
        extra_body = dict(self.extra_body or {})
        template_kwargs = dict(
            extra_body.get("chat_template_kwargs") or {},
        )
        if tools:
            template_kwargs["enable_thinking"] = False
            # 工具调用固定低温，降低函数名/参数结构漂移概率。
            generate_kwargs["temperature"] = 0.1
            # 当前 Qwen GGUF 的模板声明支持并行工具调用，但本项目的计划、
            # 状态流转工具均是有序状态机。显式禁止并行，避免模型在同一轮
            # 交错 DeletePlan / UpdatePlan 等相互依赖的操作。
            generate_kwargs["parallel_tool_calls"] = False
            # 同时从 API 层关闭推理，而不只依赖 Jinja 的模板变量；部分
            # llama.cpp/Qwen 模板仍会预填 <think> 标签，二者配合可避免
            # 推理文本污染函数参数。
            generate_kwargs["reasoning_effort"] = "none"
        extra_body["chat_template_kwargs"] = template_kwargs
        generate_kwargs["extra_body"] = extra_body

        return await super()._call_api(
            model_name,
            messages,
            tools,
            tool_choice,
            **generate_kwargs,
        )


def DeepSeek(
        Ver: str = "Min",
        think: bool = True,
        temperature: float = 0.7,
        web_search: bool | None = None,
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
        config: 运行时配置。

    Returns:
        DeepSeekResponsesModel（默认 Flash / Pro）或 DeepSeekChatModel 实例。
    """
    runtime = config or RuntimeConfig.from_env()
    if web_search is None:
        web_search = runtime.deepseek_web_search

    model_name = runtime.model_name(Ver, provider="deepseek")

    # 未被配置为 Responses API 的模型回退到 Chat Completions；联网搜索
    # 仅 Responses API 提供，此处忽略 web_search 开关。
    if model_name not in runtime.deepseek_responses_models:
        if not think:
            _effort = None
        elif Ver in ("Low", "Min"):
            _effort = "high"
        else:
            _effort = "max"
        return DeepSeekChatModel(
            credential=DeepSeekCredential(
                api_key=SecretStr(runtime.get_api_key("deepseek")),
                base_url=runtime.get_base_url("deepseek"),
            ),
            model=model_name,
            parameters=DeepSeekChatModel.Parameters(
                thinking_enable=think,
                reasoning_effort=_effort,
                temperature=temperature,
            ),
            stream=True,
            max_retries=3,
            client_kwargs={"timeout": 600.0},
        )

    if not think:
        _effort = "none"
    elif Ver == "Low":
        _effort = "low"
    elif Ver == "Min":
        _effort = "high"
    else:
        _effort = "max"

    return DeepSeekResponsesModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("deepseek")),
            base_url=runtime.get_base_url("deepseek"),
        ),
        model=runtime.model_name(Ver, provider="deepseek"),
        parameters=DeepSeekResponsesModel.Parameters(
            thinking_enable=True,
            reasoning_effort=_effort,
            temperature=temperature,
        ),
        web_search=web_search,
        stream=True,
        max_retries=3,
        client_kwargs={"timeout": 600.0},
    )


def Qwen(
        Ver: str = "Min",
        temperature: float = 0.7,
        config: RuntimeConfig | None = None,
) -> OpenAIChatModel:
    """创建 Qwen 模型（llama.cpp OpenAI 兼容 API）。

    思考级别通过 ``chat_template_kwargs.enable_thinking`` 传递给 llama.cpp:
      Low  → 所有调用关闭 thinking
      Min  → 纯文本开启 thinking
      Max  → 纯文本开启 thinking + max_tokens=8192
      任意带 tools 的调用 → 强制关闭 thinking，温度固定 0.1

    Args:
        Ver: 思考级别（Low/Min/Max）。
        temperature: 温度参数。
        config: 运行时配置。
    """
    runtime = config or RuntimeConfig.from_env()
    model_name = runtime.model_name(Ver, provider="qwen")

    # 思考级别 → 推理参数
    # level = _think_levels.get(Ver, _think_levels["Min"])

    return OpenAIChatModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("qwen")),
            base_url=runtime.get_base_url("qwen"),
        ),
        model=model_name,
        parameters=OpenAIChatModel.Parameters(
            temperature=temperature,
            reasoning_effort="medium",
            thinking_enable=True,
            top_p=0.95,


        ),
        stream=True,
        max_retries=3,
        client_kwargs={"timeout": 600.0},
    )


def create_model(
        provider: str = "deepseek",
        Ver: str = "Min",
        temperature: float = 0.7,
        web_search: bool | None = None,
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
    return DeepSeek(
        Ver=Ver, think=True, temperature=temperature,
        web_search=web_search, config=config,
    )
