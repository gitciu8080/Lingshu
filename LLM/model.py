"""AgentScope 2.x 模型工厂 — DeepSeek + Qwen (llama.cpp 兼容)。

思考级别:
  Low → 快速响应 / 低推理深度
  Min → 默认平衡（默认）
  Max → 深度推理 / 强思考链

DeepSeek 走 Responses API（联网搜索工具仅在该 API 下可用），
通过 web_search 参数（或环境变量 DEEPSEEK_WEB_SEARCH）开启/关闭
服务端内置联网搜索。
"""
from typing import Any, AsyncGenerator, Literal, Union

from pydantic import Field, SecretStr

from agentscope.credential import DeepSeekCredential, OpenAICredential
from agentscope.model import DeepSeekChatModel, OpenAIResponseModel, OpenAIChatModel
from agentscope.model import ChatResponse

from config import RuntimeConfig


class _ResponseEventAlias:
    """Expose a compatible event type while preserving the original payload."""

    def __init__(self, event: Any, event_type: str) -> None:
        self._event = event
        self.type = event_type

    def __getattr__(self, name: str) -> Any:
        return getattr(self._event, name)


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
            model: DeepSeek 模型名（Responses API 仅支持 deepseek-v4-flash）。
            parameters: Responses API 参数。
            web_search: 是否注入服务端联网搜索工具。
            **kwargs: 透传给 OpenAIResponseModel 的其他参数。
        """
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


def DeepSeek(
        Ver: str = "Min",
        think: bool = True,
        temperature: float = 0.7,
        web_search: bool | None = None,
        config: RuntimeConfig | None = None,
) -> Union[DeepSeekResponsesModel, DeepSeekChatModel]:
    """创建 DeepSeek 模型，自带联网搜索开关（可开关）。

    模型选择：
      - 模型名在 ``deepseek_responses_models`` 内（默认仅 deepseek-v4-flash）
        → 走 Responses API（``DeepSeekResponsesModel``），联网搜索可用；
      - 其他模型（如 deepseek-v4-pro）→ 自动回退到普通
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
        DeepSeekResponsesModel（flash）或 DeepSeekChatModel（pro）实例。
    """
    runtime = config or RuntimeConfig.from_env()
    if web_search is None:
        web_search = runtime.deepseek_web_search

    model_name = runtime.model_name(Ver, provider="deepseek")

    # 非 Responses API 模型（如 pro）→ 回退到普通 Chat Completions，
    # 联网搜索仅 Responses API 提供，此处忽略 web_search 开关。
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
        repeat_penalty: float | None = None,
        config: RuntimeConfig | None = None,
) -> OpenAIChatModel:
    """创建 Qwen 模型（llama.cpp OpenAI 兼容 API）。

    思考能力通过 extra_body 传递 llama.cpp 原生参数:
      Low  → chat_template_kwargs.enable_thinking=false (快速、低延迟)
      Min  → enable_thinking=true + thinking_budget_tokens=4096 (默认平衡)
      Max  → enable_thinking=true + thinking_budget_tokens=8192 (深度推理)

    重复惩罚通过 llama.cpp 原生 repeat_penalty 传递（>1.0 惩罚重复 token，
    调高可抑制模型重复输出残缺/空洞的 <tool_call> 等标签）。
    Args:
        Ver: 思考级别（Low/Min/Max）。
        temperature: 温度参数。
        repeat_penalty: 重复惩罚系数；None 时读取 config.qwen_repeat_penalty。
        config: 运行时配置。
    """
    runtime = config or RuntimeConfig.from_env()
    model_name = runtime.model_name(Ver, provider="qwen")
    penalty = runtime.qwen_repeat_penalty if repeat_penalty is None else repeat_penalty

    # 思考级别 → 推理参数
    # max_tokens 限制总输出（思考+回答），必须 > thinking_budget_tokens，
    # 否则思考链会吃满输出额度导致最终回答被截断。
    _think_levels = {
        "Low": {"enable_thinking": False, "budget": 2048, "max_tokens": 2048},
        "Min": {"enable_thinking": True,  "budget": 4096, "max_tokens": 8192},
        "Max": {"enable_thinking": True,  "budget": 8192, "max_tokens": 16384},
    }
    level = _think_levels.get(Ver, _think_levels["Min"])

    return OpenAIChatModel(
        credential=OpenAICredential(
            api_key=SecretStr(runtime.get_api_key("qwen")),
            base_url=runtime.get_base_url("qwen"),
        ),
        model=model_name,
        parameters=OpenAIChatModel.Parameters(
            temperature=temperature,
            max_tokens=level["max_tokens"],
        ),
        extra_body={
            "reasoning_format": "auto",
            "chat_template_kwargs": {
                "enable_thinking": level["enable_thinking"],
            },
            "thinking_budget_tokens": level["budget"],
            "repeat_penalty": penalty,
            "reasoning_control": True,
            "return_progress": True,
            "timings_per_token": True,
        },
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
