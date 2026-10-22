"""Provider-neutral request, response and capability types of the AI engines."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Protocol


class ReasoningLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAX = "max"


class StopReason(StrEnum):
    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TOKENS = "max_tokens"
    REFUSAL = "refusal"
    ERROR = "error"


ToolsSupport = Literal["native", "emulated", "none"]
StructuredSupport = Literal["native", "guided_json", "none"]


@dataclass(frozen=True)
class ModelCapabilities:
    tools: ToolsSupport = "none"
    structured_output: StructuredSupport = "none"
    context_window: int = 8192
    max_output_tokens: int = 4096
    reasoning_levels: frozenset[ReasoningLevel] = frozenset()
    streaming: bool = False
    prompt_cache: bool = False
    # The engine's own web search (Claude web_search, Gemini Google Search grounding).
    web_search: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "tools": self.tools,
            "structured_output": self.structured_output,
            "context_window": self.context_window,
            "max_output_tokens": self.max_output_tokens,
            "reasoning_levels": sorted(self.reasoning_levels),
            "streaming": self.streaming,
            "prompt_cache": self.prompt_cache,
            "web_search": self.web_search,
        }


@dataclass(frozen=True)
class ToolSpec:
    """A read-only tool offered to the model; ``parameters`` is a JSON Schema object."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class Message:
    """One conversation turn. ``provider_state`` is opaque replay data an adapter needs
    to continue its own conversation (Claude thinking blocks, Gemini thought
    signatures); other adapters ignore it."""

    role: Literal["user", "assistant"]
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    provider_state: dict[str, Any] | None = None


@dataclass(frozen=True)
class WebSearch:
    """The engine's web search for this request, restricted to ``allowed_domains`` where
    the provider can (otherwise the caller filters the results by domain)."""

    allowed_domains: tuple[str, ...]
    max_uses: int = 2


@dataclass(frozen=True)
class WebResult:
    url: str
    title: str = ""


@dataclass(frozen=True)
class AIRequest:
    model: str
    system: str
    messages: tuple[Message, ...]
    tools: tuple[ToolSpec, ...] = ()
    output_schema: dict[str, Any] | None = None
    reasoning_level: ReasoningLevel = ReasoningLevel.MEDIUM
    max_output_tokens: int = 8192
    web_search: WebSearch | None = None


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    web_search_requests: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
            self.cache_write_tokens + other.cache_write_tokens,
            self.web_search_requests + other.web_search_requests,
        )


@dataclass(frozen=True)
class AIResponse:
    stop_reason: StopReason
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: Usage = field(default_factory=Usage)
    model_served: str = ""
    refusal_category: str | None = None
    provider_state: dict[str, Any] | None = None
    web_results: tuple[WebResult, ...] = ()

    def assistant_message(self) -> Message:
        return Message(
            role="assistant",
            text=self.text,
            tool_calls=self.tool_calls,
            provider_state=self.provider_state,
        )


class AIError(Exception):
    """An engine failure; ``code`` is stable and safe to store (no content, no secret)."""

    retryable = False

    def __init__(self, code: str, retry_after: float | None = None) -> None:
        super().__init__(code)
        self.code = code[:200]
        self.retry_after = retry_after


class AIRateLimitedError(AIError):
    retryable = True


class AIUnavailableError(AIError):
    retryable = True


class AIConfigurationError(AIError):
    """Bad credentials, unknown model, rejected request: retrying does not help."""


class AIEngine(Protocol):
    def capabilities(self, model: str) -> ModelCapabilities: ...

    async def complete(self, request: AIRequest) -> AIResponse: ...
