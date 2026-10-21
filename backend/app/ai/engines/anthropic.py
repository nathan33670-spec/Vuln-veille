"""Claude, through the official ``anthropic`` SDK (spec 03 §3, ADR-011).

Kept ready for the day an API budget exists (ADR-025: no budget yet). Every request
goes through ``SafeHttpClient`` (``SafeHttpx2Transport``). Specifics handled here:
- adaptive thinking is the model's default on ``claude-opus-5-5`` and is never sent as
  disabled; the abstract reasoning level becomes ``output_config.effort``;
- structured output by ``output_config.format`` and strict tools; ``tool_choice``
  stays automatic (forcing a tool is refused by the current models);
- assistant turns are replayed with their original blocks (thinking included);
- a refusal is read from ``stop_reason`` before any content, and the server-side
  fallback (``fallbacks: "default"``) is opted into by default.
"""

from decimal import Decimal
from typing import Any

import anthropic
from anthropic import AsyncAnthropic, DefaultAsyncHttpxClient
from pydantic import Field

from app.ai.config import ALL_BUT_RED, DataClass, EngineConfig, ModelConfig
from app.ai.connector import EngineConnectorType
from app.ai.engines.transport import SafeHttpx2Transport, egress_cause
from app.ai.types import (
    AIConfigurationError,
    AIError,
    AIRateLimitedError,
    AIRequest,
    AIResponse,
    AIUnavailableError,
    Message,
    ModelCapabilities,
    ReasoningLevel,
    StopReason,
    ToolCall,
    Usage,
)
from app.connectors.base import (
    ConnectorContext,
    CostClass,
    Quotas,
    SecretSlot,
    register,
)
from app.core.narrow import expect
from app.net.safe_http import EgressDeniedError

API_BASE = "https://api.anthropic.com"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
EFFORT = {
    ReasoningLevel.LOW: "low",
    ReasoningLevel.MEDIUM: "medium",
    ReasoningLevel.HIGH: "high",
    ReasoningLevel.MAX: "max",
}
STOP = {
    "end_turn": StopReason.END_TURN,
    "stop_sequence": StopReason.END_TURN,
    "tool_use": StopReason.TOOL_USE,
    "max_tokens": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSAL,
}


def _default_models() -> list[ModelConfig]:
    return [
        ModelConfig(
            model_id="claude-opus-5-5",
            display_name="Claude Opus 5.5",
            context_window=1_000_000,
            max_output_tokens=128_000,
            reasoning_levels=list(ReasoningLevel),
            prompt_cache=True,
            price_input_per_mtok=Decimal("4.00"),
            price_output_per_mtok=Decimal("20.00"),
        )
    ]


class AnthropicConfig(EngineConfig):
    models: list[ModelConfig] = Field(default_factory=_default_models, min_length=1, max_length=20)
    data_classes: list[DataClass] = Field(
        default_factory=lambda: list(ALL_BUT_RED),
        description="Q6 : tout sauf TLP:RED",
    )
    refusal_fallback: bool = Field(
        default=True, description="Repli côté serveur sur un autre modèle en cas de refus"
    )

    def max_data_classes(self) -> tuple[DataClass, ...]:
        return ALL_BUT_RED


def _strict(schema: dict[str, Any]) -> bool:
    return schema.get("type") == "object" and schema.get("additionalProperties") is False


def _user_content(message: Message) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = [
        {
            "type": "tool_result",
            "tool_use_id": r.call_id,
            "content": r.content,
            **({"is_error": True} if r.is_error else {}),
        }
        for r in message.tool_results
    ]
    if message.text:
        blocks.append({"type": "text", "text": message.text})
    return blocks


def _assistant_content(message: Message) -> list[dict[str, Any]]:
    replay = (message.provider_state or {}).get("anthropic_content")
    if isinstance(replay, list) and replay:
        return replay
    blocks: list[dict[str, Any]] = []
    if message.text:
        blocks.append({"type": "text", "text": message.text})
    blocks.extend(
        {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
        for c in message.tool_calls
    )
    return blocks


class AnthropicEngine:
    def __init__(self, ctx: ConnectorContext) -> None:
        self.config = expect(ctx.config, AnthropicConfig)
        self.client = AsyncAnthropic(
            api_key=ctx.secrets["api_key"],
            base_url=API_BASE,
            http_client=DefaultAsyncHttpxClient(transport=SafeHttpx2Transport(ctx.http)),
            max_retries=1,
            timeout=float(self.config.timeout_seconds),
        )

    def capabilities(self, model: str) -> ModelCapabilities:
        declared = self.config.model(model)
        if declared is None:
            raise AIConfigurationError("unknown_model")
        return declared.capabilities()

    def _params(self, request: AIRequest) -> dict[str, Any]:
        caps = self.capabilities(request.model)
        system: list[dict[str, Any]] = [{"type": "text", "text": request.system}]
        if caps.prompt_cache:
            system[0]["cache_control"] = {"type": "ephemeral"}
        messages = [
            {
                "role": m.role,
                "content": _user_content(m) if m.role == "user" else _assistant_content(m),
            }
            for m in request.messages
        ]
        params: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_output_tokens,
            "system": system,
            "messages": messages,
        }
        if request.tools:
            params["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                    **({"strict": True} if _strict(t.parameters) else {}),
                }
                for t in request.tools
            ]
        output_config: dict[str, Any] = {}
        if request.reasoning_level in caps.reasoning_levels:
            output_config["effort"] = EFFORT[request.reasoning_level]
        if request.output_schema is not None and caps.structured_output == "native":
            output_config["format"] = {"type": "json_schema", "schema": request.output_schema}
        if output_config:
            params["output_config"] = output_config
        if self.config.refusal_fallback:
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        return params

    async def complete(self, request: AIRequest) -> AIResponse:
        params = self._params(request)
        try:
            response = await self.client.beta.messages.create(**params)
        except anthropic.RateLimitError as exc:
            raise AIRateLimitedError("rate_limited", _retry_after(exc.response.headers)) from None
        except (anthropic.InternalServerError, anthropic.OverloadedError) as exc:
            raise AIUnavailableError(f"http_{exc.status_code}") from None
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500:  # noqa: PLR2004
                raise AIUnavailableError(f"http_{exc.status_code}") from None
            raise AIConfigurationError(f"http_{exc.status_code}") from None
        except anthropic.APIConnectionError as exc:
            raise _connection_error(exc) from None
        return _parse(response)


def _retry_after(headers: Any) -> float | None:
    try:
        return float(headers.get("retry-after"))
    except (TypeError, ValueError):
        return None


def _connection_error(exc: BaseException) -> AIError:
    cause = egress_cause(exc)
    if isinstance(cause, EgressDeniedError):
        return AIConfigurationError(f"egress: {cause.code}")
    if cause is not None:
        return AIUnavailableError(f"egress: {cause.code}")
    return AIUnavailableError("network_error")


def _parse(response: Any) -> AIResponse:
    usage = response.usage
    tokens = Usage(
        input_tokens=usage.input_tokens or 0,
        output_tokens=usage.output_tokens or 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", None) or 0,
        cache_write_tokens=getattr(usage, "cache_creation_input_tokens", None) or 0,
    )
    if response.stop_reason == "refusal":  # checked before reading any content
        details = getattr(response, "stop_details", None)
        return AIResponse(
            stop_reason=StopReason.REFUSAL,
            usage=tokens,
            model_served=response.model,
            refusal_category=getattr(details, "category", None),
        )
    text = "".join(b.text for b in response.content if b.type == "text")
    calls = tuple(
        ToolCall(id=b.id, name=b.name, arguments=dict(b.input or {}))
        for b in response.content
        if b.type == "tool_use"
    )
    return AIResponse(
        stop_reason=STOP.get(response.stop_reason or "", StopReason.ERROR),
        text=text,
        tool_calls=calls,
        usage=tokens,
        model_served=response.model,
        provider_state={"anthropic_content": [b.to_dict() for b in response.content]},
    )


@register
class AnthropicConnector(EngineConnectorType):
    kind = "anthropic"
    label = "Claude (API Anthropic)"
    cost_class = CostClass.AI_BILLED
    config_model = AnthropicConfig
    secret_slots = (SecretSlot("api_key", "Clé API Anthropic"),)
    egress_domains = ("api.anthropic.com",)
    # No API budget yet (ADR-025): nothing is spent until an administrator sets one.
    default_quotas = Quotas(requests_per_minute=50, monthly_budget_eur=Decimal("0"))

    def engine(self, ctx: ConnectorContext) -> AnthropicEngine:
        return AnthropicEngine(ctx)
