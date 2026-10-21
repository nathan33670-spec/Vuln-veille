"""Gemini, free tier of Google AI Studio, through the official ``google-genai`` SDK
(starting engine, ADR-025).

No billing is ever enabled on the Google project: beyond the free quotas requests
fail instead of being billed, and the connector's own quotas (requests per minute and
per day, Q35) stop them earlier. The free tier may reuse what it receives, so only
public and TLP:CLEAR data may be sent (Q6). Every request goes through
``SafeHttpClient`` (``SafeHttpxTransport``); the SDK's synchronous client is disabled.
"""

import base64
import json
from typing import Any

from google import genai
from google.genai import errors, types
from pydantic import Field

from app.ai.config import PUBLIC_ONLY, DataClass, EngineConfig, ModelConfig
from app.ai.connector import EngineConnectorType
from app.ai.engines.transport import (
    TRANSPORT_ERRORS,
    TransportEgressError,
    safe_httpx_clients,
)
from app.ai.types import (
    AIConfigurationError,
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
from app.connectors.base import ConnectorContext, CostClass, Quotas, SecretSlot, register
from app.core.narrow import expect
from app.net.safe_http import EgressDeniedError

API_BASE = "https://generativelanguage.googleapis.com"
THINKING = {
    ReasoningLevel.LOW: types.ThinkingLevel.LOW,
    ReasoningLevel.MEDIUM: types.ThinkingLevel.MEDIUM,
    ReasoningLevel.HIGH: types.ThinkingLevel.HIGH,
    ReasoningLevel.MAX: types.ThinkingLevel.HIGH,
}
REFUSALS = {
    "SAFETY",
    "RECITATION",
    "BLOCKLIST",
    "PROHIBITED_CONTENT",
    "SPII",
    "LANGUAGE",
    "IMAGE_SAFETY",
    "IMAGE_PROHIBITED_CONTENT",
}
SCHEMA_INSTRUCTION = (
    "\n\nQuand tu as fini d'utiliser les outils, réponds uniquement par un objet JSON "
    "conforme à ce schéma JSON :\n"
)


def _default_models() -> list[ModelConfig]:
    return [
        ModelConfig(
            model_id="gemini-2.5-flash",
            display_name="Gemini 2.5 Flash (palier gratuit)",
            context_window=1_000_000,
            max_output_tokens=65_536,
            reasoning_levels=[ReasoningLevel.LOW, ReasoningLevel.MEDIUM, ReasoningLevel.HIGH],
            price_input_per_mtok=None,
            price_output_per_mtok=None,
        )
    ]


class GeminiConfig(EngineConfig):
    models: list[ModelConfig] = Field(default_factory=_default_models, min_length=1, max_length=20)
    data_classes: list[DataClass] = Field(
        default_factory=lambda: list(PUBLIC_ONLY),
        description="Palier gratuit : données publiques et TLP:CLEAR uniquement (Q6)",
    )

    def max_data_classes(self) -> tuple[DataClass, ...]:
        return PUBLIC_ONLY


def _user_parts(message: Message) -> list[types.Part]:
    parts = [
        types.Part(
            function_response=types.FunctionResponse(
                id=r.call_id or None,
                name=r.name,
                response={"error": r.content} if r.is_error else {"result": r.content},
            )
        )
        for r in message.tool_results
    ]
    if message.text:
        parts.append(types.Part(text=message.text))
    return parts


def _assistant_parts(message: Message) -> list[types.Part]:
    replay = (message.provider_state or {}).get("gemini_parts")
    if isinstance(replay, list) and replay:
        return [_load_part(p) for p in replay]
    parts = [types.Part(text=message.text)] if message.text else []
    parts.extend(
        types.Part(function_call=types.FunctionCall(id=c.id, name=c.name, args=c.arguments))
        for c in message.tool_calls
    )
    return parts


def _dump_part(part: types.Part) -> dict[str, Any]:
    data = part.model_dump(mode="python", exclude_none=True)
    signature = data.pop("thought_signature", None)
    if isinstance(signature, bytes):
        data["thought_signature_b64"] = base64.b64encode(signature).decode()
    return data


def _load_part(data: dict[str, Any]) -> types.Part:
    data = dict(data)
    signature = data.pop("thought_signature_b64", None)
    if isinstance(signature, str):
        data["thought_signature"] = base64.b64decode(signature)
    return types.Part.model_validate(data)


class GeminiEngine:
    def __init__(self, ctx: ConnectorContext) -> None:
        self.config = expect(ctx.config, GeminiConfig)
        timeout = float(self.config.timeout_seconds)
        async_client, sync_client = safe_httpx_clients(ctx.http, timeout)
        self.client = genai.Client(
            api_key=ctx.secrets["api_key"],
            http_options=types.HttpOptions(
                base_url=API_BASE,
                timeout=int(timeout * 1000),
                httpx_async_client=async_client,
                httpx_client=sync_client,
            ),
        )

    def capabilities(self, model: str) -> ModelCapabilities:
        declared = self.config.model(model)
        if declared is None:
            raise AIConfigurationError("unknown_model")
        return declared.capabilities()

    def _config(self, request: AIRequest) -> types.GenerateContentConfig:
        caps = self.capabilities(request.model)
        system = request.system
        config: dict[str, Any] = {
            "max_output_tokens": request.max_output_tokens,
            "automatic_function_calling": types.AutomaticFunctionCallingConfig(disable=True),
        }
        if request.tools:
            config["tools"] = [
                types.Tool(
                    function_declarations=[
                        types.FunctionDeclaration(
                            name=t.name,
                            description=t.description,
                            parameters_json_schema=t.parameters,
                        )
                        for t in request.tools
                    ]
                )
            ]
        if request.output_schema is not None:
            if request.tools or caps.structured_output == "none":
                # Response schemas and function calling do not combine: the schema
                # goes in the instructions and the runtime validates the answer.
                system += SCHEMA_INSTRUCTION + json.dumps(request.output_schema, ensure_ascii=False)
            else:
                config["response_mime_type"] = "application/json"
                config["response_json_schema"] = request.output_schema
        if request.reasoning_level in caps.reasoning_levels:
            config["thinking_config"] = types.ThinkingConfig(
                thinking_level=THINKING[request.reasoning_level]
            )
        config["system_instruction"] = system
        return types.GenerateContentConfig(**config)

    async def complete(self, request: AIRequest) -> AIResponse:
        contents = [
            types.Content(
                role="user" if m.role == "user" else "model",
                parts=_user_parts(m) if m.role == "user" else _assistant_parts(m),
            )
            for m in request.messages
        ]
        try:
            response = await self.client.aio.models.generate_content(
                model=request.model, contents=contents, config=self._config(request)
            )
        except errors.APIError as exc:
            code = int(getattr(exc, "code", 0) or 0)
            if code == 429:  # noqa: PLR2004
                raise AIRateLimitedError("rate_limited") from None
            if code >= 500:  # noqa: PLR2004
                raise AIUnavailableError(f"http_{code}") from None
            raise AIConfigurationError(f"http_{code}") from None
        except TransportEgressError as exc:
            if isinstance(exc.error, EgressDeniedError):
                raise AIConfigurationError(f"egress: {exc.error.code}") from None
            raise AIUnavailableError(f"egress: {exc.error.code}") from None
        except TRANSPORT_ERRORS:
            raise AIUnavailableError("network_error") from None
        return _parse(response, request.model)


def _parse(response: types.GenerateContentResponse, model: str) -> AIResponse:
    meta = response.usage_metadata
    usage = Usage(
        input_tokens=(meta.prompt_token_count or 0) if meta else 0,
        output_tokens=((meta.candidates_token_count or 0) + (meta.thoughts_token_count or 0))
        if meta
        else 0,
        cache_read_tokens=(meta.cached_content_token_count or 0) if meta else 0,
    )
    served = response.model_version or model
    candidate = response.candidates[0] if response.candidates else None
    if candidate is None:
        feedback = response.prompt_feedback
        reason = feedback.block_reason.value if feedback and feedback.block_reason else None
        return AIResponse(
            stop_reason=StopReason.REFUSAL if reason else StopReason.ERROR,
            usage=usage,
            model_served=served,
            refusal_category=reason.lower() if reason else None,
        )
    finish = candidate.finish_reason.value if candidate.finish_reason else "STOP"
    if finish in REFUSALS:
        return AIResponse(
            stop_reason=StopReason.REFUSAL,
            usage=usage,
            model_served=served,
            refusal_category=finish.lower(),
        )
    parts = list(candidate.content.parts or []) if candidate.content else []
    text = "".join(p.text for p in parts if p.text and not p.thought)
    calls = tuple(
        ToolCall(
            id=p.function_call.id or f"call_{i}",
            name=p.function_call.name or "",
            arguments=dict(p.function_call.args or {}),
        )
        for i, p in enumerate(parts)
        if p.function_call is not None
    )
    if finish == "MAX_TOKENS":
        stop = StopReason.MAX_TOKENS
    elif finish == "STOP":
        stop = StopReason.TOOL_USE if calls else StopReason.END_TURN
    else:
        stop = StopReason.ERROR
    return AIResponse(
        stop_reason=stop,
        text=text,
        tool_calls=calls,
        usage=usage,
        model_served=served,
        provider_state={"gemini_parts": [_dump_part(p) for p in parts]},
    )


@register
class GeminiConnector(EngineConnectorType):
    kind = "gemini"
    label = "Gemini (palier gratuit Google AI Studio)"
    cost_class = CostClass.FREE_ACCOUNT
    config_model = GeminiConfig
    secret_slots = (SecretSlot("api_key", "Clé API Google AI Studio (projet sans facturation)"),)
    egress_domains = ("generativelanguage.googleapis.com",)
    # Conservative defaults; the exact free quotas of the account are checked in AI
    # Studio (Q35) and set on the connector.
    default_quotas = Quotas(requests_per_minute=10, requests_per_day=250)

    def engine(self, ctx: ConnectorContext) -> GeminiEngine:
        return GeminiEngine(ctx)
