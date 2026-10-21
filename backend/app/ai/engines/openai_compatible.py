"""OpenAI-compatible chat completions: the planned LLMaaS (Q33), and self-hosted
servers (vLLM, OpenLLM, Ollama) or Mistral (spec 03 §3).

There is no common SDK for these servers, so the adapter speaks the documented
``/chat/completions`` protocol through ``SafeHttpClient`` directly. Capabilities
vary by server and model:
- tools ``native``: ``tools`` / ``tool_calls``; ``emulated``: the model answers a
  constrained JSON ``{"tool": …, "arguments": …}`` or ``{"final": …}`` that the
  adapter turns into the same tool calls, so the agent loop does not change;
- structured output ``native``: ``response_format`` JSON Schema; ``guided_json``:
  vLLM's guided decoding; ``none``: JSON asked for in the prompt (the runtime
  validates and retries once).
"""

import json
import uuid
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, HttpUrl, field_validator

from app.ai.config import EngineConfig, Location
from app.ai.connector import EngineConnectorType
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
    ToolSpec,
    Usage,
)
from app.connectors.base import (
    ConnectorConfig,
    ConnectorContext,
    CostClass,
    Quotas,
    SecretSlot,
    register,
)
from app.core.narrow import expect
from app.net.safe_http import EgressDeniedError, EgressError

EFFORT = {
    ReasoningLevel.LOW: "low",
    ReasoningLevel.MEDIUM: "medium",
    ReasoningLevel.HIGH: "high",
    ReasoningLevel.MAX: "high",
}
FINISH = {
    "stop": StopReason.END_TURN,
    "tool_calls": StopReason.TOOL_USE,
    "function_call": StopReason.TOOL_USE,
    "length": StopReason.MAX_TOKENS,
    "content_filter": StopReason.REFUSAL,
}
EMULATION = """

Tu peux utiliser des outils. Réponds TOUJOURS par un seul objet JSON, sans texte autour :
- pour appeler un outil : {{"tool": "<nom>", "arguments": {{...}}}}
- pour donner ta réponse finale : {{"final": <réponse>}}
Outils disponibles (nom, description, schéma JSON des arguments) :
{tools}"""
JSON_ONLY = "\n\nRéponds uniquement par un objet JSON conforme à ce schéma JSON :\n{schema}"


class OpenAICompatibleConfig(EngineConfig):
    base_url: HttpUrl = Field(description="URL de base de l'API, par ex. https://llm.interne/v1")
    location: Location = "self_hosted"

    @field_validator("base_url")
    @classmethod
    def _https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https" or not value.host:
            raise ValueError("https only (spec 07 §4.7)")
        return value


def _tool_catalog(tools: tuple[ToolSpec, ...]) -> str:
    return "\n".join(
        json.dumps(
            {"name": t.name, "description": t.description, "parameters": t.parameters},
            ensure_ascii=False,
        )
        for t in tools
    )


class OpenAICompatibleEngine:
    def __init__(self, ctx: ConnectorContext) -> None:
        self.config = expect(ctx.config, OpenAICompatibleConfig)
        self.http = ctx.http
        self.api_key = ctx.secrets.get("api_key")

    def capabilities(self, model: str) -> ModelCapabilities:
        declared = self.config.model(model)
        if declared is None:
            raise AIConfigurationError("unknown_model")
        return declared.capabilities()

    def _messages(self, request: AIRequest, system: str, emulated: bool) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in request.messages:
            if m.role == "assistant":
                out.append(self._assistant(m, emulated))
                continue
            if emulated and m.tool_results:
                results = "\n".join(
                    f'<tool_result name="{r.name}" error="{str(r.is_error).lower()}">\n'
                    f"{r.content}\n</tool_result>"
                    for r in m.tool_results
                )
                out.append(
                    {"role": "user", "content": results + (f"\n\n{m.text}" if m.text else "")}
                )
                continue
            out.extend(
                {"role": "tool", "tool_call_id": r.call_id, "content": r.content}
                for r in m.tool_results
            )
            if m.text:
                out.append({"role": "user", "content": m.text})
        return out

    @staticmethod
    def _assistant(message: Message, emulated: bool) -> dict[str, Any]:
        if emulated:
            if message.tool_calls:
                call = message.tool_calls[0]
                content = json.dumps({"tool": call.name, "arguments": call.arguments})
            else:
                content = message.text
            return {"role": "assistant", "content": content}
        entry: dict[str, Any] = {"role": "assistant", "content": message.text or None}
        if message.tool_calls:
            entry["tool_calls"] = [
                {
                    "id": c.id,
                    "type": "function",
                    "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                }
                for c in message.tool_calls
            ]
        return entry

    def _body(self, request: AIRequest) -> tuple[dict[str, Any], bool]:
        caps = self.capabilities(request.model)
        emulated = bool(request.tools) and caps.tools == "emulated"
        system = request.system
        if emulated:
            system += EMULATION.format(tools=_tool_catalog(request.tools))
        body: dict[str, Any] = {"model": request.model, "max_tokens": request.max_output_tokens}
        schema = request.output_schema
        if request.tools and caps.tools == "native":
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in request.tools
            ]
            body["tool_choice"] = "auto"
        if emulated:
            body["response_format"] = {"type": "json_object"}
            if schema is not None:
                system += JSON_ONLY.format(schema=json.dumps(schema, ensure_ascii=False))
        elif schema is not None:
            if caps.structured_output == "native" and not request.tools:
                body["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": "output", "schema": schema, "strict": True},
                }
            elif caps.structured_output == "guided_json" and not request.tools:
                body["guided_json"] = schema
            else:
                system += JSON_ONLY.format(schema=json.dumps(schema, ensure_ascii=False))
        if request.reasoning_level in caps.reasoning_levels:
            body["reasoning_effort"] = EFFORT[request.reasoning_level]
        body["messages"] = self._messages(request, system, emulated)
        return body, emulated

    async def complete(self, request: AIRequest) -> AIResponse:
        body, emulated = self._body(request)
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        url = str(self.config.base_url).rstrip("/") + "/chat/completions"
        try:
            response = await self.http.post(url, headers=headers, json_body=body)
        except EgressDeniedError as exc:
            raise AIConfigurationError(f"egress: {exc.code}") from None
        except EgressError as exc:
            raise AIUnavailableError(f"egress: {exc.code}") from None
        status = response.status_code
        if status == 429:  # noqa: PLR2004
            retry = response.headers.get("retry-after")
            raise AIRateLimitedError(
                "rate_limited", float(retry) if retry and retry.isdigit() else None
            )
        if status >= 500:  # noqa: PLR2004
            raise AIUnavailableError(f"http_{status}")
        if status != 200:  # noqa: PLR2004
            raise AIConfigurationError(f"http_{status}")
        try:
            data = response.json()
        except ValueError:
            raise AIUnavailableError("invalid_json") from None
        return _parse(data, request.model, emulated)


def _parse(data: Any, model: str, emulated: bool) -> AIResponse:
    if not isinstance(data, dict) or not data.get("choices"):
        raise AIUnavailableError("unexpected_answer")
    choice = data["choices"][0]
    message = choice.get("message") or {}
    raw_usage = data.get("usage") or {}
    details = raw_usage.get("prompt_tokens_details") or {}
    usage = Usage(
        input_tokens=int(raw_usage.get("prompt_tokens") or 0),
        output_tokens=int(raw_usage.get("completion_tokens") or 0),
        cache_read_tokens=int(details.get("cached_tokens") or 0),
    )
    served = str(data.get("model") or model)
    if message.get("refusal"):
        return AIResponse(
            stop_reason=StopReason.REFUSAL,
            usage=usage,
            model_served=served,
            refusal_category="model_refusal",
        )
    text = message.get("content") or ""
    if not isinstance(text, str):
        text = ""
    finish = FINISH.get(str(choice.get("finish_reason") or "stop"), StopReason.END_TURN)
    if emulated:
        return _emulated(text, finish, usage, served)
    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except ValueError:
            arguments = None
        if not isinstance(arguments, dict):
            return AIResponse(
                stop_reason=StopReason.ERROR,
                usage=usage,
                model_served=served,
                refusal_category=None,
            )
        calls.append(
            ToolCall(
                id=str(call.get("id") or uuid.uuid4().hex),
                name=str(function.get("name") or ""),
                arguments=arguments,
            )
        )
    if calls:
        finish = StopReason.TOOL_USE
    return AIResponse(
        stop_reason=finish, text=text, tool_calls=tuple(calls), usage=usage, model_served=served
    )


def _emulated(text: str, finish: StopReason, usage: Usage, served: str) -> AIResponse:
    from app.ai.capabilities import parse_json_object  # noqa: PLC0415

    if finish == StopReason.MAX_TOKENS:
        return AIResponse(stop_reason=finish, text=text, usage=usage, model_served=served)
    parsed = parse_json_object(text)
    if parsed is None:
        return AIResponse(
            stop_reason=StopReason.END_TURN, text=text, usage=usage, model_served=served
        )
    if isinstance(parsed.get("tool"), str) and isinstance(parsed.get("arguments"), dict):
        call = ToolCall(id=uuid.uuid4().hex, name=parsed["tool"], arguments=parsed["arguments"])
        return AIResponse(
            stop_reason=StopReason.TOOL_USE, tool_calls=(call,), usage=usage, model_served=served
        )
    final = parsed.get("final", parsed)
    answer = final if isinstance(final, str) else json.dumps(final, ensure_ascii=False)
    return AIResponse(
        stop_reason=StopReason.END_TURN, text=answer, usage=usage, model_served=served
    )


@register
class OpenAICompatibleConnector(EngineConnectorType):
    kind = "openai_compatible"
    label = "LLM compatible OpenAI (LLMaaS, vLLM, Ollama…)"
    cost_class = CostClass.AI_BILLED
    config_model = OpenAICompatibleConfig
    secret_slots = (SecretSlot("api_key", "Jeton d'accès (Bearer)", required=False),)
    default_quotas = Quotas(requests_per_minute=60, monthly_budget_eur=Decimal("0"))

    @classmethod
    def egress_for(cls, config: ConnectorConfig) -> tuple[str, ...]:
        config = expect(config, OpenAICompatibleConfig)
        return ((urlsplit(str(config.base_url)).hostname or "").lower(),)

    def engine(self, ctx: ConnectorContext) -> OpenAICompatibleEngine:
        return OpenAICompatibleEngine(ctx)
