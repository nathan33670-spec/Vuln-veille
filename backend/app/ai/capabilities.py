"""Automatic verification of declared model capabilities (spec 07 §4.2).

Three probes: a plain completion, a JSON answer conforming to a schema, and a tool
call round trip. A capability that fails its probe is downgraded in the verified
set (structured output to ``none``: the runtime then asks for JSON in the prompt and
validates it); a model failing the plain completion is unusable.
"""

import json
from dataclasses import replace
from typing import Any

from app.ai.types import (
    AIEngine,
    AIRequest,
    Message,
    ModelCapabilities,
    ReasoningLevel,
    StopReason,
    ToolResult,
    ToolSpec,
)

PROBE_SYSTEM = "Tu es une sonde de test automatique. Réponds brièvement et exactement."
PROBE_TOKENS = 2048
ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"answer": {"type": "string", "enum": ["OK"]}},
    "required": ["answer"],
    "additionalProperties": False,
}
PROBE_TOOL = ToolSpec(
    name="lookup_constant",
    description="Renvoie la valeur d'une constante de test.",
    parameters={
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
        "additionalProperties": False,
    },
)
CONSTANT = "4817"


def _request(model: str, caps: ModelCapabilities, text: str, **kwargs: Any) -> AIRequest:
    level = (
        ReasoningLevel.LOW if ReasoningLevel.LOW in caps.reasoning_levels else ReasoningLevel.MEDIUM
    )
    return AIRequest(
        model=model,
        system=PROBE_SYSTEM,
        messages=(Message(role="user", text=text),),
        reasoning_level=level,
        max_output_tokens=min(PROBE_TOKENS, caps.max_output_tokens),
        **kwargs,
    )


def parse_json_object(text: str) -> dict[str, Any] | None:
    """The JSON object of an answer, tolerating a fenced block around it."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        value = json.loads(cleaned[start : end + 1])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


async def verify_model(engine: AIEngine, model: str, declared: ModelCapabilities) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    plain = await engine.complete(_request(model, declared, "Réponds uniquement par le mot OK."))
    checks["completion"] = plain.stop_reason == StopReason.END_TURN and "OK" in plain.text.upper()
    checks["model_served"] = plain.model_served
    verified = declared

    if declared.structured_output != "none":
        answer = await engine.complete(
            _request(
                model, declared, "Réponds OK dans le champ answer.", output_schema=ANSWER_SCHEMA
            )
        )
        parsed = parse_json_object(answer.text)
        checks["structured_output"] = parsed == {"answer": "OK"}
        if not checks["structured_output"]:
            verified = replace(verified, structured_output="none")

    if declared.tools != "none":
        checks["tools"] = await _tool_round_trip(engine, model, declared)
        if not checks["tools"]:
            verified = replace(verified, tools="none")

    return {"ok": bool(checks["completion"]), "checks": checks, "verified": verified.as_dict()}


async def _tool_round_trip(engine: AIEngine, model: str, caps: ModelCapabilities) -> bool:
    request = _request(
        model,
        caps,
        'Appelle l\'outil lookup_constant avec name="probe", puis donne sa valeur.',
        tools=(PROBE_TOOL,),
    )
    first = await engine.complete(request)
    if first.stop_reason != StopReason.TOOL_USE or not first.tool_calls:
        return False
    call = first.tool_calls[0]
    if call.name != PROBE_TOOL.name:
        return False
    follow = replace(
        request,
        messages=(
            *request.messages,
            first.assistant_message(),
            Message(
                role="user",
                tool_results=(ToolResult(call_id=call.id, name=call.name, content=CONSTANT),),
            ),
        ),
    )
    second = await engine.complete(follow)
    return second.stop_reason == StopReason.END_TURN and CONSTANT in second.text
