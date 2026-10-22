"""Compatibility of an agent with a model (spec 07 §4.4).

Shown before the preferred engine changes, and checked again before each run: an
agent whose needs the model does not cover must be pinned on its current engine or
adapted. ``missing`` blocks a run; ``degraded`` runs with a fallback (JSON asked in
the prompt and validated, reasoning level ignored, output tokens capped).
"""

from dataclasses import dataclass, field
from typing import Any, Literal

from app.ai.agents.spec import AgentSpec
from app.ai.config import accepts
from app.ai.models import AIModel
from app.ai.types import ModelCapabilities, ReasoningLevel

Level = Literal["ok", "degraded", "missing"]
TOOL_CONTEXT = 32_000
BASE_CONTEXT = 4_000


def model_capabilities(model: AIModel) -> ModelCapabilities:
    """Verified capabilities when the probe ran, otherwise the declared ones."""
    raw: dict[str, Any] = model.verified or model.declared or {}
    return ModelCapabilities(
        tools=raw.get("tools", "none"),
        structured_output=raw.get("structured_output", "none"),
        context_window=int(raw.get("context_window", 8192)),
        max_output_tokens=int(raw.get("max_output_tokens", 4096)),
        reasoning_levels=frozenset(ReasoningLevel(r) for r in raw.get("reasoning_levels", [])),
        streaming=bool(raw.get("streaming", False)),
        prompt_cache=bool(raw.get("prompt_cache", False)),
        web_search=bool(raw.get("web_search", False)),
    )


@dataclass(frozen=True)
class Need:
    name: str
    level: Level
    detail: str = ""


@dataclass(frozen=True)
class Compatibility:
    needs: list[Need] = field(default_factory=list)

    @property
    def compatible(self) -> bool:
        return all(n.level != "missing" for n in self.needs)

    @property
    def missing(self) -> list[str]:
        return [n.name for n in self.needs if n.level == "missing"]


def required_context(spec: AgentSpec) -> int:
    return (
        len(spec.system_prompt) // 3
        + spec.limits.max_output_tokens
        + (TOOL_CONTEXT if spec.tools else BASE_CONTEXT)
    )


def check(spec: AgentSpec, model: AIModel) -> Compatibility:
    caps = model_capabilities(model)
    needs = [
        Need(
            "data_classes",
            "ok" if accepts(model.data_classes, list(spec.data_classes)) else "missing",
            ",".join(sorted(set(spec.data_classes) - set(model.data_classes))),
        )
    ]
    if spec.tools:
        needs.append(Need("tools", "missing" if caps.tools == "none" else "ok", caps.tools))
    if spec.output_schema is not None:
        needs.append(
            Need(
                "structured_output",
                "degraded" if caps.structured_output == "none" else "ok",
                caps.structured_output,
            )
        )
    context = required_context(spec)
    needs.append(
        Need(
            "context_window",
            "ok" if caps.context_window >= context else "missing",
            f"{caps.context_window} / {context}",
        )
    )
    needs.append(
        Need(
            "max_output_tokens",
            "ok" if caps.max_output_tokens >= spec.limits.max_output_tokens else "degraded",
            f"{caps.max_output_tokens} / {spec.limits.max_output_tokens}",
        )
    )
    if caps.reasoning_levels or spec.reasoning_level != ReasoningLevel.MEDIUM:
        needs.append(
            Need(
                "reasoning_level",
                "ok" if spec.reasoning_level in caps.reasoning_levels else "degraded",
                spec.reasoning_level.value,
            )
        )
    return Compatibility(needs)
