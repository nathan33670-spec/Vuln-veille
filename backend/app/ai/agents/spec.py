"""The configuration of an agent version (spec 03 §2), stored as validated JSON.

A version is immutable: editing an agent creates a new version, and every run is
tied to the version it ran with. Nothing here is executed: the system prompt is
plain text sent to the engine, the output schema is data checked by ``jsonschema``.
"""

import json
import re
import uuid
from decimal import Decimal
from typing import Any, Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ai.config import DATA_CLASSES, PUBLIC_ONLY, DataClass
from app.ai.types import ReasoningLevel

# Read-only tools (spec 03 §5); ``app.ai.agents.tools`` registers exactly these.
TOOL_NAMES: frozenset[str] = frozenset(
    {
        "web_fetch",
        "github_search",
        "github_get",
        "x_discover",
        "x_read",
        "stackexchange_search",
        "social_search",
        "nvd_lookup",
        "epss_lookup",
        "kev_lookup",
        "osv_lookup",
        "internal_vuln_search",
        "technology_lookup",
    }
)
MAX_SCHEMA_BYTES = 32 * 1024
_DOMAIN = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class AgentLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_turns: int = Field(default=12, ge=1, le=50)
    max_tool_calls: int = Field(default=30, ge=0, le=200)
    max_output_tokens: int = Field(default=8192, ge=256, le=128_000)
    timeout_seconds: int = Field(default=600, ge=10, le=1800)
    max_cost_usd: Decimal | None = Field(default=Decimal("1"), ge=0, le=1000, decimal_places=4)


class ToolConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    # Narrows the domains of the allowed ``web`` connectors; empty: theirs.
    web_domains: list[str] = Field(default_factory=list, max_length=50)
    max_results: int = Field(default=10, ge=1, le=50)
    max_result_chars: int = Field(default=20_000, ge=1000, le=100_000)

    @field_validator("web_domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        cleaned = sorted({d.strip().lower() for d in value})
        bad = [d for d in cleaned if not _DOMAIN.fullmatch(d)]
        if bad:
            raise ValueError(f"invalid domains: {bad}")
        return cleaned


class AgentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    engine_mode: Literal["inherit", "pinned"] = "inherit"
    engine_model_row_id: uuid.UUID | None = None
    reasoning_level: ReasoningLevel = ReasoningLevel.MEDIUM
    system_prompt: str = Field(min_length=1, max_length=50_000)
    tools: list[str] = Field(default_factory=list, max_length=len(TOOL_NAMES))
    allowed_connectors: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    tool_config: ToolConfig = Field(default_factory=ToolConfig)
    output_schema: dict[str, Any] | None = None
    limits: AgentLimits = Field(default_factory=AgentLimits)
    data_classes: list[DataClass] = Field(default_factory=lambda: list(PUBLIC_ONLY))

    @field_validator("tools")
    @classmethod
    def _tools(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - TOOL_NAMES)
        if unknown:
            raise ValueError(f"unknown tools: {unknown}")
        return sorted(set(value))

    @field_validator("allowed_connectors")
    @classmethod
    def _connectors(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        return sorted(set(value))

    @field_validator("data_classes")
    @classmethod
    def _classes(cls, value: list[DataClass]) -> list[DataClass]:
        if "client_data" in value:  # Q6: never sent to a model
            raise ValueError("client data is never sent to an AI engine")
        return sorted(set(value), key=DATA_CLASSES.index)

    @field_validator("output_schema")
    @classmethod
    def _schema(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        if len(json.dumps(value)) > MAX_SCHEMA_BYTES:
            raise ValueError("output schema too large")
        try:
            Draft202012Validator.check_schema(value)
        except SchemaError as exc:
            raise ValueError(f"invalid JSON Schema: {exc.message[:200]}") from None
        if value.get("type") != "object":
            raise ValueError('the output schema must describe an object ("type": "object")')
        if _has_reference(value):
            raise ValueError("$ref to external documents is not allowed")
        return value

    @model_validator(mode="after")
    def _engine(self) -> "AgentSpec":
        if (self.engine_mode == "pinned") != (self.engine_model_row_id is not None):
            raise ValueError("a pinned engine needs engine_model_row_id, an inherited one none")
        return self

    @property
    def pinned(self) -> uuid.UUID | None:
        return self.engine_model_row_id if self.engine_mode == "pinned" else None


def _has_reference(node: Any) -> bool:
    """External ``$ref`` would make the validator resolve URLs: only local ones."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and not ref.startswith("#"):
            return True
        return any(_has_reference(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_reference(v) for v in node)
    return False
