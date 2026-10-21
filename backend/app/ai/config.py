"""Configuration shared by every AI engine connector: declared models and data policy
(spec 07 §4.2 and §4.5, Q6)."""

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ai.types import ModelCapabilities, ReasoningLevel, StructuredSupport, ToolsSupport
from app.connectors.base import ConnectorConfig

DataClass = Literal["public", "tlp_clear", "tlp_green", "tlp_amber", "tlp_red", "client_data"]
# Ordered from least to most sensitive.
DATA_CLASSES: tuple[DataClass, ...] = (
    "public",
    "tlp_clear",
    "tlp_green",
    "tlp_amber",
    "tlp_red",
    "client_data",
)
Location = Literal["external_cloud", "self_hosted"]
PUBLIC_ONLY: tuple[DataClass, ...] = ("public", "tlp_clear")
ALL_BUT_RED: tuple[DataClass, ...] = ("public", "tlp_clear", "tlp_green", "tlp_amber")


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")
    display_name: str = Field(default="", max_length=100)
    enabled: bool = True
    tools: ToolsSupport = "native"
    structured_output: StructuredSupport = "native"
    context_window: int = Field(default=128_000, ge=1024, le=10_000_000)
    max_output_tokens: int = Field(default=8192, ge=256, le=1_000_000)
    reasoning_levels: list[ReasoningLevel] = Field(default_factory=list, max_length=4)
    prompt_cache: bool = False
    price_input_per_mtok: Decimal | None = Field(default=None, ge=0, le=1000, decimal_places=4)
    price_output_per_mtok: Decimal | None = Field(default=None, ge=0, le=1000, decimal_places=4)

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            tools=self.tools,
            structured_output=self.structured_output,
            context_window=self.context_window,
            max_output_tokens=self.max_output_tokens,
            reasoning_levels=frozenset(self.reasoning_levels),
            streaming=False,
            prompt_cache=self.prompt_cache,
        )


class EngineConfig(ConnectorConfig):
    models: list[ModelConfig] = Field(min_length=1, max_length=20)
    location: Location = "external_cloud"
    data_classes: list[DataClass] = Field(
        default_factory=lambda: list(PUBLIC_ONLY),
        description="Classes de données que ce moteur peut recevoir",
    )
    timeout_seconds: int = Field(default=180, ge=10, le=900)

    @field_validator("models")
    @classmethod
    def _unique(cls, models: list[ModelConfig]) -> list[ModelConfig]:
        if len({m.model_id for m in models}) != len(models):
            raise ValueError("duplicate model_id")
        return models

    @field_validator("data_classes")
    @classmethod
    def _no_client_data(cls, classes: list[DataClass]) -> list[DataClass]:
        # Q6: client subscriptions and secrets are never sent to a model.
        if "client_data" in classes:
            raise ValueError("client data is never sent to an AI engine")
        return sorted(set(classes), key=DATA_CLASSES.index)

    @model_validator(mode="after")
    def _ceiling(self) -> "EngineConfig":
        over = set(self.data_classes) - set(self.max_data_classes())
        if over:
            raise ValueError(f"data classes not allowed for this engine: {sorted(over)}")
        return self

    def max_data_classes(self) -> tuple[DataClass, ...]:
        """The most this kind of engine may ever receive; types narrow it."""
        return DATA_CLASSES[:-1]

    def model(self, model_id: str) -> ModelConfig | None:
        return next((m for m in self.models if m.model_id == model_id), None)


def accepts(allowed: list[str], requested: list[str]) -> bool:
    return set(requested) <= set(allowed)
