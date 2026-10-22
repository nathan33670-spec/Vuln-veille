"""Bulletin template specification (spec 04 §1): fields, generation, rendering, rules.

A template version stores one validated ``TemplateSpec``. Templates are written by
analysts, so every part is bounded and checked when a version is saved: field keys and
types, per-field AI instructions, computed sources (a closed list), and a Liquid render
template compiled in the restricted bulletin environment.
"""

from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.bulletins.render import compile_render_template

FieldType = Literal[
    "text", "markdown", "enum", "list", "cvss", "date", "references", "products", "boolean"
]
Severity = Literal["low", "medium", "high", "critical"]
Tlp = Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]
Language = Literal["fr", "en"]
Key = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")]

SEVERITY_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# What a computed field may copy, and into which field types (facts.py builds them).
COMPUTED_SOURCES: dict[str, frozenset[str]] = {
    "vuln.ref": frozenset({"text"}),
    "vuln.title": frozenset({"text"}),
    "vuln.description": frozenset({"text", "markdown"}),
    "vuln.cve_ids": frozenset({"list"}),
    "vuln.severity": frozenset({"enum", "text"}),
    "vuln.cvss": frozenset({"cvss"}),
    "vuln.kev": frozenset({"boolean"}),
    "vuln.kev_date_added": frozenset({"date", "text"}),
    "vuln.epss": frozenset({"text"}),
    "vuln.exploitation_status": frozenset({"enum", "text"}),
    "vuln.patch_status": frozenset({"enum", "text"}),
    "vuln.priority": frozenset({"enum", "text"}),
    "vuln.cwes": frozenset({"list"}),
    "vuln.technologies": frozenset({"list"}),
    "vuln.published_at": frozenset({"date", "text"}),
    "evidence.references": frozenset({"references"}),
    "synthesis.summary": frozenset({"markdown", "text"}),
    "synthesis.affected_products": frozenset({"products"}),
    "synthesis.mitigations": frozenset({"list"}),
}
MAX_FIELDS = 40


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Generation(_Strict):
    mode: Literal["ai", "computed", "manual"]
    instructions: str = Field(default="", max_length=2000)
    source: str | None = Field(default=None, alias="from", max_length=60)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.mode == "ai" and not self.instructions.strip():
            raise ValueError("ai fields need instructions")
        if self.mode == "computed" and self.source not in COMPUTED_SOURCES:
            raise ValueError("computed fields need a known source")
        if self.mode != "computed" and self.source is not None:
            raise ValueError("only computed fields have a source")
        return self


class TemplateField(_Strict):
    key: Key
    label: str = Field(default="", max_length=120)
    type: FieldType
    required: bool = False
    max_length: int | None = Field(default=None, ge=1, le=20000)
    max_items: int | None = Field(default=None, ge=1, le=100)
    options: list[Annotated[str, Field(min_length=1, max_length=60)]] = Field(
        default_factory=list, max_length=30
    )
    item_schema: dict[Key, Literal["text"]] | None = Field(default=None, max_length=10)
    generation: Generation

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.type == "enum") != bool(self.options):
            raise ValueError("options are for enum fields, which need them")
        if self.item_schema is not None and self.type != "list":
            raise ValueError("item_schema is for list fields")
        source = self.generation.source
        if source is not None and self.type not in COMPUTED_SOURCES[source]:
            raise ValueError(f"{source} cannot fill a {self.type} field")
        return self


class MatchBlock(_Strict):
    """All conditions of a block must hold; blocks are alternatives."""

    technologies_any: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=50, description="« éditeur » ou « éditeur/produit »"
    )
    severity_min: Severity | None = None
    kev: bool | None = None
    exploitation_in: list[Annotated[str, Field(max_length=40)]] = Field(
        default_factory=list, max_length=10
    )
    priority_in: list[Literal["P1", "P2", "P3", "P4"]] = Field(default_factory=list, max_length=4)
    cwe_any: list[Annotated[str, Field(pattern=r"^CWE-\d{1,5}$")]] = Field(
        default_factory=list, max_length=50
    )
    epss_min: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_dump(exclude_defaults=True):
            raise ValueError("a rule needs at least one condition")
        return self


class TemplateSpec(_Strict):
    language: Language
    priority: int = Field(default=0, ge=0, le=1000)
    tlp: Tlp = "AMBER"
    match_rules: list[MatchBlock] = Field(default_factory=list, max_length=20)
    style_guide: str = Field(default="", max_length=4000)
    example: str = Field(default="", max_length=20000)
    fields: list[TemplateField] = Field(min_length=1, max_length=MAX_FIELDS)
    render_template: str = Field(min_length=1, max_length=50000)

    @field_validator("render_template")
    @classmethod
    def _compiles(cls, value: str) -> str:
        compile_render_template(value)
        return value

    @model_validator(mode="after")
    def _fields(self) -> Self:
        keys = [f.key for f in self.fields]
        if len(set(keys)) != len(keys):
            raise ValueError("field keys must be unique")
        title = next((f for f in self.fields if f.key == "title"), None)
        if title is None or title.type != "text":
            raise ValueError("a text field « title » is required")
        return self

    def field(self, key: str) -> TemplateField | None:
        return next((f for f in self.fields if f.key == key), None)


def parse_spec(raw: dict[str, Any]) -> TemplateSpec:
    return TemplateSpec.model_validate(raw)
