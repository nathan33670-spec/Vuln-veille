"""Dynamic values in node parameters (spec 02 §3, ADR-009, ADR-010).

- ``{"$expr": "<JMESPath>"}``: pure selection and conditions, no side effect, no
  system function; evaluated on ``{json, meta, run, nodes}``.
- ``{"$tpl": "<Liquid>"}``: strings (e-mail subjects…), no Python attribute access,
  no template loading (``include``/``render`` removed), loop and output limits.

They are declared field by field in node parameters (``Expr``, ``Tpl``) and compiled
when a graph is saved. Data flowing through a workflow is never re-read as an
expression or a template: only what an analyst typed in a parameter is compiled.
"""

from functools import lru_cache
from typing import Any

import jmespath
import liquid
from jmespath.exceptions import JMESPathError
from liquid.exceptions import LiquidError
from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_EXPRESSION = 2000
MAX_TEMPLATE = 20000


class ExpressionError(ValueError):
    """Invalid or failing expression/template; the message carries no data value."""


class _SafeLiquid(liquid.Environment):
    loop_iteration_limit = 1000
    output_stream_limit = 100_000
    context_depth_limit = 20
    local_namespace_limit = 50_000

    def setup_tags_and_filters(self, *, extra: bool = False) -> None:
        super().setup_tags_and_filters(extra=extra)
        for tag in ("include", "render"):  # no access to other templates or files
            self.tags.pop(tag, None)


_LIQUID = _SafeLiquid()


@lru_cache(maxsize=1024)
def compile_expression(source: str) -> Any:
    if len(source) > MAX_EXPRESSION:
        raise ExpressionError("expression too long")
    try:
        return jmespath.compile(source)
    except JMESPathError as exc:
        raise ExpressionError(f"invalid expression: {type(exc).__name__}") from None


@lru_cache(maxsize=512)
def compile_template(source: str) -> Any:
    if len(source) > MAX_TEMPLATE:
        raise ExpressionError("template too long")
    try:
        return _LIQUID.from_string(source)
    except LiquidError as exc:
        raise ExpressionError(f"invalid template: {type(exc).__name__}") from None


class Expr(BaseModel):
    """A JMESPath expression typed by an analyst in a parameter."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    source: str = Field(alias="$expr", min_length=1, max_length=MAX_EXPRESSION)

    @field_validator("source")
    @classmethod
    def _compiles(cls, value: str) -> str:
        compile_expression(value)
        return value

    def evaluate(self, context: dict[str, Any]) -> Any:
        try:
            return compile_expression(self.source).search(context)
        except JMESPathError as exc:
            raise ExpressionError(f"expression failed: {type(exc).__name__}") from None

    def truthy(self, context: dict[str, Any]) -> bool:
        value = self.evaluate(context)
        return value not in (None, False, "", [], {}, 0)


class Tpl(BaseModel):
    """A Liquid template typed by an analyst in a parameter."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    source: str = Field(alias="$tpl", max_length=MAX_TEMPLATE)

    @field_validator("source")
    @classmethod
    def _compiles(cls, value: str) -> str:
        compile_template(value)
        return value

    def render(self, context: dict[str, Any]) -> str:
        try:
            return str(compile_template(self.source).render(**context))
        except LiquidError as exc:
            raise ExpressionError(f"template failed: {type(exc).__name__}") from None
