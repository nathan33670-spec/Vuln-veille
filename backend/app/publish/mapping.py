"""Declarative payload mapping of a publication connector (spec 05 §2, ADR-030).

A mapping is a JSON tree: objects and lists are copied as structure, and every leaf
is one of
- ``{"const": <any JSON>}``: a constant;
- ``{"path": "<JMESPath>", "map": {...}, "default": ..., "format": "..."}``: a value
  read from the publication context, optionally translated by a table and formatted;
- ``{"template": "<Liquid>"}``: a string rendered from the context.

An object is a leaf when it holds exactly one of ``const``, ``path`` or ``template``
and only leaf keys; to send an object whose keys look like a leaf, wrap it in
``const``. The payload is built as a JSON value, then serialised: no string
concatenation, no injection. Values read from the context are never compiled.
"""

from datetime import date, datetime
from typing import Any

from jmespath.exceptions import JMESPathError
from liquid.exceptions import LiquidError

from app.workflows.expressions import ExpressionError, compile_expression, compile_template

MAX_DEPTH = 12
MAX_NODES = 500
MAX_MAP_ENTRIES = 200
FORMATS = frozenset({"iso8601", "date", "string", "number", "upper", "lower"})
LEAF_KINDS = ("const", "path", "template")
LEAF_KEYS = frozenset({*LEAF_KINDS, "map", "default", "format"})


class MappingError(ValueError):
    """An invalid mapping; ``path`` locates it in the tree (no data value inside)."""

    def __init__(self, path: str, code: str) -> None:
        super().__init__(f"{path}: {code}")
        self.path = path
        self.code = code


def _is_leaf(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    kinds = [k for k in LEAF_KINDS if k in node]
    return len(kinds) == 1 and set(node) <= LEAF_KEYS


def _where(path: str, key: str | int) -> str:
    return f"{path}[{key}]" if isinstance(key, int) else f"{path}.{key}" if path else key


def validate_mapping(mapping: Any) -> list[dict[str, str]]:
    """Every problem of a mapping, as ``{path, code}``; empty when valid."""
    errors: list[dict[str, str]] = []
    count = 0

    def visit(node: Any, path: str, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_NODES:
            if count == MAX_NODES + 1:
                errors.append({"path": path or "$", "code": "too_many_nodes"})
            return
        if depth > MAX_DEPTH:
            errors.append({"path": path or "$", "code": "too_deep"})
            return
        if _is_leaf(node):
            _check_leaf(node, path, errors)
        elif isinstance(node, dict):
            if any(k in node for k in LEAF_KINDS):
                errors.append({"path": path or "$", "code": "ambiguous_leaf"})
                return
            for key, child in node.items():
                visit(child, _where(path, key), depth + 1)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                visit(child, _where(path, index), depth + 1)
        else:
            # Bare scalars are refused: a constant is explicit (``{"const": ...}``).
            errors.append({"path": path or "$", "code": "bare_value"})

    if not isinstance(mapping, dict | list):
        return [{"path": "$", "code": "not_a_tree"}]
    visit(mapping, "", 0)
    return errors


def _check_leaf(node: dict[str, Any], path: str, errors: list[dict[str, str]]) -> None:
    where = path or "$"
    if "path" in node:
        source = node["path"]
        if not isinstance(source, str) or not source:
            errors.append({"path": where, "code": "invalid_path"})
        else:
            try:
                compile_expression(source)
            except ExpressionError:
                errors.append({"path": where, "code": "invalid_path"})
        table = node.get("map")
        if table is not None and (not isinstance(table, dict) or len(table) > MAX_MAP_ENTRIES):
            errors.append({"path": where, "code": "invalid_map"})
        fmt = node.get("format")
        if fmt is not None and fmt not in FORMATS:
            errors.append({"path": where, "code": "invalid_format"})
    else:
        extras = set(node) - {"const", "template"}
        if extras:
            errors.append({"path": where, "code": "leaf_options_need_path"})
    if "template" in node:
        source = node["template"]
        if not isinstance(source, str):
            errors.append({"path": where, "code": "invalid_template"})
        else:
            try:
                compile_template(source)
            except ExpressionError:
                errors.append({"path": where, "code": "invalid_template"})


def _format(value: Any, fmt: str | None) -> Any:  # noqa: PLR0911 - one case per format
    if fmt is None or value is None:
        return value
    if fmt in ("iso8601", "date"):
        if isinstance(value, str):
            try:
                parsed: datetime | date = datetime.fromisoformat(value)
            except ValueError:
                return value
        elif isinstance(value, datetime | date):
            parsed = value
        else:
            return value
        if fmt == "date":
            return parsed.date().isoformat() if isinstance(parsed, datetime) else parsed.isoformat()
        return parsed.isoformat()
    if fmt == "string":
        return value if isinstance(value, str) else str(value)
    if fmt == "number":
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return int(number) if number.is_integer() else number
    if fmt == "upper" and isinstance(value, str):
        return value.upper()
    if fmt == "lower" and isinstance(value, str):
        return value.lower()
    return value


def _leaf(node: dict[str, Any], context: dict[str, Any], path: str) -> Any:
    if "const" in node:
        return node["const"]
    if "template" in node:
        try:
            return str(compile_template(node["template"]).render(**context))
        except (ExpressionError, LiquidError):
            raise MappingError(path or "$", "template_failed") from None
    try:
        value = compile_expression(node["path"]).search(context)
    except (ExpressionError, JMESPathError):
        raise MappingError(path or "$", "path_failed") from None
    table = node.get("map")
    if table is not None:
        if isinstance(value, list):
            value = [table.get(str(v), v) for v in value]
        elif value is not None:
            value = table.get(str(value), value)
    if value is None and "default" in node:
        value = node["default"]
    return _format(value, node.get("format"))


def build_payload(mapping: Any, context: dict[str, Any]) -> Any:
    """The JSON value described by a (valid) mapping, for one publication context."""

    def build(node: Any, path: str) -> Any:
        if _is_leaf(node):
            return _leaf(node, context, path)
        if isinstance(node, dict):
            return {key: build(child, _where(path, key)) for key, child in node.items()}
        if isinstance(node, list):
            return [build(child, _where(path, index)) for index, child in enumerate(node)]
        raise MappingError(path or "$", "bare_value")

    return build(mapping, "")


def context_paths(context: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """The JMESPath paths available in a context (for completion in the editor)."""
    if depth > 4:  # noqa: PLR2004 - completion stays shallow
        return []
    paths: list[str] = []
    if isinstance(context, dict):
        for key, value in context.items():
            here = f"{prefix}.{key}" if prefix else str(key)
            paths.append(here)
            paths.extend(context_paths(value, here, depth + 1))
    elif isinstance(context, list) and context and isinstance(context[0], dict):
        paths.extend(context_paths(context[0], f"{prefix}[]", depth + 1))
    return paths
