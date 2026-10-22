"""Deterministic rendering of a bulletin (spec 04 §3.5 and §6).

Liquid template (written by an analyst) → Markdown → HTML, sanitised. Field values come
from the AI engine or from collected data: Liquid outputs them as text and never parses
them as a template; raw HTML in them is escaped by Markdown (``html=False``), and the
final HTML only keeps an allow-list of tags, ``http(s)``/``mailto`` links and no image.
"""

import hashlib
import json
from functools import lru_cache
from typing import Any

import liquid
import nh3
from liquid.exceptions import LiquidError
from markdown_it import MarkdownIt

MAX_RENDER_TEMPLATE = 50000

# Filters an analyst may use: text and list helpers, no encoding tricks, no ``safe``.
ALLOWED_FILTERS = frozenset(
    {
        "append", "capitalize", "compact", "date", "default", "downcase", "escape",
        "first", "join", "last", "map", "prepend", "remove", "replace", "size", "slice",
        "sort", "sort_natural", "split", "strip", "strip_newlines", "truncate",
        "truncatewords", "uniq", "upcase", "where", "plus", "minus", "round",
    }
)  # fmt: skip

SEVERITY_LABELS = {
    "fr": {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"},
    "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
}

ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "code", "em", "h1", "h2", "h3", "h4", "h5", "h6",
    "hr", "i", "li", "ol", "p", "pre", "strong", "table", "tbody", "td", "th", "thead",
    "tr", "ul",
}  # fmt: skip


class RenderError(ValueError):
    """Invalid or failing render template; the message carries no field value."""


def _severity_label(value: object, language: str = "fr") -> str:
    labels = SEVERITY_LABELS.get(str(language), SEVERITY_LABELS["fr"])
    return labels.get(str(value).lower(), str(value or ""))


def _tlp_label(value: object) -> str:
    return f"TLP:{value}" if value else ""


class _BulletinLiquid(liquid.Environment):
    loop_iteration_limit = 2000
    output_stream_limit = 200_000
    context_depth_limit = 20
    local_namespace_limit = 50_000

    def setup_tags_and_filters(self, *, extra: bool = False) -> None:
        super().setup_tags_and_filters(extra=extra)
        for tag in ("include", "render"):  # no access to other templates or files
            self.tags.pop(tag, None)
        for name in list(self.filters):
            if name not in ALLOWED_FILTERS:
                del self.filters[name]
        self.filters["severity_label"] = _severity_label
        self.filters["tlp_label"] = _tlp_label


_LIQUID = _BulletinLiquid()
_MARKDOWN = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


@lru_cache(maxsize=256)
def compile_render_template(source: str) -> Any:
    if len(source) > MAX_RENDER_TEMPLATE:
        raise RenderError("render template too long")
    try:
        template = _LIQUID.from_string(source)
    except LiquidError as exc:
        raise RenderError(f"invalid render template: {type(exc).__name__}") from None
    # Checked statically: an unknown filter on a branch the preview never reaches.
    unknown = sorted(set(template.filter_names()) - set(_LIQUID.filters))
    if unknown:
        raise RenderError(f"filters not allowed: {', '.join(unknown)[:200]}")
    return template


def render_markdown(source: str, context: dict[str, Any]) -> str:
    """The Markdown of a bulletin: ``fields`` (and ``tlp``, ``language``) in context."""
    try:
        return str(compile_render_template(source).render(**context))
    except LiquidError as exc:
        raise RenderError(f"render failed: {type(exc).__name__}") from None


def markdown_to_html(markdown: str) -> str:
    """Markdown to sanitised HTML: the only HTML that leaves the platform."""
    html = _MARKDOWN.render(markdown)
    return nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes={"a": {"href", "title"}, "abbr": {"title"}, "th": {"align"}, "td": {"align"}},
        url_schemes={"http", "https", "mailto"},
        link_rel="noopener noreferrer nofollow",
        strip_comments=True,
    )


def content_hash(fields: dict[str, Any], markdown: str) -> str:
    canonical = json.dumps({"fields": fields, "markdown": markdown}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
