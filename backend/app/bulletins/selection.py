"""Which template fits a vulnerability (spec 04 §2), and the fields computed from it.

The active templates of the workspace are tried by decreasing priority; a template
matches when one of its rule blocks holds entirely. The workspace's default template is
the fallback. The result says which conditions held, for the interface.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.bulletins.facts import Facts
from app.bulletins.spec import SEVERITY_RANK, MatchBlock, TemplateSpec


@dataclass(frozen=True)
class Candidate:
    template_id: uuid.UUID
    version_id: uuid.UUID
    name: str
    spec: TemplateSpec


@dataclass
class Selection:
    candidate: Candidate
    rule_index: int | None  # None: the workspace's default template
    reasons: list[str] = field(default_factory=list)


def _technology_matches(entry: str, technologies: list[tuple[str, str]]) -> bool:
    wanted = entry.strip().lower()
    for vendor, product in technologies:
        if wanted in (vendor.lower(), f"{vendor}/{product}".lower()):
            return True
    return False


def block_reasons(block: MatchBlock, facts: Facts) -> list[str] | None:  # noqa: PLR0911, PLR0912
    """The conditions of a block, as reasons, if all of them hold; else None."""
    reasons: list[str] = []
    if block.technologies_any:
        found = [t for t in block.technologies_any if _technology_matches(t, facts.technologies)]
        if not found:
            return None
        reasons.append(f"technologies: {', '.join(found)}")
    if block.severity_min is not None:
        rank = SEVERITY_RANK.get(facts.severity or "", 0)
        if rank < SEVERITY_RANK[block.severity_min]:
            return None
        reasons.append(f"severity: {facts.severity} >= {block.severity_min}")
    if block.kev is not None:
        if facts.kev != block.kev:
            return None
        reasons.append(f"kev: {str(facts.kev).lower()}")
    if block.exploitation_in:
        if facts.exploitation_status not in block.exploitation_in:
            return None
        reasons.append(f"exploitation: {facts.exploitation_status}")
    if block.priority_in:
        if facts.priority not in block.priority_in:
            return None
        reasons.append(f"priority: {facts.priority}")
    if block.cwe_any:
        cwes = sorted(set(block.cwe_any) & set(facts.cwes))
        if not cwes:
            return None
        reasons.append(f"cwe: {', '.join(cwes)}")
    if block.epss_min is not None:
        if facts.epss is None or facts.epss < block.epss_min:
            return None
        reasons.append(f"epss: {facts.epss:.3f} >= {block.epss_min}")
    return reasons


def select_template(
    candidates: list[Candidate],
    facts: Facts,
    *,
    default_template_id: uuid.UUID | None = None,
    language: str | None = None,
) -> Selection | None:
    pool = [c for c in candidates if language is None or c.spec.language == language]
    for candidate in sorted(pool, key=lambda c: (-c.spec.priority, c.name)):
        for index, block in enumerate(candidate.spec.match_rules):
            reasons = block_reasons(block, facts)
            if reasons is not None:
                return Selection(candidate, index, reasons)
    default = fallback_template(pool, default_template_id)
    return Selection(default, None) if default else None


def fallback_template(
    pool: list[Candidate], default_template_id: uuid.UUID | None
) -> Candidate | None:
    """The workspace default, or, in another language, a generic template (no rules)."""
    default = next((c for c in pool if c.template_id == default_template_id), None)
    if default is not None:
        return default
    generic = sorted(
        (c for c in pool if not c.spec.match_rules), key=lambda c: (c.spec.priority, c.name)
    )
    return generic[0] if generic else None


def computed_fields(spec: TemplateSpec, facts: Facts) -> dict[str, Any]:
    """The ``computed`` fields of a template, copied from the facts (no AI)."""
    return {
        f.key: facts.values.get(f.generation.source or "")
        for f in spec.fields
        if f.generation.mode == "computed"
    }


def preview_fields(spec: TemplateSpec, facts: Facts | None) -> dict[str, Any]:
    """Fields for a template preview: computed ones from a real vulnerability, the AI
    and manual ones as visible placeholders (the preview makes no AI call)."""
    placeholder = {"fr": "[{} : rédigé par l'IA]", "en": "[{}: written by the AI]"}[spec.language]
    manual = {"fr": "[{} : saisi par l'analyste]", "en": "[{}: written by the analyst]"}[
        spec.language
    ]
    values: dict[str, Any] = computed_fields(spec, facts) if facts else {}
    for f in spec.fields:
        if f.key in values:
            continue
        label = f.label or f.key
        text = (placeholder if f.generation.mode == "ai" else manual).format(label)
        if f.type in ("list", "products", "references"):
            values[f.key] = []
        elif f.type == "boolean":
            values[f.key] = False
        elif f.type == "enum":
            values[f.key] = f.options[0]
        elif f.type == "cvss":
            values[f.key] = None
        else:
            values[f.key] = text
    return values
