"""Bulletin field values: the schema asked of the engine, the prompt, and the cleaning
of what the engine or an analyst sends (spec 04 §3-4)."""

import copy
import uuid
from typing import Any

from app.bulletins.fields import clean_fields, output_schema, system_prompt
from app.bulletins.seeds import SEEDS
from app.bulletins.selection import Candidate, fallback_template
from app.bulletins.spec import parse_spec

GENERIC = parse_spec(SEEDS["generic_fr"][2])


def _with_field(**field: Any) -> Any:
    raw = copy.deepcopy(SEEDS["generic_fr"][2])
    raw["fields"].append({"generation": {"mode": "manual"}, **field})
    return parse_spec(raw)


def test_output_schema_holds_only_ai_fields() -> None:
    schema = output_schema(GENERIC)
    ai = [f.key for f in GENERIC.fields if f.generation.mode == "ai"]
    assert schema["required"] == ai
    assert schema["additionalProperties"] is False
    assert "severity" not in schema["properties"]  # computed
    assert output_schema(GENERIC, only="summary")["required"] == ["summary"]


def test_prompt_marks_data_as_untrusted() -> None:
    prompt = system_prompt(GENERIC, extra_instructions="Plus court.")
    first, *_ = prompt.splitlines()
    assert "français" in first
    assert "données non fiables" in prompt
    assert prompt.rstrip().endswith("Plus court.")
    translated = system_prompt(parse_spec(SEEDS["generic_en"][2]), translation=True)
    assert "anglais" in translated.splitlines()[0]
    assert "traduire fidèlement" in translated


def test_clean_fields_by_type() -> None:
    values = {
        "title": "Titre",
        "summary": "Résumé",
        "recommendations": "Corriger.",
        "severity": "critical",
        "references": [
            {"title": "ok", "url": "https://example.org/a"},
            {"title": "piège", "url": "javascript:alert(1)"},
            "pas un objet",
        ],
    }
    clean, errors = clean_fields(GENERIC, values)
    assert errors == []
    assert clean["references"] == [{"title": "ok", "url": "https://example.org/a"}]

    _, errors = clean_fields(GENERIC, {**values, "severity": "bogus", "title": "x" * 1000})
    assert {e["path"]: e["code"] for e in errors} == {
        "fields.severity": "enum",
        "fields.title": "too_long",
    }
    _, errors = clean_fields(GENERIC, {**values, "summary": "   "})
    assert errors == [{"path": "fields.summary", "code": "missing"}]


def test_clean_date_field() -> None:
    spec = _with_field(key="fixed_on", type="date", label="Corrigé le")
    base = {"title": "T", "summary": "S", "recommendations": "R"}
    clean, errors = clean_fields(spec, {**base, "fixed_on": "2026-10-22"})
    assert (clean["fixed_on"], errors) == ("2026-10-22", [])
    for bad in ("2026-ab-cd", "2026-13-01", "22/10/2026"):
        _, errors = clean_fields(spec, {**base, "fixed_on": bad})
        assert errors == [{"path": "fields.fixed_on", "code": "date_type"}]


def test_fallback_template_in_another_language() -> None:
    candidates = [
        Candidate(uuid.UUID(int=i), uuid.UUID(int=10 + i), name, parse_spec(spec))
        for i, (name, _, spec) in enumerate(SEEDS.values())
    ]
    french_default = next(
        c for c in candidates if c.spec.language == "fr" and not c.spec.match_rules
    )
    english = [c for c in candidates if c.spec.language == "en"]
    chosen = fallback_template(english, french_default.template_id)
    assert chosen is not None
    assert (chosen.spec.language, chosen.spec.match_rules) == ("en", [])
    french = [c for c in candidates if c.spec.language == "fr"]
    assert fallback_template(french, french_default.template_id) is french_default
    assert fallback_template([], None) is None
