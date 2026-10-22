"""Bulletin templates: specification checks, safe rendering, template selection."""

import copy
import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from app.bulletins.facts import Facts
from app.bulletins.render import RenderError, markdown_to_html, render_markdown
from app.bulletins.seeds import SEEDS
from app.bulletins.selection import (
    Candidate,
    computed_fields,
    preview_fields,
    select_template,
)
from app.bulletins.spec import TemplateSpec, parse_spec

GENERIC = SEEDS["generic_fr"][2]
URGENT = SEEDS["urgent_fr"][2]


def _spec(**changes: Any) -> dict[str, Any]:
    spec = copy.deepcopy(GENERIC)
    spec.update(changes)
    return spec


def _codes(raw: dict[str, Any]) -> list[str]:
    with pytest.raises(ValidationError) as caught:
        parse_spec(raw)
    return [str(e["msg"]) for e in caught.value.errors()]


def test_delivered_templates_are_valid() -> None:
    for _, _, spec in SEEDS.values():
        assert isinstance(parse_spec(spec), TemplateSpec)
    assert parse_spec(URGENT).priority > parse_spec(GENERIC).priority
    assert {parse_spec(s).language for _, _, s in SEEDS.values()} == {"fr", "en"}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"generation": {"mode": "ai"}}, "ai fields need instructions"),
        ({"generation": {"mode": "computed", "from": "os.environ"}}, "known source"),
        ({"generation": {"mode": "computed", "from": "vuln.cvss"}}, "cannot fill a text field"),
        ({"generation": {"mode": "manual", "from": "vuln.ref"}}, "only computed"),
        ({"type": "enum"}, "options are for enum fields"),
    ],
)
def test_field_rules(change: dict[str, Any], message: str) -> None:
    spec = _spec()
    spec["fields"][0] = {**spec["fields"][0], **change}
    assert any(message in m for m in _codes(spec))


def test_template_rules() -> None:
    spec = _spec()
    spec["fields"].append(copy.deepcopy(spec["fields"][1]))
    assert any("unique" in m for m in _codes(spec))
    no_title = _spec(fields=[f for f in GENERIC["fields"] if f["key"] != "title"])
    assert any("title" in m for m in _codes(no_title))
    assert any("at least one condition" in m for m in _codes(_spec(match_rules=[{}])))
    assert _codes(_spec(tlp="PURPLE"))
    assert _codes(_spec(unknown=1))


@pytest.mark.parametrize(
    "template",
    [
        "{% include 'x' %}",  # no access to other templates or files
        "{% render 'x' %}",
        "{{ fields.title | base64_decode }}",  # filters outside the allow-list
        "{{ fields.title",
    ],
)
def test_render_template_is_restricted(template: str) -> None:
    assert _codes(_spec(render_template=template))


def test_rendering_keeps_values_as_data() -> None:
    fields = {
        "title": "RCE {{ 7 * 7 }} {% raw %}",
        "summary": "Voir [ici](javascript:alert(1)) <script>alert(1)</script> <img src=x>",
        "references": [{"title": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1"}],
        "cves": [],
        "affected_products": [],
        "recommendations": "Appliquer le correctif.",
    }
    markdown = render_markdown(
        GENERIC["render_template"], {"fields": fields, "tlp": "AMBER", "language": "fr"}
    )
    assert "{{ 7 * 7 }}" in markdown  # a value is never rendered as a template
    html = markdown_to_html(markdown)
    assert "<script" not in html
    assert "<img" not in html
    assert "javascript:" not in html.replace("[ici](javascript:alert(1))", "")
    assert 'href="javascript' not in html
    assert '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-1" rel="noopener' in html
    assert "TLP:AMBER" in html


def test_render_limits() -> None:
    loop = "{% for i in (1..100000) %}x{% endfor %}"
    with pytest.raises(RenderError):
        render_markdown(loop, {"fields": {}})


def _facts(**values: Any) -> Facts:
    facts = Facts(vulnerability_id=uuid.uuid4(), **values)
    facts.values = {
        "vuln.cve_ids": ["CVE-2026-1"],
        "vuln.severity": values.get("severity"),
        "evidence.references": [],
    }
    return facts


def _candidates() -> list[Candidate]:
    return [
        Candidate(uuid.UUID(int=i), uuid.UUID(int=10 + i), name, parse_spec(spec))
        for i, (name, _, spec) in enumerate(SEEDS.values())
    ]


def test_selection_by_rule_then_default() -> None:
    candidates = _candidates()
    default = candidates[0].template_id  # generic_fr
    kev = select_template(candidates, _facts(kev=True), default_template_id=default)
    assert kev is not None
    assert (kev.candidate.name, kev.rule_index, kev.reasons) == (
        "Vulnérabilité exploitée ou critique (FR)",
        0,
        ["kev: true"],
    )
    critical = select_template(candidates, _facts(severity="critical"), default_template_id=default)
    assert critical is not None
    assert critical.rule_index == 2
    assert critical.reasons == ["severity: critical >= critical"]
    plain = select_template(candidates, _facts(severity="high"), default_template_id=default)
    assert plain is not None
    assert (plain.candidate.template_id, plain.rule_index) == (default, None)
    english = select_template(
        candidates, _facts(kev=True), default_template_id=default, language="en"
    )
    # No English rule matches and the default is French: the generic English template.
    assert english is not None
    assert (english.candidate.name, english.rule_index) == ("Generic bulletin (EN)", None)


def test_technology_and_combined_conditions() -> None:
    spec = _spec(
        priority=500,
        match_rules=[{"technologies_any": ["microsoft/exchange_server"], "severity_min": "high"}],
    )
    candidate = Candidate(uuid.uuid4(), uuid.uuid4(), "Exchange", parse_spec(spec))
    exchange = [("microsoft", "exchange_server")]
    assert select_template([candidate], _facts(technologies=exchange, severity="medium")) is None
    found = select_template([candidate], _facts(technologies=exchange, severity="high"))
    assert found is not None
    assert found.reasons == ["technologies: microsoft/exchange_server", "severity: high >= high"]


def test_computed_and_preview_fields() -> None:
    spec = parse_spec(GENERIC)
    facts = _facts(severity="high")
    assert computed_fields(spec, facts)["cves"] == ["CVE-2026-1"]
    preview = preview_fields(spec, facts)
    assert preview["title"] == "[Titre : rédigé par l'IA]"
    assert preview["analyst_note"] == "[Note de l'analyste : saisi par l'analyste]"
    assert preview["severity"] == "high"
