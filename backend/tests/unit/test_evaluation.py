"""Evaluation bench scoring (spec 07 §4.6): deterministic criteria and comparison."""

from decimal import Decimal

from app.ai.evaluation import scoring

EXPECTED = {
    "exploitation_status": "exploited_itw",
    "patch_status": "available",
    "affected_products": [
        {"vendor": "apache", "product": "log4j"},
        {"vendor": "apache", "product": "solr"},
    ],
    "cwes": ["CWE-502"],
}


def test_field_scores() -> None:
    assert scoring.field_score("Exploited_ITW ", "exploited_itw") == 1.0
    assert scoring.field_score("available", "none") == 0.0
    products = [{"vendor": "Apache", "product": "Log4j", "versions": "< 2.17"}]
    assert scoring.field_score(EXPECTED["affected_products"], products) == 0.5
    assert scoring.field_score(["CWE-502"], ["cwe-502", "CWE-20"]) == 1.0
    assert scoring.field_score(["a"], "not a list") == 0.0
    assert scoring.field_score([], []) == 1.0


def _score(status: str, output: dict | None, flags: list | None = None) -> dict:  # type: ignore[type-arg]
    return scoring.score(
        "c",
        "CVE-2026-1",
        EXPECTED,
        run_id="r",
        status=status,
        output=output,
        flags=flags or [],
        cost_usd=Decimal("0.02"),
        latency_seconds=2.0,
        error=None,
    ).as_dict()


def test_a_case_is_scored_on_every_criterion() -> None:
    good = _score(
        "succeeded",
        {
            "exploitation_status": "exploited_itw",
            "patch_status": "available",
            "affected_products": [{"vendor": "apache", "product": "log4j"}],
            "cwes": ["CWE-502"],
        },
    )
    assert good["schema_valid"] is True
    assert good["citations_valid"] is True
    assert good["accuracy"] == (1 + 1 + 0.5 + 1) / 4
    uncited = _score("succeeded", {}, [{"kind": "uncited_url"}])
    assert uncited["citations_valid"] is False
    refused = _score("refused", None)
    assert refused["refused"] is True
    assert refused["schema_valid"] is False
    assert refused["accuracy"] == 0.0  # nothing right when nothing is answered


def test_metrics_and_comparison() -> None:
    baseline = scoring.metrics(
        [_score("succeeded", {"exploitation_status": "exploited_itw"}), _score("refused", None)]
    )
    assert baseline["cases"] == 2
    assert baseline["schema_valid_rate"] == 0.5
    assert baseline["refusal_rate"] == 0.5
    assert baseline["cost_usd"] == "0.04"
    assert baseline["cost_per_case_usd"] == "0.020000"
    candidate = scoring.metrics([_score("succeeded", {"exploitation_status": "exploited_itw"})])
    report = scoring.compare(baseline, candidate)
    assert report["schema_valid_rate"] == {"baseline": 0.5, "candidate": 1.0, "delta": 0.5}
    assert report["refusal_rate"]["delta"] == -0.5
    assert scoring.metrics([])["cost_per_case_usd"] == "0"
