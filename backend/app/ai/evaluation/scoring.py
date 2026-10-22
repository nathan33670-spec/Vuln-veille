"""Deterministic scoring of one agent output against a reference case (spec 07 §4.6).

Criteria: valid output (the schema was met), valid citations (no URL outside the
consulted sources), refusal, accuracy of the key fields the analysts filled in, cost
and latency. Accuracy compares each expected field: a scalar must be equal (case and
spacing ignored); a list of objects is scored by recall on the expected items, matched
on the fields the expectation gives (``vendor`` and ``product``, for instance); a list
of scalars by recall. A grid review by an analyst can come on top of it later.
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import Any


def _norm(value: Any) -> Any:
    return " ".join(value.lower().split()) if isinstance(value, str) else value


def _matches(expected: dict[str, Any], actual: Any) -> bool:
    return isinstance(actual, dict) and all(
        _norm(actual.get(k)) == _norm(v) for k, v in expected.items()
    )


def field_score(expected: Any, actual: Any) -> float:
    if isinstance(expected, list):
        if not expected:
            return 1.0 if not actual else 0.0
        if not isinstance(actual, list):
            return 0.0
        if all(isinstance(e, dict) for e in expected):
            found = sum(1 for e in expected if any(_matches(e, a) for a in actual))
        else:
            values = {_norm(a) for a in actual if not isinstance(a, dict | list)}
            found = sum(1 for e in expected if _norm(e) in values)
        return found / len(expected)
    return 1.0 if _norm(expected) == _norm(actual) else 0.0


def accuracy(expected: dict[str, Any], output: dict[str, Any] | None) -> dict[str, float]:
    if not expected:
        return {}
    return {key: field_score(value, (output or {}).get(key)) for key, value in expected.items()}


@dataclass(frozen=True)
class CaseScore:
    case_id: str
    cve_id: str
    run_id: str | None
    status: str
    schema_valid: bool
    citations_valid: bool
    refused: bool
    fields: dict[str, float]
    cost_usd: Decimal
    latency_seconds: float | None
    error: str | None = None

    @property
    def accuracy(self) -> float | None:
        return sum(self.fields.values()) / len(self.fields) if self.fields else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "cve_id": self.cve_id,
            "run_id": self.run_id,
            "status": self.status,
            "schema_valid": self.schema_valid,
            "citations_valid": self.citations_valid,
            "refused": self.refused,
            "fields": self.fields,
            "accuracy": self.accuracy,
            "cost_usd": str(self.cost_usd),
            "latency_seconds": self.latency_seconds,
            "error": self.error,
        }


def score(
    case_id: str,
    cve_id: str,
    expected: dict[str, Any],
    *,
    run_id: str | None,
    status: str,
    output: dict[str, Any] | None,
    flags: list[dict[str, Any]],
    cost_usd: Decimal,
    latency_seconds: float | None,
    error: str | None,
) -> CaseScore:
    succeeded = status == "succeeded"
    return CaseScore(
        case_id=case_id,
        cve_id=cve_id,
        run_id=run_id,
        status=status,
        schema_valid=succeeded,
        citations_valid=succeeded and not any(f.get("kind") == "uncited_url" for f in flags),
        refused=status == "refused",
        fields=accuracy(expected, output if succeeded else None),
        cost_usd=cost_usd,
        latency_seconds=latency_seconds,
        error=error,
    )


def _rate(values: list[bool]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregated over the cases played."""
    cost = sum((Decimal(r["cost_usd"]) for r in results), Decimal(0))
    accuracies = [r["accuracy"] for r in results if r["accuracy"] is not None]
    latencies = [r["latency_seconds"] for r in results if r["latency_seconds"] is not None]
    return {
        "cases": len(results),
        "schema_valid_rate": _rate([r["schema_valid"] for r in results]),
        "citation_valid_rate": _rate([r["citations_valid"] for r in results]),
        "refusal_rate": _rate([r["refused"] for r in results]),
        "accuracy": _mean(accuracies),
        "cost_usd": str(cost),
        "cost_per_case_usd": str((cost / len(results)).quantize(Decimal("0.000001")))
        if results
        else "0",
        "latency_seconds_mean": _mean(latencies),
    }


COMPARED = (
    "schema_valid_rate",
    "citation_valid_rate",
    "refusal_rate",
    "accuracy",
    "cost_per_case_usd",
    "latency_seconds_mean",
)


def compare(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Metric by metric: both values and the difference (candidate minus baseline)."""
    out: dict[str, Any] = {}
    for key in COMPARED:
        a, b = baseline.get(key), candidate.get(key)
        delta = None
        if a is not None and b is not None:
            delta = round(float(b) - float(a), 6)
        out[key] = {"baseline": a, "candidate": b, "delta": delta}
    return out
