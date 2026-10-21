"""Watch scope matching: does a new CVE deserve an investigation? (spec 07 §3.4)

Order of the rules:
1. a rejected CVE is out;
2. KEV entries are always in (unless disabled);
3. an excluded CWE puts it out;
4. ``all`` mode: in. ``scoped`` mode: the CVE must match a followed technology (CPE
   prefix, then product name or alias in the description), a vendor (CPE vendor or
   name in the description), a keyword, or an included CWE;
5. CVSS threshold; a CVE without a score yet is included, put on hold or excluded.

The decision carries its reasons, shown to analysts and kept in workflow runs.
"""

import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal

from app.catalog.models import CveRecord
from app.technologies.models import Technology
from app.watch.models import WatchScope

Decision = Literal["in_scope", "out_of_scope", "pending"]


@dataclass(frozen=True)
class ScopeDecision:
    decision: Decision
    reasons: list[str] = field(default_factory=list)

    @property
    def in_scope(self) -> bool:
        return self.decision == "in_scope"


def _word(term: str) -> re.Pattern[str]:
    # Whole words, case-insensitive: "ssh" must not match "sshd" or "rssh".
    return re.compile(rf"(?<![\w-]){re.escape(term.strip())}(?![\w-])", re.IGNORECASE)


def _cpe_vendor(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[3] if len(parts) > 3 else ""  # noqa: PLR2004 - cpe:2.3:part:vendor


def subject_matches(scope: WatchScope, cve: CveRecord, technologies: list[Technology]) -> list[str]:
    reasons = []
    description = cve.description or ""
    for tech in technologies:
        if any(c.startswith(p) for p in tech.cpe_prefixes for c in cve.cpe_criteria):
            reasons.append(f"technology:{tech.vendor}:{tech.product}:cpe")
            continue
        names = [tech.display_name, tech.product.replace("_", " "), *tech.aliases]
        if any(len(n) >= 3 and _word(n).search(description) for n in names):  # noqa: PLR2004
            reasons.append(f"technology:{tech.vendor}:{tech.product}:description")
    vendors = {_cpe_vendor(c) for c in cve.cpe_criteria}
    for vendor in scope.vendors:
        if vendor.lower().replace(" ", "_") in vendors or _word(vendor).search(description):
            reasons.append(f"vendor:{vendor}")
    reasons.extend(f"keyword:{k}" for k in scope.keywords if _word(k).search(description))
    reasons.extend(f"cwe:{c}" for c in scope.cwe_include if c in cve.cwes)
    return reasons


def match(  # noqa: PLR0911 - one return per rule reads like the spec
    scope: WatchScope, cve: CveRecord, technologies: list[Technology]
) -> ScopeDecision:
    """``technologies``: the scope's followed technologies, merges already resolved."""
    if cve.vuln_status == "Rejected":
        return ScopeDecision("out_of_scope", ["rejected"])
    if scope.always_include_kev and cve.kev:
        return ScopeDecision("in_scope", ["kev"])
    excluded = [c for c in scope.cwe_exclude if c in cve.cwes]
    if excluded:
        return ScopeDecision("out_of_scope", [f"cwe_excluded:{c}" for c in excluded])
    if scope.mode == "all":
        reasons = ["mode:all"]
    else:
        reasons = subject_matches(scope, cve, technologies)
        if not reasons:
            return ScopeDecision("out_of_scope", ["no_match"])
    if cve.base_score is None:
        if scope.include_unscored == "include":
            return ScopeDecision("in_scope", [*reasons, "unscored:included"])
        if scope.include_unscored == "wait":
            return ScopeDecision("pending", [*reasons, "unscored:waiting"])
        return ScopeDecision("out_of_scope", [*reasons, "unscored:excluded"])
    if scope.cvss_min is not None and Decimal(cve.base_score) < scope.cvss_min:
        return ScopeDecision("out_of_scope", [*reasons, f"cvss_below:{scope.cvss_min}"])
    return ScopeDecision("in_scope", reasons)
