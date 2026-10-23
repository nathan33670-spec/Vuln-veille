"""CSAF 2.0 export of a bulletin (OASIS, profile ``csaf_security_advisory``; spec 05 §4).

The publisher (name, category, namespace) is a setting of each workspace (Q42): the
export is refused while it is empty, rather than inventing an identity. Products come
from the bulletin's « affected products » field, else from its technologies; CVSS v3
scores are included when the bulletin carries a v3 vector.
"""

from typing import Any

from app.publish.context import Publication, PublishError
from app.vulns.models import Vulnerability

CSAF_TLP = {
    "CLEAR": "WHITE",
    "GREEN": "GREEN",
    "AMBER": "AMBER",
    "AMBER+STRICT": "AMBER",
    "RED": "RED",
}
CVSS3_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"), (0.0, "NONE"))
GENERATOR = {"engine": {"name": "Vuln-Veille"}}


def _severity(score: float) -> str:
    return next(label for floor, label in CVSS3_BANDS if score >= floor)


def _products(publication: Publication) -> tuple[list[dict[str, Any]], list[str]]:
    """The product tree branches, and every product id."""
    affected = publication.revision.fields.get("affected_products") or []
    rows = [
        (str(p.get("vendor") or "").strip(), str(p.get("product") or "").strip(),
         str(p.get("versions") or "").strip())
        for p in affected
        if isinstance(p, dict)
    ] or [(t.vendor, t.product, "") for t in publication.technologies]  # fmt: skip
    vendors: dict[str, dict[str, list[str]]] = {}
    for vendor, product, version_range in rows:
        if vendor and product:
            vendors.setdefault(vendor, {}).setdefault(product, []).append(version_range)
    branches: list[dict[str, Any]] = []
    ids: list[str] = []
    for vendor, products in vendors.items():
        product_branches = []
        for product, versions in products.items():
            entry: dict[str, Any] = {"category": "product_name", "name": product}
            ranges = [v for v in dict.fromkeys(versions) if v]
            if ranges:
                entry["branches"] = []
                for value in ranges:
                    pid = f"CSAFPID-{len(ids) + 1:04d}"
                    ids.append(pid)
                    entry["branches"].append(
                        {
                            "category": "product_version_range",
                            "name": value,
                            "product": {"name": f"{vendor} {product} {value}", "product_id": pid},
                        }
                    )
            else:
                pid = f"CSAFPID-{len(ids) + 1:04d}"
                ids.append(pid)
                entry["product"] = {"name": f"{vendor} {product}", "product_id": pid}
            product_branches.append(entry)
        branches.append({"category": "vendor", "name": vendor, "branches": product_branches})
    return branches, ids


def _score(fields: dict[str, Any], ids: list[str]) -> list[dict[str, Any]]:
    cvss = fields.get("cvss")
    if not isinstance(cvss, dict) or not ids:
        return []
    vector, score = str(cvss.get("vector") or ""), cvss.get("score")
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")) or not isinstance(score, int | float):
        return []
    return [
        {
            "cvss_v3": {
                "version": vector[5:8],
                "vectorString": vector,
                "baseScore": float(score),
                "baseSeverity": _severity(float(score)),
            },
            "products": ids,
        }
    ]


def csaf_document(publication: Publication) -> dict[str, Any]:
    settings = publication.settings
    if (
        settings is None
        or not settings.csaf_publisher_name
        or not settings.csaf_publisher_namespace
    ):
        raise PublishError("csaf_publisher_missing")
    b, r = publication.bulletin, publication.revision
    fields = dict(r.fields)
    released_at = b.published_at or b.approved_at or r.created_at
    released = released_at.isoformat()
    current = max(r.created_at, released_at).isoformat()
    branches, ids = _products(publication)
    if not ids:
        raise PublishError("csaf_no_product")
    summary = str(fields.get("summary") or b.title)
    references = [
        {"category": "external", "summary": str(ref.get("title") or ref["url"]), "url": ref["url"]}
        for ref in fields.get("references") or []
        if isinstance(ref, dict) and str(ref.get("url", "")).startswith(("https://", "http://"))
    ]
    remediation = str(fields.get("recommendations") or "").strip()
    vulnerabilities = []
    linked: list[Vulnerability | None] = [*publication.vulnerabilities] or [None]
    for v in linked:
        entry: dict[str, Any] = {
            "notes": [{"category": "summary", "title": "Résumé", "text": summary}],
            "product_status": {"known_affected": ids},
            "remediations": [
                {
                    "category": "vendor_fix"
                    if v is not None and v.patch_status == "available"
                    else "mitigation",
                    "details": remediation or summary,
                    "product_ids": ids,
                }
            ],
        }
        if v is not None and v.cve_id:
            entry["cve"] = v.cve_id
        elif v is not None:
            entry["ids"] = [{"system_name": "Vuln-Veille", "text": v.ref}]
        scores = _score(fields, ids)
        if scores:
            entry["scores"] = scores
        if v is not None:
            entry["title"] = v.title[:500]
        vulnerabilities.append(entry)
    document: dict[str, Any] = {
        "category": "csaf_security_advisory",
        "csaf_version": "2.0",
        "lang": b.language,
        "title": str(fields.get("title") or b.title),
        "publisher": {
            "category": settings.csaf_publisher_category,
            "name": settings.csaf_publisher_name,
            "namespace": settings.csaf_publisher_namespace,
        },
        "distribution": {"tlp": {"label": CSAF_TLP.get(b.tlp, "AMBER")}},
        "notes": [{"category": "summary", "title": "Résumé", "text": summary}],
        "tracking": {
            "id": b.ref,
            "status": "final" if b.status == "published" else "interim",
            "version": str(r.rev_no),
            "initial_release_date": released,
            "current_release_date": current,
            "revision_history": [
                {"number": str(r.rev_no), "date": current, "summary": f"Révision {r.rev_no}"}
            ],
            "generator": GENERATOR,
        },
    }
    if references:
        document["references"] = references
    if b.severity:
        document["aggregate_severity"] = {"text": b.severity}
    return {
        "document": document,
        "product_tree": {"branches": branches},
        "vulnerabilities": vulnerabilities,
    }
