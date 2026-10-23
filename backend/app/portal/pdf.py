"""PDF of a published bulletin (spec 06 §2, plan 8.4, Q46): WeasyPrint, sober layout.

Everything interpolated in the page is escaped, except the bulletin's HTML, already
rendered and sanitised by the server (ADR-029). Nothing is ever fetched while
rendering: only the logo, embedded as a ``data:`` URI, is resolved; any other URL
(``http``, ``file``…) is refused, so a bulletin can neither reach the network nor read
a local file.
"""

import base64
from dataclasses import dataclass, field
from datetime import datetime
from html import escape

from weasyprint import CSS, HTML
from weasyprint.urls import URLFetcher, URLFetcherResponse, URLFetchingError

TLP_COLOURS = {
    "CLEAR": ("#ffffff", "#000000"),
    "GREEN": ("#33ff00", "#000000"),
    "AMBER": ("#ffc000", "#000000"),
    "AMBER+STRICT": ("#ffc000", "#000000"),
    "RED": ("#ff2b2b", "#000000"),
}
SEVERITY = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}

STYLE = """
@page { size: A4; margin: 22mm 18mm 20mm 18mm;
  @bottom-left { content: string(reference); font-size: 8pt; color: #555; }
  @bottom-right { content: counter(page) " / " counter(pages); font-size: 8pt; color: #555; } }
body { font-family: "DejaVu Sans", sans-serif; font-size: 10pt; line-height: 1.45; color: #111; }
header { border-bottom: 1px solid #ccc; padding-bottom: 6mm; margin-bottom: 6mm; }
header img { max-height: 16mm; max-width: 60mm; float: right; }
.issuer { font-size: 9pt; color: #444; }
.ref { string-set: reference content(); font-weight: bold; }
.tlp { display: inline-block; padding: 1mm 3mm; font-weight: bold; font-size: 9pt; }
.meta { font-size: 9pt; color: #333; margin-top: 2mm; }
h1 { font-size: 16pt; } h2 { font-size: 12pt; margin-top: 6mm; }
pre, code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; white-space: pre-wrap; }
table { border-collapse: collapse; } td, th { border: 1px solid #ccc; padding: 1mm 2mm; }
a { color: #0645ad; text-decoration: none; }
blockquote { border-left: 3px solid #c00; margin-left: 0; padding-left: 4mm; }
"""


class _EmbeddedOnly(URLFetcher):  # type: ignore[misc]  # untyped library
    """Resolves the embedded logo only; every other URL is refused."""

    def __init__(self) -> None:
        super().__init__(allowed_protocols=("data",), allow_redirects=False)
        self.refused: list[str] = []

    def fetch(self, url: str, headers: dict[str, str] | None = None) -> URLFetcherResponse:
        if not url.startswith("data:image/png;base64,"):
            self.refused.append(url[:60])
            raise URLFetchingError("external resources are not loaded")
        return super().fetch(url, headers)


@dataclass(frozen=True)
class PdfBulletin:
    ref: str
    title: str
    severity: str | None
    tlp: str
    team: str
    language: str
    published_at: datetime
    updated_at: datetime
    cves: list[str]
    technologies: list[str]
    html: str = field(repr=False)


def bulletin_page(bulletin: PdfBulletin, issuer: str, logo_png: bytes | None) -> str:
    background, colour = TLP_COLOURS.get(bulletin.tlp, ("#ffffff", "#000000"))
    logo = (
        f'<img alt="" src="data:image/png;base64,{base64.b64encode(logo_png).decode()}">'
        if logo_png
        else ""
    )
    dates = f"Publié le {bulletin.published_at:%d/%m/%Y}"
    if bulletin.updated_at > bulletin.published_at:
        dates += f" · mis à jour le {bulletin.updated_at:%d/%m/%Y}"
    facts = [
        f"Sévérité : {escape(SEVERITY.get(bulletin.severity or '', '—'))}",
        f"Émis par : {escape(bulletin.team)}",
        escape(dates),
    ]
    if bulletin.cves:
        facts.append("CVE : " + escape(", ".join(bulletin.cves)))
    if bulletin.technologies:
        facts.append("Technologies : " + escape(", ".join(bulletin.technologies)))
    return (
        f'<!doctype html><html lang="{escape(bulletin.language)}"><head><meta charset="utf-8">'
        f"<title>{escape(bulletin.ref)} — {escape(bulletin.title)}</title></head><body>"
        f'<header>{logo}<div class="issuer">{escape(issuer)}</div>'
        f'<div class="ref">{escape(bulletin.ref)}</div>'
        f'<span class="tlp" style="background:{background};color:{colour}">'
        f"TLP:{escape(bulletin.tlp)}</span>"
        f'<div class="meta">{"<br>".join(facts)}</div></header>'
        f"<main>{bulletin.html}</main></body></html>"
    )


def render_pdf(bulletin: PdfBulletin, issuer: str = "", logo_png: bytes | None = None) -> bytes:
    fetcher = _EmbeddedOnly()
    document = HTML(string=bulletin_page(bulletin, issuer, logo_png), url_fetcher=fetcher)
    return bytes(document.write_pdf(stylesheets=[CSS(string=STYLE)]))
