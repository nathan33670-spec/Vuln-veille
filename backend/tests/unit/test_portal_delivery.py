"""Portal delivery without a database (plan 8.4, Q44 to Q46): the logo re-encoded,
the PDF rendered without fetching anything, the addressing rule, the messages."""

import io
import uuid
from datetime import UTC, datetime

import pytest
from PIL import Image
from weasyprint import HTML

from app.bulletins.models import BulletinRevision, PublicationEvent
from app.portal.branding import LogoError, normalize_logo
from app.portal.mailing import _messages, visible_to
from app.portal.pdf import PdfBulletin, _EmbeddedOnly, bulletin_page, render_pdf

ACME, BETA = uuid.UUID(int=1), uuid.UUID(int=2)
NOW = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)


def _image(fmt: str, size: tuple[int, int] = (1200, 300)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, (200, 30, 30)).save(out, format=fmt)
    return out.getvalue()


def test_logo_is_reencoded_as_png_and_bounded() -> None:
    for fmt in ("PNG", "JPEG"):
        logo = normalize_logo(_image(fmt))
        with Image.open(io.BytesIO(logo)) as image:
            assert image.format == "PNG"
            assert image.width <= 600 and image.height <= 200  # noqa: PT018
    # Bytes appended to a valid image (a polyglot) do not survive the re-encoding.
    tainted = _image("PNG", (40, 20)) + b"<script>alert(1)</script>"
    assert b"<script>" not in normalize_logo(tainted)


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "logo_format"),
        (b"not an image", "logo_format"),
        (_image("GIF", (10, 10)), "logo_format"),
        (_image("PNG")[:40], "logo_format"),
        (b"\x89PNG" + b"0" * (600 * 1024), "logo_too_large"),
    ],
)
def test_logo_refusals(raw: bytes, code: str) -> None:
    with pytest.raises(LogoError, match=code):
        normalize_logo(raw)


def _bulletin(**changes: object) -> PdfBulletin:
    values: dict[str, object] = {
        "ref": "CERT-2026-0001",
        "title": "RCE <script>alert(1)</script>",
        "severity": "critical",
        "tlp": "AMBER",
        "team": "CERT",
        "language": "fr",
        "published_at": NOW,
        "updated_at": NOW,
        "cves": ["CVE-2026-0001"],
        "technologies": ["Exemple Serveur"],
        "html": "<h1>RCE</h1><p>Contenu.</p>",
    }
    values.update(changes)
    return PdfBulletin(**values)  # type: ignore[arg-type]


def test_pdf_page_escapes_and_renders() -> None:
    page = bulletin_page(_bulletin(), "CERT <Exemple>", None)
    assert "<script>" not in page.split("<main>")[0]
    assert "CERT &lt;Exemple&gt;" in page
    pdf = render_pdf(_bulletin(), "CERT Exemple", normalize_logo(_image("PNG", (300, 100))))
    assert pdf.startswith(b"%PDF-")


def test_pdf_never_fetches_anything() -> None:
    fetcher = _EmbeddedOnly()
    hostile = (
        '<img src="http://evil.example/x.png"><img src="file:///etc/passwd">'
        '<link rel="stylesheet" href="https://evil.example/x.css">'
    )
    HTML(string=bulletin_page(_bulletin(html=hostile), "", None), url_fetcher=fetcher).write_pdf()
    assert sorted(fetcher.refused) == [
        "file:///etc/passwd",
        "http://evil.example/x.png",
        "https://evil.example/x.css",
    ]


def _event(
    tlp: str, audience: list[uuid.UUID] | None = None, kind: str = "published"
) -> PublicationEvent:
    return PublicationEvent(
        id=uuid.uuid4(),
        bulletin_id=uuid.uuid4(),
        kind=kind,
        at=NOW,
        ref="CERT-2026-0001",
        language="fr",
        team="CERT",
        title="RCE",
        severity="critical",
        tlp=tlp,
        audience_type="selected" if audience else "all_clients",
        audience_org_ids=audience or [],
        cves=[],
        technologies=[],
    )


@pytest.mark.parametrize(
    ("tlp", "audience", "acme", "beta"),
    [
        ("CLEAR", None, True, True),
        ("GREEN", None, True, True),
        ("GREEN", [ACME], True, False),
        ("AMBER", None, False, False),
        ("AMBER", [BETA], False, True),
        ("AMBER+STRICT", [ACME], True, False),
        ("RED", [ACME, BETA], False, False),
    ],
)
def test_addressing_follows_the_portal_rule(
    tlp: str, audience: list[uuid.UUID] | None, acme: bool, beta: bool
) -> None:
    event = _event(tlp, audience)
    assert (visible_to(event, ACME), visible_to(event, BETA)) == (acme, beta)


def test_messages_carry_the_bulletin_or_a_notice() -> None:
    revision = BulletinRevision(rendered_markdown="# RCE", rendered_html="<h1>RCE</h1>")
    mails = _messages(
        ["a@acme.example", "b@acme.example"], _event("AMBER", [ACME], "updated"), revision,
        b"%PDF-1.7", "CERT Exemple", "https://portal.example/bulletins/x",
    )  # fmt: skip
    assert [m.to for m in mails] == ["a@acme.example", "b@acme.example"]  # one each
    assert mails[0].subject == "[TLP:AMBER] Mise à jour : CERT-2026-0001 — RCE"
    assert "TLP:AMBER" in mails[0].body
    assert mails[0].html is not None and "<h1>RCE</h1>" in mails[0].html  # noqa: PT018
    assert [(a.filename, a.content_type) for a in mails[0].attachments] == [
        ("CERT-2026-0001.pdf", "application/pdf")
    ]
    notice = _messages(["a@acme.example"], _event("GREEN", None, "withdrawn"), None, None, "X", "")
    assert notice[0].subject.startswith("[TLP:GREEN] Retrait : ")
    assert (notice[0].html, notice[0].attachments) == (None, ())
