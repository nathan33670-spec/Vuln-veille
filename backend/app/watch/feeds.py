"""RSS 2.0 / RSS 1.0 / Atom parsing. defusedxml refuses entities and DTDs; the text
is reduced to plain text (tags dropped, entities decoded) and never rendered as HTML."""

import html
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

MAX_ENTRIES = 500
FEED_TYPES = (
    "application/rss+xml",
    "application/atom+xml",
    "application/xml",
    "text/xml",
    "application/rdf+xml",
)
_TAG = re.compile(r"<[^>]{0,2000}>")
_SPACE = re.compile(r"\s+")
ATOM = "{http://www.w3.org/2005/Atom}"
DC = "{http://purl.org/dc/elements/1.1/}"
RSS1 = "{http://purl.org/rss/1.0/}"


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class FeedEntry:
    title: str
    url: str | None
    content: str
    published_at: datetime | None
    author: str
    guid: str


def plain_text(value: str | None) -> str:
    if not value:
        return ""
    return _SPACE.sub(" ", html.unescape(_TAG.sub(" ", value))).strip()


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _text(node: Element | None, *paths: str) -> str | None:
    if node is None:
        return None
    for path in paths:
        found = node.find(path)
        if found is not None and (found.text or "").strip():
            return found.text
    return None


def _http(url: str | None) -> str | None:
    url = (url or "").strip()
    return url if url.lower().startswith(("http://", "https://")) else None


def _rss_item(entry: Element) -> FeedEntry:
    link = _text(entry, "link", f"{RSS1}link")
    return FeedEntry(
        title=plain_text(_text(entry, "title", f"{RSS1}title")),
        url=_http(link),
        content=plain_text(_text(entry, "description", f"{RSS1}description")),
        published_at=_date(_text(entry, "pubDate", f"{DC}date")),
        author=plain_text(_text(entry, "author", f"{DC}creator")),
        guid=(_text(entry, "guid") or link or "").strip()[:500],
    )


def _atom_entry(entry: Element) -> FeedEntry:
    url = None
    for link in entry.findall(f"{ATOM}link"):
        if link.get("rel", "alternate") == "alternate":
            url = _http(link.get("href"))
            break
    return FeedEntry(
        title=plain_text(_text(entry, f"{ATOM}title")),
        url=url,
        content=plain_text(_text(entry, f"{ATOM}summary", f"{ATOM}content")),
        published_at=_date(_text(entry, f"{ATOM}published", f"{ATOM}updated")),
        author=plain_text(_text(entry, f"{ATOM}author/{ATOM}name")),
        guid=(_text(entry, f"{ATOM}id") or url or "").strip()[:500],
    )


def parse_feed(content: bytes) -> list[FeedEntry]:
    try:
        root = ElementTree.fromstring(content, forbid_dtd=True)
    except (DefusedXmlException, ElementTree.ParseError) as exc:
        raise FeedError("invalid_feed") from exc
    if root.tag == f"{ATOM}feed":
        entries = [_atom_entry(e) for e in root.findall(f"{ATOM}entry")[:MAX_ENTRIES]]
    elif root.tag == "rss":
        entries = [_rss_item(e) for e in root.findall("channel/item")[:MAX_ENTRIES]]
    elif root.tag.endswith("RDF"):
        entries = [_rss_item(e) for e in root.findall(f"{RSS1}item")[:MAX_ENTRIES]]
    else:
        raise FeedError("unknown_feed_format")
    return entries
