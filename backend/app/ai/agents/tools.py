"""Read-only tools offered to agents (spec 03 §5).

A tool reads: the local catalogue, the workspace's own records, or an outside service
through one of the connectors the agent is allowed to use (egress policy, quotas and
secrets of that connector apply). No tool writes to the database, sends a message or
touches a publication connector. Nothing fetched is ever executed: ``github_get``
returns text only and refuses binaries and archives.

Results are documents marked untrusted with their provenance (``guards.document``).
"""

import base64
import binascii
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.guards import Flag, document, scan
from app.ai.agents.spec import TOOL_NAMES, AgentSpec
from app.ai.types import ToolSpec
from app.catalog.models import CveRecord
from app.connectors.base import ConnectorContext
from app.connectors.found import FetchError, Found, as_dict, fetch, json_of
from app.connectors.models import Connector
from app.connectors.runtime import build_context
from app.connectors.types import bluesky, hackernews, mastodon, osv, reddit, stackexchange, web
from app.connectors.types.github import API as GITHUB_API
from app.connectors.types.github import github_headers
from app.connectors.types.rss import host_allowed
from app.connectors.types.x_reader import POST_URL, discover_post_urls, read_post
from app.core.config import Settings
from app.core.narrow import expect
from app.net.safe_http import EgressError, SafeHttpClient
from app.technologies.models import Technology
from app.vault.crypto import VaultError
from app.vault.service import Vault
from app.vulns.models import Assessment, Vulnerability
from app.watch.models import CollectedItem

CVE_ID = r"^CVE-\d{4}-\d{4,7}$"
MAX_FILE_BYTES = 512 * 1024
REFUSED_EXTENSIONS = frozenset(
    {
        ".exe", ".dll", ".scr", ".msi", ".so", ".dylib", ".bin", ".elf", ".o", ".class",
        ".jar", ".war", ".apk", ".dmg", ".iso", ".img", ".zip", ".rar", ".7z", ".gz",
        ".tgz", ".bz2", ".xz", ".tar", ".cab", ".deb", ".rpm", ".pyc", ".whl", ".png",
        ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".docx", ".xlsx", ".pptx",
    }
)  # fmt: skip
_REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_PATH = re.compile(r"^[A-Za-z0-9._/@+-]{1,300}$")
SOCIAL = {
    "mastodon": mastodon.search,
    "bluesky": bluesky.search,
    "reddit": reddit.search,
    "hackernews": hackernews.search,
}


class ToolError(Exception):
    """A tool could not answer; ``code`` is safe to show the model and the analyst."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code[:200]


@dataclass
class ToolOutput:
    documents: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, found: Found, *, poc: bool = False) -> None:
        extra = {"author": found.author} if found.author else {}
        if found.published_at:
            extra["published_at"] = found.published_at.isoformat()
        entry = document(found.source, found.url, found.title, found.content)
        entry["untrusted_document"].update(extra)
        self.documents.append(entry)
        if found.url:
            self.sources.append(found.url)
        self.flags.extend(
            scan(f"{found.title}\n{found.content}", found.url or found.source, poc=poc)
        )


@dataclass
class ToolConnectors:
    """The agent's allowed connectors (workspace or global, enabled, source family)."""

    db: AsyncSession
    settings: Settings
    vault: Vault
    workspace_id: uuid.UUID
    allowed: tuple[uuid.UUID, ...]
    redis: Redis | None = None
    http: SafeHttpClient | None = None  # tests only
    _opened: dict[uuid.UUID, ConnectorContext] = field(default_factory=dict)

    async def rows(self, kinds: tuple[str, ...]) -> list[Connector]:
        if not self.allowed:
            return []
        result = await self.db.execute(
            select(Connector)
            .where(
                Connector.id.in_(self.allowed),
                Connector.kind.in_(kinds),
                Connector.family == "source",
                Connector.enabled.is_(True),
                or_(Connector.workspace_id.is_(None), Connector.workspace_id == self.workspace_id),
            )
            .order_by(Connector.name)
        )
        return list(result.scalars())

    async def context(self, connector: Connector) -> ConnectorContext:
        if connector.id not in self._opened:
            try:
                _, ctx = await build_context(
                    self.db, self.settings, self.vault, connector, self.redis
                )
            except EgressError as exc:
                raise ToolError(f"egress: {exc.code}") from None
            except VaultError:
                raise ToolError("secret_unavailable") from None
            except (ValidationError, KeyError):
                raise ToolError("invalid_connector_configuration") from None
            if self.http is not None:
                ctx.http = self.http
            self._opened[connector.id] = ctx
        return self._opened[connector.id]

    async def one(self, kinds: tuple[str, ...]) -> ConnectorContext:
        rows = await self.rows(kinds)
        if not rows:
            raise ToolError("no_allowed_connector")
        return await self.context(rows[0])


@dataclass
class ToolContext:
    db: AsyncSession
    workspace_id: uuid.UUID
    spec: AgentSpec
    connectors: ToolConnectors
    now: datetime


Runner = Callable[[ToolContext, dict[str, Any]], Awaitable[ToolOutput]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    run: Runner
    connector_kinds: tuple[str, ...] = ()  # empty: local data, no connector needed

    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.parameters)


def _object(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def _string(max_length: int = 200, **extra: Any) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": max_length, **extra}


CVE = _string(20, pattern=CVE_ID)
QUERY = _string(200)


def _limit(ctx: ToolContext) -> int:
    return ctx.spec.tool_config.max_results


# Local catalogue and workspace data ---------------------------------------------


async def _cve(ctx: ToolContext, cve_id: str) -> CveRecord:
    record = await ctx.db.get(CveRecord, cve_id.upper())
    if record is None:
        raise ToolError("not_in_catalogue")
    return record


async def nvd_lookup(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    record = await _cve(ctx, args["cve_id"])
    references = [str(r.get("url")) for r in record.references[:50] if r.get("url")]
    out = ToolOutput()
    out.documents.append(
        document(
            "nvd",
            f"https://nvd.nist.gov/vuln/detail/{record.cve_id}",
            record.cve_id,
            {
                "description": record.description,
                "published_at": record.published_at.isoformat() if record.published_at else None,
                "status": record.vuln_status,
                "base_score": str(record.base_score) if record.base_score is not None else None,
                "severity": record.severity,
                "cvss": record.cvss,
                "cwes": record.cwes,
                "cpe_criteria": record.cpe_criteria[:50],
                "references": references,
            },
        )
    )
    out.sources.extend([f"https://nvd.nist.gov/vuln/detail/{record.cve_id}", *references])
    out.flags.extend(scan(record.description, f"nvd:{record.cve_id}"))
    return out


async def epss_lookup(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    ids = sorted({c.upper() for c in args["cve_ids"]})
    rows = await ctx.db.execute(select(CveRecord).where(CveRecord.cve_id.in_(ids)))
    found = {r.cve_id: r for r in rows.scalars()}
    out = ToolOutput()
    for cve_id in ids:
        record = found.get(cve_id)
        out.documents.append(
            {
                "epss": {
                    "cve_id": cve_id,
                    "score": str(record.epss_score) if record and record.epss_score else None,
                    "percentile": str(record.epss_percentile)
                    if record and record.epss_percentile
                    else None,
                    "date": record.epss_date.isoformat() if record and record.epss_date else None,
                }
            }
        )
    return out


async def kev_lookup(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    record = await _cve(ctx, args["cve_id"])
    out = ToolOutput()
    out.documents.append(
        document(
            "cisa_kev",
            None,
            record.cve_id,
            {"in_kev": record.kev is not None, **(record.kev or {})},
        )
    )
    return out


async def internal_vuln_search(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    query = select(Vulnerability, Assessment).join(
        Assessment,
        (Assessment.vulnerability_id == Vulnerability.id)
        & (Assessment.workspace_id == ctx.workspace_id),
    )
    if args.get("cve_id"):
        cve_id = str(args["cve_id"]).upper()
        query = query.where(
            or_(Vulnerability.cve_id == cve_id, Vulnerability.aliases.contains([cve_id]))
        )
    if args.get("query"):
        like = f"%{_escape_like(str(args['query']))}%"
        query = query.where(
            or_(
                Vulnerability.title.ilike(like, escape="\\"),
                Vulnerability.ref.ilike(like, escape="\\"),
            )
        )
    if not args.get("cve_id") and not args.get("query"):
        raise ToolError("cve_id_or_query_required")
    rows = await ctx.db.execute(
        query.order_by(Vulnerability.first_seen_at.desc()).limit(_limit(ctx))
    )
    out = ToolOutput()
    for vuln, assessment in rows.all():
        out.documents.append(
            {
                "internal_vulnerability": {
                    "id": str(vuln.id),
                    "ref": vuln.ref,
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "exploitation_status": vuln.exploitation_status,
                    "patch_status": vuln.patch_status,
                    "status": assessment.status,
                    "priority": assessment.priority,
                }
            }
        )
    return out


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def technology_lookup(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    like = f"%{_escape_like(str(args['query']))}%"
    rows = await ctx.db.execute(
        select(Technology)
        .where(
            Technology.status == "active",
            or_(
                Technology.display_name.ilike(like, escape="\\"),
                Technology.vendor.ilike(like, escape="\\"),
                Technology.product.ilike(like, escape="\\"),
                func.array_to_string(Technology.aliases, " ").ilike(like, escape="\\"),
            ),
        )
        .order_by(Technology.display_name)
        .limit(_limit(ctx))
    )
    out = ToolOutput()
    for tech in rows.scalars():
        out.documents.append(
            {
                "technology": {
                    "id": str(tech.id),
                    "vendor": tech.vendor,
                    "product": tech.product,
                    "display_name": tech.display_name,
                    "aliases": tech.aliases,
                    "cpe_prefixes": tech.cpe_prefixes,
                    "purls": tech.purls,
                }
            }
        )
    return out


# Connectors ----------------------------------------------------------------------


async def osv_lookup(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    connector = await ctx.connectors.one(("osv",))
    out = ToolOutput()
    try:
        if args.get("id"):
            found = await osv.lookup(connector, str(args["id"]))
            if found is not None:
                out.add(found)
        elif args.get("purl"):
            for found in (await osv.by_package(connector, str(args["purl"])))[: _limit(ctx)]:
                out.add(found)
        else:
            raise ToolError("id_or_purl_required")
    except FetchError as exc:
        raise ToolError(exc.code) from None
    return out


GITHUB_KINDS = ("repositories", "code", "commits", "issues")


def _github_item(kind: str, entry: dict[str, Any]) -> Found | None:
    url = entry.get("html_url")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        return None
    repo = as_dict(entry.get("repository"))
    if kind == "repositories":
        owner = as_dict(entry.get("owner"))
        return Found(
            source="github",
            url=url,
            title=str(entry.get("full_name") or ""),
            content=str(entry.get("description") or ""),
            author=str(owner.get("login") or ""),
            extra={
                "stars": entry.get("stargazers_count"),
                "forks": entry.get("forks_count"),
                "fork": entry.get("fork"),
                "archived": entry.get("archived"),
                "created_at": entry.get("created_at"),
                "pushed_at": entry.get("pushed_at"),
            },
        )
    if kind == "code":
        return Found(
            source="github",
            url=url,
            title=f"{repo.get('full_name', '')}:{entry.get('path', '')}",
            content="",
        )
    if kind == "commits":
        commit = as_dict(entry.get("commit"))
        return Found(
            source="github",
            url=url,
            title=str(repo.get("full_name") or ""),
            content=str(commit.get("message") or "")[:2000],
        )
    return Found(
        source="github",
        url=url,
        title=str(entry.get("title") or ""),
        content=str(entry.get("body") or "")[:2000],
        extra={"state": entry.get("state")},
    )


async def github_search(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    connector = await ctx.connectors.one(("github",))
    kind = str(args.get("kind") or "repositories")
    try:
        response = await fetch(
            connector,
            "GET",
            f"{GITHUB_API}/search/{kind}",
            headers=github_headers(connector),
            params={"q": str(args["query"]), "per_page": str(_limit(ctx))},
        )
    except FetchError as exc:
        raise ToolError(exc.code) from None
    out = ToolOutput()
    items = as_dict(json_of(response)).get("items")
    for entry in items if isinstance(items, list) else []:
        found = _github_item(kind, as_dict(entry))
        if found is not None:
            out.add(found, poc=kind == "repositories")
    return out


def _refused_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in REFUSED_EXTENSIONS)


async def github_get(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    repo, path = str(args["repo"]), str(args.get("path") or "")
    if not _REPO.fullmatch(repo) or ".." in repo:
        raise ToolError("invalid_repository")
    if path and (not _PATH.fullmatch(path) or ".." in path.split("/")):
        raise ToolError("invalid_path")
    if path and _refused_path(path):
        raise ToolError("binary_or_archive_refused")
    connector = await ctx.connectors.one(("github",))
    endpoint = f"{GITHUB_API}/repos/{repo}/" + (
        f"contents/{quote(path, safe='/')}" if path else "readme"
    )
    try:
        response = await fetch(connector, "GET", endpoint, headers=github_headers(connector))
    except FetchError as exc:
        raise ToolError(exc.code) from None
    data = json_of(response)
    out = ToolOutput()
    url = f"https://github.com/{repo}"
    if isinstance(data, list):  # a directory: names only
        listing = [
            {"name": str(e.get("path") or ""), "type": e.get("type"), "size": e.get("size")}
            for e in (as_dict(x) for x in data[:200])
        ]
        out.documents.append(
            document("github", f"{url}/tree/HEAD/{path}", path, {"entries": listing})
        )
        out.sources.append(f"{url}/tree/HEAD/{path}")
        out.flags.extend(scan("\n".join(str(e["name"]) for e in listing), url, poc=True))
        return out
    entry = as_dict(data)
    name = str(entry.get("path") or path or "README")
    if entry.get("type") != "file" or entry.get("encoding") != "base64":
        raise ToolError("not_a_text_file")
    if _refused_path(name):
        raise ToolError("binary_or_archive_refused")
    if int(entry.get("size") or 0) > MAX_FILE_BYTES:
        raise ToolError("file_too_large")
    try:
        raw = base64.b64decode(str(entry.get("content") or ""), validate=False)
    except (binascii.Error, ValueError):
        raise ToolError("invalid_content") from None
    if b"\x00" in raw:
        raise ToolError("binary_or_archive_refused")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ToolError("binary_or_archive_refused") from None
    html_url = entry.get("html_url")
    source_url = html_url if isinstance(html_url, str) and html_url.startswith(url) else url
    out.add(Found(source="github", url=source_url, title=f"{repo}:{name}", content=text), poc=True)
    return out


async def x_discover(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    """Layer 1 (spec 07 §2.1): X post URLs cited by collected items and NVD references.
    Layer 2 (the engine's web search restricted to x.com) comes with the social agent."""
    await ctx.connectors.one(("x_reader",))  # the tool belongs to an allowed connector
    cve_id, query = args.get("cve_id"), args.get("query")
    if not cve_id and not query:
        raise ToolError("cve_id_or_query_required")
    texts: list[str] = []
    items = select(CollectedItem.url, CollectedItem.content_text).where(
        CollectedItem.workspace_id == ctx.workspace_id
    )
    if cve_id:
        cve_id = str(cve_id).upper()
        items = items.where(CollectedItem.cve_ids.contains([cve_id]))
        record = await ctx.db.get(CveRecord, cve_id)
        if record is not None:
            texts.extend(str(r.get("url") or "") for r in record.references)
    if query:
        items = items.where(
            CollectedItem.content_text.ilike(f"%{_escape_like(str(query))}%", escape="\\")
        )
    rows = await ctx.db.execute(items.order_by(CollectedItem.fetched_at.desc()).limit(500))
    for url, content in rows.all():
        texts.extend((url or "", content or ""))
    urls = discover_post_urls("\n".join(texts))[: _limit(ctx)]
    out = ToolOutput()
    out.documents.append({"x_post_urls": urls})
    out.sources.extend(urls)
    return out


async def x_read(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    connector = await ctx.connectors.one(("x_reader",))
    try:
        found = await read_post(connector, str(args["url"]))
    except FetchError as exc:
        raise ToolError(exc.code) from None
    out = ToolOutput()
    if found is None:
        out.documents.append({"x_post": {"url": str(args["url"]), "withdrawn": True}})
    else:
        out.add(found)
    return out


async def social_search(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    platforms = tuple(args.get("platforms") or SOCIAL)
    rows = await ctx.connectors.rows(platforms)
    if not rows:
        raise ToolError("no_allowed_connector")
    out = ToolOutput()
    for connector in rows:
        try:
            ctx_ = await ctx.connectors.context(connector)
            found = await SOCIAL[connector.kind](ctx_, str(args["query"]), _limit(ctx))
        except (FetchError, ToolError) as exc:
            out.errors.append(f"{connector.kind}: {exc.code}")
            continue
        for entry in found[: _limit(ctx)]:
            out.add(entry)
    return out


async def stackexchange_search(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    connector = await ctx.connectors.one(("stackexchange",))
    try:
        found = await stackexchange.search(connector, str(args["query"]), _limit(ctx))
    except FetchError as exc:
        raise ToolError(exc.code) from None
    out = ToolOutput()
    for entry in found:
        out.add(entry)
    return out


async def web_fetch(ctx: ToolContext, args: dict[str, Any]) -> ToolOutput:
    url = str(args["url"])
    if urlsplit(url).scheme != "https":
        raise ToolError("https_only")
    narrowed = ctx.spec.tool_config.web_domains
    if narrowed and not host_allowed(url, narrowed):
        raise ToolError("domain_not_allowed")
    for connector in await ctx.connectors.rows(("web",)):
        config = expect(web.WebConfig.model_validate(connector.config), web.WebConfig)
        if host_allowed(url, config.allowed_domains):
            try:
                found = await web.read_page(await ctx.connectors.context(connector), url)
            except FetchError as exc:
                raise ToolError(exc.code) from None
            out = ToolOutput()
            out.add(found)
            return out
    raise ToolError("domain_not_allowed")


TOOLS: Mapping[str, Tool] = {
    t.name: t
    for t in (
        Tool(
            "nvd_lookup",
            "Fiche NVD d'une CVE (catalogue local) : description, CVSS, CWE, CPE, références.",
            _object({"cve_id": CVE}, ("cve_id",)),
            nvd_lookup,
        ),
        Tool(
            "epss_lookup",
            "Score et percentile EPSS d'une ou plusieurs CVE (catalogue local).",
            _object(
                {"cve_ids": {"type": "array", "items": CVE, "minItems": 1, "maxItems": 20}},
                ("cve_ids",),
            ),
            epss_lookup,
        ),
        Tool(
            "kev_lookup",
            "Présence d'une CVE au catalogue KEV de la CISA (exploitation avérée) et détails.",
            _object({"cve_id": CVE}, ("cve_id",)),
            kev_lookup,
        ),
        Tool(
            "osv_lookup",
            "Avis OSV par identifiant (CVE, GHSA…) ou vulnérabilités d'un paquet (purl).",
            _object({"id": _string(100), "purl": _string(300)}),
            osv_lookup,
            ("osv",),
        ),
        Tool(
            "internal_vuln_search",
            "Vulnérabilités déjà suivies par l'espace (doublons, historique), par CVE ou texte.",
            _object({"cve_id": CVE, "query": QUERY}),
            internal_vuln_search,
        ),
        Tool(
            "technology_lookup",
            "Recherche dans le catalogue des technologies (éditeur, produit, alias, CPE, purl).",
            _object({"query": QUERY}, ("query",)),
            technology_lookup,
        ),
        Tool(
            "github_search",
            "Recherche GitHub (dépôts, code, commits, issues), par exemple des PoC d'une CVE.",
            _object(
                {"query": _string(256), "kind": {"type": "string", "enum": list(GITHUB_KINDS)}},
                ("query",),
            ),
            github_search,
            ("github",),
        ),
        Tool(
            "github_get",
            "Lit en texte le README (sans path), un fichier ou la liste d'un dossier d'un dépôt "
            "GitHub. Aucun binaire ni archive ; rien n'est exécuté.",
            _object({"repo": _string(140), "path": _string(300)}, ("repo",)),
            github_get,
            ("github",),
        ),
        Tool(
            "x_discover",
            "URL de posts X déjà citées par les sources collectées et les références NVD.",
            _object({"cve_id": CVE, "query": QUERY}),
            x_discover,
            ("x_reader",),
        ),
        Tool(
            "x_read",
            "Texte d'un post X public à partir de son URL (oEmbed officiel, gratuit).",
            _object({"url": _string(300, pattern=POST_URL.pattern)}, ("url",)),
            x_read,
            ("x_reader",),
        ),
        Tool(
            "social_search",
            "Posts et discussions sur Mastodon, Bluesky, Reddit et Hacker News.",
            _object(
                {
                    "query": QUERY,
                    "platforms": {
                        "type": "array",
                        "items": {"type": "string", "enum": list(SOCIAL)},
                        "maxItems": len(SOCIAL),
                    },
                },
                ("query",),
            ),
            social_search,
            tuple(SOCIAL),
        ),
        Tool(
            "stackexchange_search",
            "Questions et réponses Stack Overflow / Stack Exchange par mots-clés.",
            _object({"query": QUERY}, ("query",)),
            stackexchange_search,
            ("stackexchange",),
        ),
        Tool(
            "web_fetch",
            "Texte d'une page web (avis éditeur…) sur un domaine autorisé, en HTTPS.",
            _object({"url": _string(2048, pattern="^https://")}, ("url",)),
            web_fetch,
            ("web",),
        ),
    )
}
if set(TOOLS) != TOOL_NAMES:  # pragma: no cover - import-time consistency check
    raise RuntimeError("tool registry and TOOL_NAMES differ")


def tool_specs(names: list[str]) -> tuple[ToolSpec, ...]:
    return tuple(TOOLS[n].spec() for n in sorted(names))
