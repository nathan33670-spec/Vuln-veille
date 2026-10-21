"""Free watch connectors (spec 07 §2) against a fake web, through SafeHttpClient."""

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from app.connectors.base import ConnectorConfig, ConnectorContext, registered
from app.connectors.found import FetchError
from app.connectors.types import (
    bluesky,
    hackernews,
    mastodon,
    osv,
    reddit,
    stackexchange,
    web,
    x_reader,
)
from tests.web_fakes import FakeWeb, RawBody


def _ctx(
    fake: FakeWeb, config: ConnectorConfig, secrets: dict[str, str] | None = None
) -> ConnectorContext:
    kind = next(t for t in registered().values() if isinstance(config, t.config_model))
    return ConnectorContext(
        connector_id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        config=config,
        secrets=secrets or {},
        http=fake.client(*kind.egress_for(config)),
    )


def test_every_watch_connector_is_free() -> None:
    kinds = {
        "x_reader",
        "stackexchange",
        "mastodon",
        "bluesky",
        "reddit",
        "hackernews",
        "osv",
        "web",
    }
    types = registered()
    assert kinds <= set(types)
    assert {types[k].cost_class for k in kinds} <= {"free", "free_account"}


# X ----------------------------------------------------------------------------

OEMBED_HTML = (
    '<blockquote class="twitter-tweet"><p lang="en" dir="ltr">PoC for CVE-2026-1234 '
    '<a href="https://t.co/x">github.com/x/poc</a><br>patch now &amp; rotate keys</p>'
    "&mdash; Researcher (@researcher) "
    '<a href="https://twitter.com/researcher/status/1849000000000000000?ref_src=twsrc">'
    'October 20, 2026</a></blockquote>\n<script async src="https://platform.twitter.com/widgets.js"></script>'
)


def test_x_post_discovery_from_collected_text() -> None:
    text = (
        "See https://twitter.com/researcher/status/1849000000000000000 and "
        "https://x.com/other_one/status/1849000000000000001?s=20, also "
        "https://x.com/researcher/status/1849000000000000000 again; not https://x.com/home"
    )
    assert x_reader.discover_post_urls(text) == [
        "https://x.com/researcher/status/1849000000000000000",
        "https://x.com/other_one/status/1849000000000000001",
    ]


async def test_x_reading_through_official_oembed() -> None:
    fake = FakeWeb()
    seen: list[httpx.QueryParams] = []

    def oembed(request: httpx.Request) -> tuple[int, Any]:
        seen.append(request.url.params)
        if request.url.params["url"].endswith("0001"):
            return 404, {"error": "gone"}
        return 200, {
            "url": "https://twitter.com/researcher/status/1849000000000000000",
            "author_name": "Researcher",
            "author_url": "https://twitter.com/researcher",
            "html": OEMBED_HTML,
            "cache_age": "3153600000",
        }

    fake.routes[x_reader.OEMBED] = oembed
    ctx = _ctx(fake, x_reader.XReaderConfig())
    post = await x_reader.read_post(
        ctx, "https://twitter.com/researcher/status/1849000000000000000"
    )
    assert post is not None
    assert post.content == "PoC for CVE-2026-1234 github.com/x/poc patch now & rotate keys"
    assert post.author == "@researcher"
    assert post.published_at == datetime(2026, 10, 20, tzinfo=UTC)
    assert seen[0]["url"] == "https://x.com/researcher/status/1849000000000000000"
    assert seen[0]["omit_script"] == "1"
    assert await x_reader.read_post(ctx, "https://x.com/gone/status/1849000000000000001") is None
    with pytest.raises(FetchError, match="not_an_x_post_url"):
        await x_reader.read_post(ctx, "https://x.com/researcher")  # profiles are never read


# Stack Exchange, Hacker News ---------------------------------------------------


async def test_stackexchange_search() -> None:
    fake = FakeWeb()
    fake.json(
        "https://api.stackexchange.com/2.3/search/advanced",
        {
            "items": [
                {
                    "link": "https://stackoverflow.com/questions/1",
                    "title": "Log4j &quot;JNDI&quot; mitigation",
                    "tags": ["java", "log4j"],
                    "owner": {"display_name": "dev &amp; ops"},
                    "creation_date": 1760000000,
                    "score": 12,
                    "is_answered": True,
                    "answer_count": 3,
                }
            ],
            "quota_remaining": 290,
        },
    )
    config = stackexchange.StackExchangeConfig(sites=["security"])
    found = await stackexchange.search(_ctx(fake, config, {"key": "free-key"}), "CVE-2021-44228")
    assert found[0].title == 'Log4j "JNDI" mitigation'
    assert found[0].author == "dev & ops"
    assert found[0].extra["answered"] is True
    assert fake.requests[0].url.params["site"] == "security"
    assert fake.requests[0].url.params["key"] == "free-key"


async def test_hackernews_search() -> None:
    fake = FakeWeb()
    fake.json(
        hackernews.API,
        {
            "hits": [
                {
                    "objectID": "4200",
                    "title": "Exploit for CVE-2026-1",
                    "url": "https://blog.example/x",
                    "author": "pg",
                    "created_at": "2026-10-20T10:00:00Z",
                    "points": 10,
                },
                {
                    "objectID": "4201",
                    "comment_text": "<p>Patched in <i>2.1</i></p>",
                    "story_title": "t",
                    "author": "dang",
                    "created_at": "2026-10-20T11:00:00.000Z",
                },
            ]
        },
    )
    found = await hackernews.search(_ctx(fake, hackernews.HackerNewsConfig()), "CVE-2026-1")
    assert [f.url for f in found] == [
        "https://news.ycombinator.com/item?id=4200",
        "https://news.ycombinator.com/item?id=4201",
    ]
    assert found[1].content == "Patched in 2.1"
    assert fake.requests[0].url.params["tags"] == "(story,comment)"


# Mastodon, Bluesky, Reddit -----------------------------------------------------


STATUS = {
    "id": "1",
    "url": "https://infosec.exchange/@alice/1",
    "created_at": "2026-10-20T09:00:00.000Z",
    "content": "<p>Exploitation of <a href='#'>#CVE20261234</a> in the wild</p>",
    "account": {"acct": "alice"},
}


async def test_mastodon_tag_timeline_and_authenticated_search() -> None:
    fake = FakeWeb()
    fake.json("https://infosec.exchange/api/v1/timelines/tag/CVE20261234", [STATUS])
    fake.json("https://infosec.exchange/api/v2/search", {"statuses": [STATUS], "accounts": []})
    config = mastodon.MastodonConfig(instance="https://Infosec.Exchange/")
    assert config.instance == "infosec.exchange"
    found = await mastodon.search(_ctx(fake, config), "CVE-2026-1234")
    assert found[0].content == "Exploitation of #CVE20261234 in the wild"
    found = await mastodon.search(_ctx(fake, config, {"token": "read-token"}), "CVE-2026-1234")
    assert fake.requests[-1].headers["authorization"] == "Bearer read-token"
    assert fake.requests[-1].url.params["type"] == "statuses"
    with pytest.raises(ValueError, match="invalid instance"):
        mastodon.MastodonConfig(instance="http://169.254.169.254/latest")


async def test_bluesky_search_with_app_password() -> None:
    fake = FakeWeb()
    fake.json(f"{bluesky.PDS}/com.atproto.server.createSession", {"accessJwt": "jwt-123"})
    fake.json(
        f"{bluesky.PDS}/app.bsky.feed.searchPosts",
        {
            "posts": [
                {
                    "uri": "at://did:plc:abc/app.bsky.feed.post/3kxyz",
                    "author": {"handle": "bob.bsky.social"},
                    "record": {
                        "text": "CVE-2026-1234 PoC is out",
                        "createdAt": "2026-10-20T08:00:00Z",
                    },
                    "likeCount": 4,
                }
            ]
        },
    )
    config = bluesky.BlueskyConfig(handle="watch.bsky.social")
    found = await bluesky.search(_ctx(fake, config, {"app_password": "app-pass"}), "CVE-2026-1234")
    assert found[0].url == "https://bsky.app/profile/bob.bsky.social/post/3kxyz"
    session = fake.requests[0]
    assert b'"identifier": "watch.bsky.social"' in session.content
    assert fake.requests[1].headers["authorization"] == "Bearer jwt-123"


ATOM = b"""<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>CVE-2026-1234 exploited</title><link href="https://www.reddit.com/r/netsec/comments/a/"/>
<id>t3_a</id><updated>2026-10-20T07:00:00+00:00</updated><author><name>/u/someone</name></author>
<content type="html">&lt;p&gt;Details&lt;/p&gt;</content></entry></feed>"""


async def test_reddit_public_rss_search() -> None:
    fake = FakeWeb()
    fake.raw("https://www.reddit.com/r/netsec/search.rss", ATOM, "application/atom+xml")
    config = reddit.RedditConfig(subreddits=["r/netsec"])
    found = await reddit.search(_ctx(fake, config), "CVE-2026-1234")
    assert found[0].title == "CVE-2026-1234 exploited"
    assert found[0].content == "Details"
    assert fake.requests[0].url.params["restrict_sr"] == "on"
    with pytest.raises(ValueError, match="invalid subreddit"):
        reddit.RedditConfig(subreddits=["../../api"])


# OSV ---------------------------------------------------------------------------


OSV_RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "details": "Log4j2 JNDI features...",
    "aliases": ["CVE-2021-44228"],
    "published": "2021-12-10T00:00:00Z",
    "affected": [
        {
            "package": {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
            },
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}
            ],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
}


async def test_osv_lookup_and_package_query() -> None:
    fake = FakeWeb()
    fake.json(f"{osv.API}/vulns/CVE-2021-44228", OSV_RECORD)
    fake.json(f"{osv.API}/vulns/CVE-2099-0001", {"code": 5}, status=404)
    fake.json(f"{osv.API}/query", {"vulns": [OSV_RECORD]})
    ctx = _ctx(fake, osv.OsvConfig())
    found = await osv.lookup(ctx, "CVE-2021-44228")
    assert found is not None
    assert found.extra["affected"][0]["fixed"] == ["2.15.0"]
    assert found.extra["aliases"] == ["CVE-2021-44228"]
    assert await osv.lookup(ctx, "CVE-2099-0001") is None
    assert len(await osv.by_package(ctx, "pkg:maven/org.apache.logging.log4j/log4j-core")) == 1
    with pytest.raises(FetchError, match="invalid_identifier"):
        await osv.lookup(ctx, "../../etc/passwd")


# Web ---------------------------------------------------------------------------

PAGE = b"""<html><head><title>Advisory  VND-2026-01</title><script>steal()</script>
<style>p{}</style></head><body><nav>menu</nav><h1>Security advisory</h1>
<p>Fixed in <b>2.4.1</b>.</p><script>alert(1)</script><p>Workaround: disable &lt;feature&gt;.</p>
</body></html>"""


async def test_web_pages_are_text_only_and_follow_robots_txt() -> None:
    fake = FakeWeb()
    fake.raw(
        "https://vendor.example.com/robots.txt",
        b"User-agent: *\nDisallow: /private/\n",
        "text/plain",
    )
    fake.raw("https://vendor.example.com/advisories/1", PAGE, "text/html")
    config = web.WebConfig(allowed_domains=["vendor.example.com"])
    ctx = _ctx(fake, config)
    found = await web.read_page(ctx, "https://vendor.example.com/advisories/1")
    assert found.title == "Advisory VND-2026-01"
    assert (
        found.content == "menu\nSecurity advisory\nFixed in 2.4.1.\nWorkaround: disable <feature>."
    )
    assert "steal" not in found.content
    with pytest.raises(FetchError, match="disallowed_by_robots_txt"):
        await web.read_page(ctx, "https://vendor.example.com/private/x")
    with pytest.raises(FetchError, match="domain_not_allowed"):
        await web.read_page(ctx, "https://attacker.example.net/advisory")
    with pytest.raises(FetchError, match="domain_not_allowed"):
        await web.read_page(ctx, "http://vendor.example.com/advisories/1")


def test_raw_body_helper_exists() -> None:
    assert RawBody(b"x", "text/plain").content_type == "text/plain"
