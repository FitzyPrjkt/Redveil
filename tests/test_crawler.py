"""Tests for the BFS web crawler."""

from __future__ import annotations

import pytest
import respx
from httpx import Response as HttpxResponse

from redveil.config import LimitsConfig, ScopeConfig
from redveil.core.scope import ScopeController
from redveil.discovery.crawler import Crawler, CrawlerConfig, CrawlerResult
from redveil.http.client import HttpClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope(hosts: list[str]) -> ScopeController:
    return ScopeController(ScopeConfig(allowed_hosts=hosts))


def _limits(**overrides) -> LimitsConfig:
    defaults = {
        "requests_per_second": 1000.0,
        "max_concurrent_requests": 10,
        "max_requests": 5000,
        "timeout_seconds": 5.0,
        "max_response_size_bytes": 1024 * 1024,
        "connection_pool_size": 10,
    }
    defaults.update(overrides)
    return LimitsConfig(**defaults)  # type: ignore[arg-type]


async def _make_client(scope: ScopeController) -> HttpClient:
    """Construct an HttpClient already inside its async context."""
    client = HttpClient(scope, _limits())
    # Manually drive __aenter__ so the test can `await client.send(...)`.
    await client.__aenter__()
    return client


# ---------------------------------------------------------------------------
# Basic crawl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_visits_start_url_and_follows_links():
    """A simple two-page site is crawled end-to-end."""
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text='<html><body><a href="/about">About</a></body></html>',
                )
            )
            mock.get("https://example.com/about").mock(
                return_value=HttpxResponse(200, text="<html>about page</html>")
            )
            # robots.txt: 404 -> no rules.
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404, text="not found")
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    max_depth=3,
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert result.pages_crawled == 2
    assert "https://example.com/" in result.urls_visited
    assert "https://example.com/about" in result.urls_visited
    # robots.txt is added to urls_visited when fetched.
    assert "https://example.com/robots.txt" in result.urls_visited


@pytest.mark.asyncio
async def test_crawler_records_all_visited_urls():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(200, text="no links")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(allowed_hosts={"example.com"}, honor_robots=True),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert "https://example.com/" in result.urls_visited
    # urls_visited is a set (deduped).
    assert isinstance(result.urls_visited, set)


# ---------------------------------------------------------------------------
# max_pages
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_respects_max_pages_limit():
    """When max_pages=1, only the start URL is fetched."""
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text='<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>',
                )
            )
            # These should NOT be called:
            mock.get("https://example.com/a").mock(
                return_value=HttpxResponse(200, text="a")
            )
            mock.get("https://example.com/b").mock(
                return_value=HttpxResponse(200, text="b")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    max_pages=1,
                    max_depth=10,
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert result.pages_crawled == 1
    # urls_skipped reflects the 3 enqueued candidates that never got dispatched.
    assert result.urls_skipped >= 3


# ---------------------------------------------------------------------------
# max_depth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_respects_max_depth():
    """Pages beyond max_depth are not dispatched."""
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock(assert_all_called=False) as mock:
            # depth 0 -> depth 1 -> depth 2
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200, text='<a href="/level1">x</a>'
                )
            )
            mock.get("https://example.com/level1").mock(
                return_value=HttpxResponse(
                    200, text='<a href="/level2">x</a>'
                )
            )
            # /level2 should NOT be called when max_depth=1.
            mock.get("https://example.com/level2").mock(
                return_value=HttpxResponse(200, text="x")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    max_depth=1,
                    max_pages=10,
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    # Only / and /level1 should be parsed.
    assert result.pages_crawled == 2
    # /level2 was enqueued but depth exceeded -> urls_skipped increments.
    assert result.urls_skipped >= 1


# ---------------------------------------------------------------------------
# allowed_hosts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_stays_within_allowed_hosts():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text=(
                        '<a href="https://example.com/about">in</a>'
                        '<a href="https://other.com/page">out</a>'
                    ),
                )
            )
            # in-scope
            mock.get("https://example.com/about").mock(
                return_value=HttpxResponse(200, text="about")
            )
            # out-of-scope — should NOT be called by the crawler because the
            # BFS frontier pre-filters by allowed_hosts.
            mock.get("https://other.com/page").mock(
                return_value=HttpxResponse(200, text="out")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    max_depth=5,
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert result.pages_crawled == 2
    assert "https://other.com/page" not in result.urls_visited


# ---------------------------------------------------------------------------
# Link extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_follows_anchor_hrefs():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text=(
                        '<a href="/x">x</a>'
                        '<a href="https://example.com/y">y</a>'
                        '<a href="/z">z</a>'
                    ),
                )
            )
            for path in ("x", "y", "z"):
                mock.get(f"https://example.com/{path}").mock(
                    return_value=HttpxResponse(200, text=path)
                )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    max_pages=10,
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert result.pages_crawled == 4
    for p in ("x", "y", "z"):
        assert f"https://example.com/{p}" in result.urls_visited


@pytest.mark.asyncio
async def test_crawler_skips_non_http_schemes():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text=(
                        '<a href="javascript:alert(1)">x</a>'
                        '<a href="mailto:v@example.com">y</a>'
                        '<a href="#section">z</a>'
                    ),
                )
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(allowed_hosts={"example.com"}, honor_robots=True),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    # Only the start page was visited; javascript:/mailto:/# were dropped.
    assert result.pages_crawled == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_handles_404_gracefully():
    """A 404 doesn't crash the crawler; it's recorded as an error path
    and the crawl continues."""
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text='<a href="/missing">x</a><a href="/ok">y</a>',
                )
            )
            mock.get("https://example.com/missing").mock(
                return_value=HttpxResponse(404, text="not found")
            )
            mock.get("https://example.com/ok").mock(
                return_value=HttpxResponse(200, text="ok")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"}, honor_robots=True
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    # /missing returns 404 but its body is empty so no further links found.
    # /ok returns 200 -> 2 pages crawled.
    assert result.pages_crawled == 3
    # No transport-level errors -> errors list stays empty.
    assert result.errors == []


@pytest.mark.asyncio
async def test_crawler_handles_500_gracefully():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(200, text="<a href='/x'>x</a>")
            )
            mock.get("https://example.com/x").mock(
                return_value=HttpxResponse(500, text="oops")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"}, honor_robots=True
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert result.pages_crawled == 2
    # 500 still counts as a "page crawled" — the response was returned.
    # Body may be empty so no further links discovered.


@pytest.mark.asyncio
async def test_crawler_handles_timeout_gracefully():
    import httpx

    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock() as mock:
            mock.get("https://example.com/").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            mock.get("https://example.com/robots.txt").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"}, honor_robots=True
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    # No pages parsed because transport failed on every dispatch.
    assert result.pages_crawled == 0
    # The transport-level errors are recorded.
    assert len(result.errors) >= 1


# ---------------------------------------------------------------------------
# robots.txt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_respects_robots_disallow():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text='<a href="/allowed">a</a><a href="/private">p</a>',
                )
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(
                    200,
                    text=(
                        "User-agent: *\n"
                        "Disallow: /private\n"
                    ),
                )
            )
            mock.get("https://example.com/allowed").mock(
                return_value=HttpxResponse(200, text="allowed")
            )
            # /private should NOT be called.
            mock.get("https://example.com/private").mock(
                return_value=HttpxResponse(200, text="private")
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    max_pages=10,
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    # / was visited, /robots.txt was visited, /allowed was visited.
    assert "https://example.com/" in result.urls_visited
    assert "https://example.com/allowed" in result.urls_visited
    # /private should be skipped because of robots.txt Disallow.
    assert "https://example.com/private" not in result.urls_visited
    assert result.urls_skipped >= 1


@pytest.mark.asyncio
async def test_crawler_ignores_robots_when_honor_robots_false():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200, text='<a href="/private">p</a>'
                )
            )
            mock.get("https://example.com/private").mock(
                return_value=HttpxResponse(200, text="private")
            )
            # robots.txt should NOT be requested when honor_robots=False.
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(200, text="disallow all")
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    honor_robots=False,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert "https://example.com/private" in result.urls_visited
    # robots.txt URL not added to urls_visited.
    assert "https://example.com/robots.txt" not in result.urls_visited


# ---------------------------------------------------------------------------
# excluded_paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_skips_excluded_paths():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://example.com/").mock(
                return_value=HttpxResponse(
                    200,
                    text=(
                        '<a href="/about">a</a>'
                        '<a href="/admin/users">u</a>'
                    ),
                )
            )
            mock.get("https://example.com/about").mock(
                return_value=HttpxResponse(200, text="about")
            )
            mock.get("https://example.com/admin/users").mock(
                return_value=HttpxResponse(200, text="users")
            )
            mock.get("https://example.com/robots.txt").mock(
                return_value=HttpxResponse(404)
            )
            crawler = Crawler(
                client,
                CrawlerConfig(
                    allowed_hosts={"example.com"},
                    excluded_paths={"/admin"},
                    honor_robots=True,
                ),
            )
            result = await crawler.crawl("https://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert "https://example.com/about" in result.urls_visited
    assert "https://example.com/admin/users" not in result.urls_visited


# ---------------------------------------------------------------------------
# Start URL with no scheme
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawler_rejects_non_http_start_url():
    scope = _scope(["example.com"])
    client = await _make_client(scope)
    try:
        crawler = Crawler(client, CrawlerConfig(allowed_hosts={"example.com"}))
        result = await crawler.crawl("ftp://example.com/")
    finally:
        await client.__aexit__(None, None, None)

    assert result.pages_crawled == 0
    assert result.urls_visited == set()


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_crawler_requires_http_client():
    with pytest.raises(ValueError):
        Crawler(None, CrawlerConfig())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# CrawlerResult fields
# ---------------------------------------------------------------------------


def test_crawler_result_defaults():
    r = CrawlerResult()
    assert r.pages_crawled == 0
    assert r.urls_visited == set()
    assert r.urls_skipped == 0
    assert r.errors == []
