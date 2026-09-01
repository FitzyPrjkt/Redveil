"""Async BFS web crawler used by the discovery layer.

The crawler is intentionally minimal — its only responsibility is to walk a
URL graph (bounded by ``max_pages`` and ``max_depth``) and emit every URL it
visits. Scope enforcement, rate limiting, and per-request audit come from the
shared :class:`redveil.http.client.HttpClient` instance the caller passes in.

Design notes
------------

* The crawler uses ``HttpClient.send`` for *every* outbound request so scope
  enforcement is automatic and a plugin-supplied client cannot be substituted.
* A ``robots.txt`` (when present) is honored via a tiny built-in parser — only
  ``User-agent: *`` rules are considered, which is sufficient for our scope.
* ``urls_visited`` is a ``set[str]`` so dedup is O(1). ``urls_skipped`` counts
  pages skipped because the cap or excluded-path predicate fired.
* Errors raised by ``HttpClient.send`` (transport errors, ``ScopeViolation``,
  etc.) are caught and recorded in ``errors``; the crawler never raises.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from redveil.http.request import Request
from redveil.http.response import Response

if TYPE_CHECKING:
    from redveil.http.client import HttpClient


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config + Result
# ---------------------------------------------------------------------------


@dataclass
class CrawlerConfig:
    """Tunables for the BFS crawler.

    Attributes:
        max_pages: Hard cap on the number of distinct pages visited (excludes
            redirects and robots.txt). 0 means unlimited.
        max_depth: BFS depth limit; depth 0 is the start URL, depth 1 is a page
            linked from it, etc. Negative depths are treated as 0.
        allowed_hosts: Set of hostnames the crawler may visit. The HttpClient's
            scope controller already enforces this; we pass it here so the
            crawler can pre-filter the BFS frontier and avoid dispatching
            requests it knows will be rejected.
        excluded_paths: Set of path prefixes that are skipped without an HTTP
            call (e.g. ``/logout``, ``/admin/delete``). Matched by ``startswith``.
        delay_seconds: Sleep between successive dispatches. Honors the global
            rate limit of the HttpClient but adds an extra, predictable throttle
            suitable for crawling.
        user_agent: Sent as the ``User-Agent`` header. The HttpClient also sets
            its own default; this overrides only when non-empty.
        honor_robots: When True, a fetched ``robots.txt`` adds its ``Disallow``
            entries to the per-host excluded set.
        max_response_bytes: Response bodies larger than this are still parsed
            for links but truncated before returning to the caller. 0 disables.
    """

    max_pages: int = 100
    max_depth: int = 3
    allowed_hosts: set[str] = field(default_factory=set)
    excluded_paths: set[str] = field(default_factory=set)
    delay_seconds: float = 0.0
    user_agent: str = "redveil-crawler/0.1"
    honor_robots: bool = True
    max_response_bytes: int = 1_000_000


@dataclass
class CrawlerResult:
    """Outcome of a crawl.

    Attributes:
        pages_crawled: Number of distinct pages whose body was parsed.
        urls_visited: Set of every URL the crawler issued a request for
            (start page + every discovered link + robots.txt when present).
        urls_skipped: Number of candidate URLs that were not dispatched because
            of a cap (max_pages / max_depth / excluded_paths / already visited).
        errors: List of ``(url, error_string)`` tuples for requests that failed
            at the transport layer.
    """

    pages_crawled: int = 0
    urls_visited: set[str] = field(default_factory=set)
    urls_skipped: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HREF_RE = re.compile(
    r"""(?xi)
    \s+
    (?P<attr>href | src | action)      # the attribute name
    \s* = \s*
    (?P<q>["']?)
    (?P<url>[^\s"'<>]+)                # the URL value (any non-attr chars)
    (?P=q)
    """
)


def _normalize_url(base: str, href: str) -> str | None:
    """Resolve a possibly-relative ``href`` against ``base``. Returns the
    absolute URL, or None if it cannot be parsed (e.g. ``javascript:``, ``#``).
    """
    if not href:
        return None
    href = href.strip()
    if not href or href.startswith("#"):
        return None
    # Strip fragments for dedup; we don't care about in-page anchors.
    parsed_href = urlparse(href)
    if parsed_href.scheme in {"javascript", "mailto", "tel", "data", "blob"}:
        return None
    joined = urljoin(base, href)
    parsed = urlparse(joined)
    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    # Strip fragment.
    parsed = parsed._replace(fragment="")
    return parsed.geturl()


def _parse_robots(body: str) -> set[str]:
    """Return Disallow paths from a robots.txt body. Only rules under
    ``User-agent: *`` are honored. Comments (``#``) and blank lines are
    ignored. Long bodies are bounded at 64 KiB.
    """
    out: set[str] = set()
    in_star = False
    for raw_line in body.splitlines()[:2000]:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            in_star = value == "*"
        elif key == "disallow" and in_star and value:
            # Treat the disallow path as a prefix.
            out.add(value)
    return out


def _extract_links(body: str, base_url: str) -> set[str]:
    """Parse ``href``/``src``/``action`` attributes out of an HTML body.
    Returns absolute URLs that have ``http`` or ``https`` scheme.
    """
    out: set[str] = set()
    for m in _HREF_RE.finditer(body):
        href = m.group("url")
        abs_url = _normalize_url(base_url, href)
        if abs_url:
            out.add(abs_url)
    return out


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------


class Crawler:
    """Breadth-first crawler over a single host (or a small allowlist)."""

    def __init__(self, http_client: HttpClient, config: CrawlerConfig | None = None):
        if http_client is None:
            raise ValueError("Crawler requires an HttpClient instance")
        self._http = http_client
        self.config = config or CrawlerConfig()
        # Per-host robots Disallow rules, populated lazily.
        self._robots: dict[str, set[str]] = {}

    # -- public API --------------------------------------------------------

    async def crawl(self, start_url: str) -> CrawlerResult:
        """BFS from ``start_url``; returns a :class:`CrawlerResult`."""
        result = CrawlerResult()
        if not start_url:
            return result

        # Normalize start URL (strip fragment).
        parsed_start = urlparse(start_url)
        if parsed_start.scheme not in {"http", "https"}:
            return result
        start_url = parsed_start._replace(fragment="").geturl()

        # If allowed_hosts is empty, derive it from the start URL.
        allowed_hosts = set(self.config.allowed_hosts)
        if not allowed_hosts:
            allowed_hosts = {parsed_start.hostname or ""}

        # Fetch robots.txt first (when enabled).
        if self.config.honor_robots:
            await self._fetch_robots(parsed_start, result)

        # BFS frontier: (url, depth)
        frontier: deque[tuple[str, int]] = deque([(start_url, 0)])

        while frontier:
            if self.config.max_pages and result.pages_crawled >= self.config.max_pages:
                # Cap reached; drop remaining candidates.
                result.urls_skipped += len(frontier)
                break

            url, depth = frontier.popleft()

            # Skip predicates first — anything we don't dispatch must NOT
            # pollute the visited set.
            if depth > self.config.max_depth:
                result.urls_skipped += 1
                continue

            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host not in allowed_hosts:
                result.urls_skipped += 1
                continue

            # robots.txt disallow check
            if self._is_disallowed(host, parsed.path):
                result.urls_skipped += 1
                continue

            # User-supplied excluded paths
            if any(parsed.path.startswith(p) for p in self.config.excluded_paths):
                result.urls_skipped += 1
                continue

            # We're committed to dispatching; mark visited now.
            result.urls_visited.add(url)

            response = await self._fetch(url)
            if response is None:
                # _fetch already recorded the error.
                continue

            # If the HttpClient captured a transport error, don't count this
            # as a successful page crawl — body is unreliable.
            if response.error:
                result.errors.append((url, response.error))
                continue

            # Body may be truncated; that's fine for link extraction.
            body = response.body or ""
            if (
                self.config.max_response_bytes
                and len(body) > self.config.max_response_bytes
            ):
                body = body[: self.config.max_response_bytes]

            result.pages_crawled += 1

            # Parse links. Apply skip predicates first so we never add a
            # URL we'd later refuse to dispatch.
            for link in _extract_links(body, url):
                if link in result.urls_visited:
                    continue
                if not self._should_enqueue(
                    link, depth + 1, allowed_hosts
                ):
                    result.urls_skipped += 1
                    continue
                result.urls_visited.add(link)
                frontier.append((link, depth + 1))

            if self.config.delay_seconds > 0:
                await asyncio.sleep(self.config.delay_seconds)

        return result

    # -- internals ---------------------------------------------------------

    async def _fetch(self, url: str) -> Response | None:
        """Issue a GET via the HttpClient. Records errors on the result.
        Returns None on transport/scope failure."""
        try:
            req = Request(
                method="GET",
                url=url,
                headers={"User-Agent": self.config.user_agent}
                if self.config.user_agent
                else {},
                purpose="crawl",
            )
            return await self._http.send(req)
        except Exception as e:  # pragma: no cover - exercised in tests
            log.debug("crawler transport error for %s: %s", url, e)
            return None

    async def _fetch_robots(self, parsed_start, result: CrawlerResult) -> None:
        """Fetch ``/robots.txt`` once for the start host, storing Disallow paths."""
        host = (parsed_start.hostname or "").lower()
        if not host or host in self._robots:
            return
        # Build robots URL against the start URL's scheme.
        robots_url = f"{parsed_start.scheme}://{parsed_start.netloc}/robots.txt"
        try:
            req = Request(
                method="GET",
                url=robots_url,
                headers={"User-Agent": self.config.user_agent}
                if self.config.user_agent
                else {},
                purpose="crawl-robots",
            )
            response = await self._http.send(req)
        except Exception as e:
            log.debug("crawler: could not fetch %s: %s", robots_url, e)
            self._robots[host] = set()
            return

        result.urls_visited.add(robots_url)

        # 4xx/5xx -> assume "no rules".
        if not host or host in self._robots:
            return
        # Build robots URL against the start URL's scheme.
        robots_url = f"{parsed_start.scheme}://{parsed_start.netloc}/robots.txt"
        try:
            req = Request(
                method="GET",
                url=robots_url,
                headers={"User-Agent": self.config.user_agent}
                if self.config.user_agent
                else {},
                purpose="crawl-robots",
            )
            response = await self._http.send(req)
        except Exception as e:
            log.debug("crawler: could not fetch %s: %s", robots_url, e)
            self._robots[host] = set()
            return

        result.urls_visited.add(robots_url)

        # 4xx/5xx -> assume "no rules".
        if response.status_code >= 400 or response.error:
            self._robots[host] = set()
            return

        self._robots[host] = _parse_robots(response.body or "")

    def _is_disallowed(self, host: str, path: str) -> bool:
        """True if ``path`` is disallowed by robots.txt for ``host``."""
        rules = self._robots.get(host)
        if not rules:
            return False
        for prefix in rules:
            if path.startswith(prefix):
                return True
        return False

    def _should_enqueue(
        self, url: str, depth: int, allowed_hosts: set[str]
    ) -> bool:
        """Apply all dispatch predicates to a candidate URL. Returns True iff
        we'd actually fetch it."""
        if depth > self.config.max_depth:
            return False
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host not in allowed_hosts:
            return False
        if self._is_disallowed(host, parsed.path):
            return False
        if any(parsed.path.startswith(p) for p in self.config.excluded_paths):
            return False
        return True
