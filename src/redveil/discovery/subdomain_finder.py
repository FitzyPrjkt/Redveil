"""Subdomain extraction and probing.

Two related operations live here:

1. :meth:`SubdomainFinder.extract_from_urls` — given a list of URLs (e.g. from
   a crawled site), return every hostname that is a subdomain of the configured
   root domain.
2. :meth:`SubdomainFinder.probe_common` — for a curated list of common
   subdomain prefixes (``www``, ``api``, ``mail``, etc.), try to prove the
   hostname exists via DNS first, then HTTP HEAD as a fallback.

The module does not depend on a network library — DNS uses ``socket.getaddrinfo``
wrapped in :func:`asyncio.to_thread` so the event loop never blocks. HTTP
probing is delegated to the caller's :class:`redveil.http.client.HttpClient` so
scope enforcement is preserved end-to-end.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import urlparse

from redveil.http.request import Request

if TYPE_CHECKING:
    from redveil.http.client import HttpClient
    from redveil.http.response import Response


log = logging.getLogger(__name__)


# A custom resolver is any awaitable callable ``(name: str) -> list[str]``.
# The default resolver is provided below.
DnsResolver = Callable[[str], "list[str] | asyncio.Future[list[str]]"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class SubdomainFinder:
    """Extract subdomains from URLs and optionally probe them.

    Args:
        root_domain: The apex domain used as the inclusion filter. Hosts equal
            to ``root_domain`` or with it as a suffix (e.g. ``api.example.com``
            for ``example.com``) are kept; everything else is dropped.
        http_client: Optional HttpClient used for HTTP HEAD probing. When None
            HTTP probing is skipped.
        dns_resolver: Optional async function ``(hostname) -> list[str]`` that
            returns resolved IPs. When None DNS probing is skipped.

    The class is stateless beyond its constructor inputs; it is safe to call
    ``extract_from_urls`` and ``probe_common`` multiple times on the same
    instance.
    """

    root_domain: str
    http_client: HttpClient | None = None
    dns_resolver: DnsResolver | None = None

    # Common subdomain prefixes used by ``probe_common``. Curated from public
    # subdomain-enumeration wordlists (subfinder, assetfinder) and trimmed for
    # common production deployments.
    # Declared as a class attribute below; the dataclass does not own it.
    COMMON_PREFIXES: ClassVar[list[str]]

    def __post_init__(self) -> None:
        # Normalize once.
        self.root_domain = self.root_domain.lower().lstrip(".")

    # -- membership -------------------------------------------------------

    def is_subdomain(self, hostname: str) -> bool:
        """True if ``hostname`` equals ``root_domain`` or is a subdomain of it."""
        if not hostname or not self.root_domain:
            return False
        h = hostname.lower().rstrip(".")
        r = self.root_domain.lower().rstrip(".")
        if h == r:
            return True
        # Use a dot-boundary suffix match so ``notexample.com`` doesn't match
        # ``example.com``.
        return h.endswith("." + r)

    # -- extraction -------------------------------------------------------

    def extract_from_urls(self, urls: Iterable[str]) -> set[str]:
        """Given an iterable of URLs, return every unique subdomain of
        ``root_domain`` found in any of them.

        Handles:
            * ``https://api.example.com/v1``
            * ``http://example.com`` (root itself)
            * ``//cdn.example.com/path`` (protocol-relative)
            * ``api.example.com`` (bare hostname)
            * URLs with non-default ports (``api.example.com:8443/...``)
            * Non-matching domains (dropped)
        """
        out: set[str] = set()
        for raw in urls:
            if not raw:
                continue
            host = self._extract_host(raw)
            if host and self.is_subdomain(host):
                out.add(host)
        return out

    @staticmethod
    def _extract_host(url: str) -> str | None:
        """Return the hostname for ``url``, handling bare/relative forms."""
        s = url.strip()
        if not s:
            return None

        parsed = urlparse(s)

        # Case 1: bare hostname, e.g. ``api.example.com``.
        if not parsed.scheme and not parsed.netloc and "/" not in s and ":" not in s:
            host = s.lower().rstrip(".")
            return host or None

        # Case 2: protocol-relative, e.g. ``//cdn.example.com/foo``.
        if s.startswith("//"):
            # urlparse keeps netloc for protocol-relative; safe to use directly.
            if parsed.hostname:
                return parsed.hostname.lower()
            return None

        # Case 3: full URL — prefer urlparse().hostname (handles ports).
        if parsed.hostname:
            return parsed.hostname.lower()

        return None

    # -- probing ----------------------------------------------------------

    async def probe_common(self) -> set[str]:
        """For each ``COMMON_PREFIXES`` entry, build ``{prefix}.{root_domain}``
        and try to prove it exists.

        Resolution strategy per hostname:
            1. DNS A/AAAA via the configured resolver (skipped if no resolver).
            2. HTTP HEAD via the configured HttpClient. A 2xx/3xx response means
               the host is reachable; treated as discovered.

        Returns:
            Set of every subdomain proven to exist via either DNS or HTTP.
        """
        found: set[str] = set()
        # Build tasks for all candidates so DNS lookups run concurrently.
        tasks: list[asyncio.Task[str | None]] = []
        for prefix in self.COMMON_PREFIXES:
            host = f"{prefix}.{self.root_domain}"
            tasks.append(asyncio.create_task(self._probe_one(host)))

        for t in tasks:
            host = await t
            if host:
                found.add(host)
        return found

    async def _probe_one(self, host: str) -> str | None:
        """Probe a single hostname. Returns the hostname on success, else None."""
        # 1. DNS resolution.
        if self.dns_resolver is not None:
            try:
                ips = await self._call_resolver(host)
            except Exception as e:  # pragma: no cover - resolver contract
                log.debug("dns resolver raised for %s: %s", host, e)
                ips = []
            if ips:
                return host

        # 2. HTTP probe.
        if self.http_client is not None:
            try:
                if await self._http_head_ok(host):
                    return host
            except Exception as e:
                log.debug("http probe failed for %s: %s", host, e)

        return None

    async def _call_resolver(self, host: str) -> list[str]:
        """Invoke ``self.dns_resolver`` whether it returns a coroutine or a
        plain list (resolvers can be sync or async)."""
        result = self.dns_resolver(host)  # type: ignore[arg-type]
        if asyncio.iscoroutine(result):
            return await result  # type: ignore[return-value]
        # Possibly a Future if the user returned one explicitly.
        if asyncio.isfuture(result):
            return await result  # type: ignore[return-value]
        # Otherwise assume it's already a list.
        return list(result)  # type: ignore[arg-type]

    async def _http_head_ok(self, host: str) -> bool:
        """HEAD ``http://{host}/`` via the HttpClient; treat 2xx/3xx as alive."""
        if self.http_client is None:
            return False
        url = f"http://{host}/"
        req = Request(
            method="HEAD",
            url=url,
            purpose="subdomain-probe",
        )
        response: Response = await self.http_client.send(req)
        # Any response (no error) with a redirect/2xx/3xx means the host
        # accepts connections; 4xx/5xx means it does (or scope rejected it).
        if response.error:
            return False
        return 200 <= response.status_code < 400


# Assign the curated prefix list as a class attribute on the dataclass. Done
# outside the @dataclass body so Python's mutable-default-checker doesn't trip.
SubdomainFinder.COMMON_PREFIXES = [
    "www", "mail", "email", "webmail", "blog", "dev", "staging",
    "api", "cdn", "cloud", "auth", "login", "admin", "portal",
    "support", "help", "docs", "status", "monitor", "git", "ci",
    "jenkins", "gitlab", "jira", "confluence", "wiki", "kb",
    "shop", "store", "pay", "billing", "invoice", "app", "mobile",
    "m", "static", "assets", "media", "images", "img", "files",
    "download", "upload", "backup", "db", "mysql", "postgres",
    "redis", "elastic", "kibana", "grafana", "prometheus", "sentry",
    "test", "qa", "uat", "sandbox", "demo", "trial", "beta",
    "vpn", "remote", "ssh", "ftp", "smtp", "imap", "pop", "mx",
    "ns1", "ns2", "ns3", "old", "new", "legacy", "v1", "v2",
]


# ---------------------------------------------------------------------------
# Default DNS resolver (sync -> async via asyncio.to_thread)
# ---------------------------------------------------------------------------


async def default_dns_resolver(hostname: str) -> list[str]:
    """Resolve ``hostname`` using ``socket.getaddrinfo`` without blocking the
    loop. Returns a list of unique address strings; empty list on failure.
    """
    def _resolve() -> list[str]:
        try:
            infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        except Exception:
            return []
        # Strip port and keep unique host strings; values are IPs, not hostnames.
        out: list[str] = []
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            addr = sockaddr[0]
            if addr and addr not in out:
                out.append(addr)
        return out

    return await asyncio.to_thread(_resolve)
