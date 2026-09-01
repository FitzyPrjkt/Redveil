"""Tests for SubdomainFinder."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.discovery.subdomain_finder import (
    SubdomainFinder,
    default_dns_resolver,
)

# ---------------------------------------------------------------------------
# is_subdomain
# ---------------------------------------------------------------------------


def test_is_subdomain_returns_true_for_root_itself():
    finder = SubdomainFinder(root_domain="example.com")
    assert finder.is_subdomain("example.com") is True
    assert finder.is_subdomain("EXAMPLE.COM") is True  # case-insensitive
    assert finder.is_subdomain("example.com.") is True  # trailing dot


def test_is_subdomain_returns_true_for_subdomains():
    finder = SubdomainFinder(root_domain="example.com")
    assert finder.is_subdomain("api.example.com") is True
    assert finder.is_subdomain("dev.api.example.com") is True  # multi-level


def test_is_subdomain_returns_false_for_unrelated():
    finder = SubdomainFinder(root_domain="example.com")
    assert finder.is_subdomain("google.com") is False
    assert finder.is_subdomain("notexample.com") is False  # suffix without dot
    assert finder.is_subdomain("") is False
    assert finder.is_subdomain("example.org") is False


# ---------------------------------------------------------------------------
# extract_from_urls
# ---------------------------------------------------------------------------


def test_extract_finds_subdomain_from_full_url():
    finder = SubdomainFinder(root_domain="example.com")
    urls = ["https://api.example.com/v1/users"]
    found = finder.extract_from_urls(urls)
    assert found == {"api.example.com"}


def test_extract_finds_multi_level_subdomain():
    finder = SubdomainFinder(root_domain="example.com")
    urls = ["https://dev.api.example.com/internal"]
    found = finder.extract_from_urls(urls)
    assert found == {"dev.api.example.com"}


def test_extract_ignores_non_matching_domains():
    finder = SubdomainFinder(root_domain="example.com")
    urls = [
        "https://google.com/search",
        "https://example.com/about",
        "https://subdomain-of-evil.com/x",
    ]
    found = finder.extract_from_urls(urls)
    assert found == {"example.com"}


def test_extract_handles_protocol_relative_url():
    finder = SubdomainFinder(root_domain="example.com")
    urls = ["//cdn.example.com/assets/style.css"]
    found = finder.extract_from_urls(urls)
    assert found == {"cdn.example.com"}


def test_extract_handles_bare_hostname():
    finder = SubdomainFinder(root_domain="example.com")
    urls = ["api.example.com"]
    found = finder.extract_from_urls(urls)
    assert found == {"api.example.com"}


def test_extract_handles_url_with_port():
    finder = SubdomainFinder(root_domain="example.com")
    urls = ["https://api.example.com:8443/v1"]
    found = finder.extract_from_urls(urls)
    # Ports are stripped from hostname.
    assert found == {"api.example.com"}


def test_extract_handles_http_and_https():
    finder = SubdomainFinder(root_domain="example.com")
    urls = [
        "http://api.example.com",
        "https://api.example.com",
        "https://www.example.com",
    ]
    found = finder.extract_from_urls(urls)
    assert found == {"api.example.com", "www.example.com"}


def test_extract_handles_mixed_input():
    finder = SubdomainFinder(root_domain="example.com")
    urls = [
        "https://example.com/",
        "https://api.example.com/v1",
        "https://google.com/",
        "//cdn.example.com/x",
        "blog.example.com",
        "",
        "javascript:void(0)",
        "#fragment",
    ]
    found = finder.extract_from_urls(urls)
    assert found == {"example.com", "api.example.com", "cdn.example.com", "blog.example.com"}


def test_extract_normalizes_case():
    finder = SubdomainFinder(root_domain="EXAMPLE.com")
    urls = ["https://API.Example.COM/v1"]
    found = finder.extract_from_urls(urls)
    # The root is normalized at construction; subdomains should be lowercase.
    assert found == {"api.example.com"}


# ---------------------------------------------------------------------------
# probe_common (DNS-first)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_common_returns_dns_resolved_hosts():
    # A resolver that always resolves to a list of IPs.
    async def always_resolves(name: str) -> list[str]:
        return ["127.0.0.1"]

    finder = SubdomainFinder(
        root_domain="example.com",
        dns_resolver=always_resolves,
    )
    found = await finder.probe_common()
    # Every prefix + "example.com" should be returned.
    expected = {f"{p}.example.com" for p in SubdomainFinder.COMMON_PREFIXES}
    assert found == expected


@pytest.mark.asyncio
async def test_probe_common_falls_back_to_http_when_dns_empty():
    # Resolver returns no IPs; HTTP HEAD mock returns 200 -> probed.
    async def empty_resolver(name: str) -> list[str]:
        return []

    mock_http = MagicMock()
    mock_http.send = AsyncMock(
        return_value=MagicMock(error=None, status_code=200)
    )
    finder = SubdomainFinder(
        root_domain="example.com",
        dns_resolver=empty_resolver,
        http_client=mock_http,
    )
    # Probe a single prefix to keep the test snappy.
    finder.COMMON_PREFIXES = ["www"]
    found = await finder.probe_common()
    assert found == {"www.example.com"}
    # HTTP HEAD should have been called once.
    assert mock_http.send.await_count == 1


@pytest.mark.asyncio
async def test_probe_common_skips_http_when_dns_resolves():
    # DNS resolves -> HTTP not called.
    async def resolves(name: str) -> list[str]:
        return ["127.0.0.1"]

    mock_http = MagicMock()
    mock_http.send = AsyncMock()
    finder = SubdomainFinder(
        root_domain="example.com",
        dns_resolver=resolves,
        http_client=mock_http,
    )
    finder.COMMON_PREFIXES = ["api"]
    found = await finder.probe_common()
    assert found == {"api.example.com"}
    # HTTP HEAD was NOT called because DNS resolved first.
    assert mock_http.send.await_count == 0


@pytest.mark.asyncio
async def test_probe_common_no_dns_only_http():
    # dns_resolver=None -> straight to HTTP.
    mock_http = MagicMock()
    mock_http.send = AsyncMock(
        return_value=MagicMock(error=None, status_code=301)
    )
    finder = SubdomainFinder(
        root_domain="example.com",
        dns_resolver=None,
        http_client=mock_http,
    )
    finder.COMMON_PREFIXES = ["api", "cdn"]
    found = await finder.probe_common()
    assert found == {"api.example.com", "cdn.example.com"}


@pytest.mark.asyncio
async def test_probe_common_no_clients_returns_empty():
    finder = SubdomainFinder(root_domain="example.com")
    finder.COMMON_PREFIXES = ["www"]
    found = await finder.probe_common()
    assert found == set()


@pytest.mark.asyncio
async def test_probe_common_handles_http_error():
    async def empty_resolver(name: str) -> list[str]:
        return []

    mock_http = MagicMock()
    mock_http.send = AsyncMock(
        return_value=MagicMock(error="connect_error", status_code=0)
    )
    finder = SubdomainFinder(
        root_domain="example.com",
        dns_resolver=empty_resolver,
        http_client=mock_http,
    )
    finder.COMMON_PREFIXES = ["api"]
    found = await finder.probe_common()
    assert found == set()


# ---------------------------------------------------------------------------
# default_dns_resolver (sanity)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_dns_resolver_returns_empty_on_unknown_host():
    # A name that getaddrinfo cannot resolve -> empty list.
    out = await default_dns_resolver("this-host-definitely-does-not-exist.invalid")
    assert out == []
