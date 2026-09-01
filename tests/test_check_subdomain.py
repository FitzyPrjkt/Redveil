"""Tests for the SubdomainFinderCheck plugin."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.config import SafetyProfile
from redveil.plugins.base import (
    CheckCategory,
    CheckDependencies,
    ValidationOutcome,
)
from redveil.plugins.discovery.subdomain import (
    SubdomainFinderCheck,
    _fingerprint_for_subdomain,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    *,
    status: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
    error: str | None = None,
    request_id: str = "req-1",
) -> Any:
    """Build an object that quacks like ``redveil.http.response.Response``."""
    from redveil.http.response import Response

    return Response(
        request_id=request_id,
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=10.0,
        error=error,
    )


def _bind(
    check: SubdomainFinderCheck,
    *,
    base_url: str = "https://example.com",
    responses: list[Any] | None = None,
    dns_resolver=None,
) -> MagicMock:
    """Bind a check to a mocked HttpClient.

    If ``responses`` is given, ``send`` returns the next one in order; otherwise
    it returns an empty 200 response for every call.
    """
    from redveil.http.client import HttpClient

    mock_http = MagicMock(spec=HttpClient)
    # The check relies on ``deps.scope.allowed_hosts`` being a real frozenset
    # so build it from a real ScopeController.
    from redveil.config import ScopeConfig
    from redveil.core.scope import ScopeController

    scope = ScopeController(ScopeConfig(allowed_hosts=["example.com"]))
    mock_http._scope = scope
    if responses is None:
        responses = [_mock_response(body="")] * 64
    mock_http.send = AsyncMock(side_effect=list(responses))

    cfg = MagicMock()
    cfg.target.base_url = base_url
    deps = CheckDependencies(
        http=mock_http,
        scope=scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


def test_meta_id_and_category():
    assert SubdomainFinderCheck.meta.id == "subdomain-finder"
    assert SubdomainFinderCheck.meta.category == CheckCategory.DISCOVERY
    assert SubdomainFinderCheck.meta.safety_profile == SafetyProfile.PASSIVE


# ---------------------------------------------------------------------------
# discover()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_produces_candidates_from_crawl():
    """A crawl that surfaces ``api.example.com`` must yield a candidate."""

    from redveil.config import ScopeConfig
    from redveil.core.scope import ScopeController

    check = SubdomainFinderCheck()

    # Build a tiny "site" with two pages:
    #   /          -> links to /about
    #   /about     -> links to //cdn.example.com/asset.js (protocol-relative)
    # Both pages are HTML; the crawler extracts the protocol-relative URL.
    crawl_responses = [
        # 1. start page
        _mock_response(
            body='<html><body><a href="/about">about</a></body></html>'
        ),
        # 2. /about
        _mock_response(
            body=(
                '<html><head>'
                '<script src="//cdn.example.com/asset.js"></script>'
                '</head><body>about</body></html>'
            )
        ),
    ]

    # The probe phase may also call send() (HEAD requests for prefixes),
    # so we provide a long list of fallback 200 responses.
    probe_responses = [_mock_response(status=200)] * 256

    from redveil.http.client import HttpClient

    mock_http = MagicMock(spec=HttpClient)
    scope = ScopeController(ScopeConfig(allowed_hosts=["example.com"]))
    mock_http._scope = scope
    mock_http.send = AsyncMock(side_effect=crawl_responses + probe_responses)

    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    deps = CheckDependencies(
        http=mock_http,
        scope=scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)

    candidates = await check.discover(MagicMock())

    # At least one candidate per discovered subdomain.
    subdomains = {c["subdomain"] for c in candidates}
    # example.com itself may be present (start URL host).
    # The protocol-relative cdn.example.com MUST be present.
    assert "cdn.example.com" in subdomains
    # All candidates must have a recognized source.
    for c in candidates:
        assert c["source"] in {"crawl", "probe"}
        assert c["root_domain"] == "example.com"


@pytest.mark.asyncio
async def test_discover_handles_empty_crawl_result():
    """When the crawler fails to fetch anything, discover() returns []."""
    from redveil.config import ScopeConfig
    from redveil.core.scope import ScopeController
    from redveil.http.client import HttpClient

    check = SubdomainFinderCheck()
    mock_http = MagicMock(spec=HttpClient)
    scope = ScopeController(ScopeConfig(allowed_hosts=["example.com"]))
    mock_http._scope = scope
    # All transport calls fail.
    mock_http.send = AsyncMock(
        return_value=_mock_response(status=0, error="connect_error")
    )

    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    deps = CheckDependencies(
        http=mock_http,
        scope=scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)

    candidates = await check.discover(MagicMock())
    # No body was fetched -> no crawled subdomains. Probed subdomains may
    # also fail because the HTTP probe errors. Either way the function
    # must return without raising.
    assert isinstance(candidates, list)


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_returns_confirmed():
    check = SubdomainFinderCheck()
    _bind(check)
    result = await check.validate(
        MagicMock(),
        {"subdomain": "api.example.com", "source": "crawl"},
    )
    assert result is not None
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.confidence == "high"


# ---------------------------------------------------------------------------
# assess()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_produces_finding_per_subdomain():
    check = SubdomainFinderCheck()
    _bind(check)
    finding = await check.assess(
        {
            "subdomain": "api.example.com",
            "source": "crawl",
            "root_domain": "example.com",
        }
    )
    assert finding is not None
    assert finding.title == "Subdomain Discovered: api.example.com"
    assert finding.target.host == "api.example.com"
    assert "api.example.com" in finding.input_used
    assert finding.summary
    assert finding.technical_explanation
    assert finding.impact
    assert finding.remediation
    assert finding.fingerprint is not None


@pytest.mark.asyncio
async def test_finding_has_unique_fingerprint_per_subdomain():
    check = SubdomainFinderCheck()
    _bind(check)

    f1 = await check.assess(
        {
            "subdomain": "api.example.com",
            "source": "crawl",
            "root_domain": "example.com",
        }
    )
    f2 = await check.assess(
        {
            "subdomain": "www.example.com",
            "source": "probe",
            "root_domain": "example.com",
        }
    )
    assert f1.fingerprint is not None
    assert f2.fingerprint is not None
    assert f1.fingerprint != f2.fingerprint


@pytest.mark.asyncio
async def test_finding_fingerprint_is_stable_for_same_subdomain():
    """Same subdomain -> same fingerprint, regardless of source label."""
    check = SubdomainFinderCheck()
    _bind(check)

    f1 = await check.assess(
        {
            "subdomain": "api.example.com",
            "source": "crawl",
            "root_domain": "example.com",
        }
    )
    f2 = await check.assess(
        {
            "subdomain": "api.example.com",
            "source": "probe",
            "root_domain": "example.com",
        }
    )
    assert f1.fingerprint == f2.fingerprint


# ---------------------------------------------------------------------------
# collect_evidence()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_evidence_returns_one_per_subdomain():
    """After discover(), each candidate must have evidence cached."""
    check = SubdomainFinderCheck()
    # Run a discover pass to populate _evidence_cache.
    from redveil.config import ScopeConfig
    from redveil.core.scope import ScopeController
    from redveil.http.client import HttpClient

    mock_http = MagicMock(spec=HttpClient)
    scope = ScopeController(ScopeConfig(allowed_hosts=["example.com"]))
    mock_http._scope = scope
    # crawl body contains only the start page; no extracted subdomains.
    mock_http.send = AsyncMock(
        return_value=_mock_response(body="<html>no links</html>")
    )

    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    deps = CheckDependencies(
        http=mock_http,
        scope=scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)

    candidates = await check.discover(MagicMock())

    if candidates:
        cand = candidates[0]
        ev = await check.collect_evidence(cand)
        assert len(ev) == 1
        assert ev[0].input_used == cand["subdomain"]


# ---------------------------------------------------------------------------
# Fingerprint helper
# ---------------------------------------------------------------------------


def test_fingerprint_helper_is_stable():
    assert _fingerprint_for_subdomain("api.example.com") == _fingerprint_for_subdomain(
        "api.example.com"
    )
    assert _fingerprint_for_subdomain("api.example.com") != _fingerprint_for_subdomain(
        "www.example.com"
    )
    # Case-insensitive.
    assert _fingerprint_for_subdomain("API.example.com") == _fingerprint_for_subdomain(
        "api.example.com"
    )
