"""Tests for the CORS policy check plugin."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.cors import CORSCheck
from redveil.config import SafetyProfile
from redveil.http.response import Response
from redveil.plugins.base import (
    CheckCategory,
    CheckDependencies,
    ValidationOutcome,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    headers: dict[str, str],
    status: int = 200,
    body: str = "",
    request_id: str = "req-1",
) -> Response:
    """Build a Response with the given headers. Body defaults to empty."""
    return Response(
        request_id=request_id,
        status_code=status,
        headers=headers,
        body=body,
        elapsed_ms=10.0,
    )


def _bind(check: CORSCheck, base_url: str = "https://example.com") -> MagicMock:
    """Bind a check to a mocked HttpClient that returns a configured response.

    The mock ``send`` always returns the *same* response — useful for tests
    that only care about a single shape of misconfiguration across all
    probed endpoints. Tests that need to vary the response per call should
    use ``_bind_with_responses`` instead.
    """
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    mock_http.send = AsyncMock(
        return_value=_mock_response(headers={}, status=200)
    )
    cfg = MagicMock()
    cfg.target.base_url = base_url
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


def _bind_with_responses(
    check: CORSCheck,
    responses: list[Response],
    base_url: str = "https://example.com",
) -> MagicMock:
    """Bind a check whose send() returns a different response per call."""
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    mock_http.send = AsyncMock(side_effect=list(responses))
    cfg = MagicMock()
    cfg.target.base_url = base_url
    deps = CheckDependencies(
        http=mock_http,
        scope=mock_http._scope,
        config=cfg,
        context=MagicMock(),
    )
    check.bind(deps)
    return mock_http


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


def test_meta_id_and_category():
    assert CORSCheck.meta.id == "cors-policy"
    assert CORSCheck.meta.category == CheckCategory.CORS
    assert CORSCheck.meta.safety_profile == SafetyProfile.PASSIVE


# ---------------------------------------------------------------------------
# Wildcard origin alone (LOW risk candidate)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wildcard_origin_alone_is_a_candidate():
    check = CORSCheck()
    # 5 paths * 2 requests (OPTIONS, GET) = 10 responses.
    responses = [
        _mock_response({"Access-Control-Allow-Origin": "*"})
        for _ in range(10)
    ]
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    issues = [c["issue"] for c in candidates]
    assert "wildcard_origin" in issues
    # No credentials -> not a "wildcard_with_credentials" candidate.
    assert "wildcard_with_credentials" not in issues


# ---------------------------------------------------------------------------
# Wildcard + credentials = CRITICAL candidate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wildcard_with_credentials_is_critical_candidate():
    check = CORSCheck()
    responses = [
        _mock_response(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        for _ in range(10)
    ]
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    issues = [c["issue"] for c in candidates]
    assert "wildcard_with_credentials" in issues
    # wildcard_with_credentials supersedes wildcard_origin for the same path.
    assert "wildcard_origin" not in issues


# ---------------------------------------------------------------------------
# Reflected origin (HIGH risk)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reflected_origin_is_high_candidate():
    check = CORSCheck()
    responses = [
        _mock_response(
            {"Access-Control-Allow-Origin": "https://evil.example"}
        )
        for _ in range(10)
    ]
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    issues = [c["issue"] for c in candidates]
    assert "reflected_origin" in issues


# ---------------------------------------------------------------------------
# Properly configured allowlist -> no candidates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_specific_allowed_origin_yields_no_candidates():
    check = CORSCheck()
    responses = [
        _mock_response(
            {"Access-Control-Allow-Origin": "https://app.example.com"}
        )
        for _ in range(10)
    ]
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    assert candidates == []


# ---------------------------------------------------------------------------
# No CORS headers at all -> no candidates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_cors_headers_yields_no_candidates():
    check = CORSCheck()
    responses = [_mock_response(headers={}) for _ in range(10)]
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    assert candidates == []


# ---------------------------------------------------------------------------
# Response with Vary: Origin but no ACAO -> no candidate
# (server is being careful about caching but doesn't permit CORS)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vary_origin_without_acao_is_not_a_candidate():
    check = CORSCheck()
    responses = [
        _mock_response(headers={"Vary": "Origin"}) for _ in range(10)
    ]
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    assert candidates == []


# ---------------------------------------------------------------------------
# Mixed endpoints: only some are misconfigured
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_only_misconfigured_endpoints_appear_as_candidates():
    check = CORSCheck()
    # 5 paths * 2 requests. Make /api/profile (path index 4) the only
    # misconfigured one (wildcard + credentials) for both preflight + GET.
    responses: list[Response] = []
    for path_idx in range(5):
        if path_idx == 4:
            responses.append(
                _mock_response(
                    {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            )  # OPTIONS
            responses.append(
                _mock_response(
                    {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            )  # GET
        else:
            responses.append(_mock_response(headers={}))  # OPTIONS
            responses.append(_mock_response(headers={}))  # GET
    _bind_with_responses(check, responses)

    candidates = await check.discover(MagicMock())
    endpoints = {c["endpoint"] for c in candidates}
    assert endpoints == {"/api/profile"}


# ---------------------------------------------------------------------------
# Validate returns CONFIRMED
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_returns_confirmed():
    check = CORSCheck()
    _bind(check)
    result = await check.validate(
        MagicMock(),
        {
            "endpoint": "/api",
            "issue": "wildcard_with_credentials",
            "acao": "*",
            "acac": "true",
            "request_origin": "https://evil.example",
        },
    )
    assert result is not None
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.confidence == "high"


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_evidence_returns_preflight_and_get_pair():
    check = CORSCheck()
    responses = [
        _mock_response(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        for _ in range(10)
    ]
    _bind_with_responses(check, responses)

    await check.discover(MagicMock())
    candidate = {
        "endpoint": "/",
        "issue": "wildcard_with_credentials",
        "acao": "*",
        "acac": "true",
        "request_origin": "https://evil.example",
    }
    evidence = await check.collect_evidence(candidate)
    # One per captured kind (preflight + get) on path "/".
    assert len(evidence) == 2
    methods = sorted(e.method for e in evidence)
    assert methods == ["GET", "OPTIONS"]
    # Both should carry the CORS headers in relevant_headers.
    for ev in evidence:
        assert "Access-Control-Allow-Origin" in ev.relevant_headers
        assert ev.relevant_headers["Access-Control-Allow-Origin"] == "*"
        assert ev.input_used == "https://evil.example"
        assert ev.parameter == "Origin"


# ---------------------------------------------------------------------------
# Assess produces a Finding with correct severity per issue type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_wildcard_with_credentials_is_critical():
    from redveil.findings.severity import Severity

    check = CORSCheck()
    _bind(check)
    finding = await check.assess(
        {
            "endpoint": "/api",
            "issue": "wildcard_with_credentials",
            "acao": "*",
            "acac": "true",
            "request_origin": "https://evil.example",
            "status_code": 200,
        }
    )
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert "CWE-942" in finding.cwe
    assert "A05:2021" in finding.owasp


@pytest.mark.asyncio
async def test_assess_reflected_origin_is_high():
    from redveil.findings.severity import Severity

    check = CORSCheck()
    _bind(check)
    finding = await check.assess(
        {
            "endpoint": "/api",
            "issue": "reflected_origin",
            "acao": "https://evil.example",
            "acac": "false",
            "request_origin": "https://evil.example",
            "status_code": 200,
        }
    )
    assert finding is not None
    assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_assess_wildcard_only_is_low():
    from redveil.findings.severity import Severity

    check = CORSCheck()
    _bind(check)
    finding = await check.assess(
        {
            "endpoint": "/api",
            "issue": "wildcard_origin",
            "acao": "*",
            "acac": "false",
            "request_origin": "https://evil.example",
            "status_code": 200,
        }
    )
    assert finding is not None
    assert finding.severity == Severity.LOW
