"""Tests for the HTTP methods check plugin."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.http_methods import HTTPMethodsCheck
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
    return Response(
        request_id=request_id,
        status_code=status,
        headers=headers,
        body=body,
        elapsed_ms=10.0,
    )


def _bind(
    check: HTTPMethodsCheck,
    responses: list[Response],
    base_url: str = "https://example.com",
) -> MagicMock:
    """Bind the check to a mocked HttpClient with a fixed response queue.

    The check probes 4 paths; per path it issues 1 OPTIONS + 5 direct
    method probes = 6 requests = 24 responses total per scan.
    """
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


def _build_responses(
    path: str,
    *,
    allow_header: str | None = None,
    method_statuses: dict[str, int] | None = None,
) -> list[Response]:
    """Build the 6 responses a single path produces in a discover() pass.

    Order: OPTIONS, PUT, DELETE, PATCH, CONNECT, TRACE.
    """
    method_statuses = method_statuses or {}
    options_headers: dict[str, str] = {}
    if allow_header:
        options_headers["Allow"] = allow_header
    out = [_mock_response(options_headers, status=200)]
    for method in ("PUT", "DELETE", "PATCH", "CONNECT", "TRACE"):
        status = method_statuses.get(method, 405)
        out.append(_mock_response(headers={}, status=status))
    return out


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


def test_meta_id_and_category():
    assert HTTPMethodsCheck.meta.id == "http-methods"
    assert HTTPMethodsCheck.meta.category == CheckCategory.METHODS
    assert HTTPMethodsCheck.meta.safety_profile == SafetyProfile.PASSIVE


# ---------------------------------------------------------------------------
# TRACE -> 200 = finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trace_200_is_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(
                _path,
                method_statuses={"TRACE": 200},
            )
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    trace_candidates = [c for c in candidates if c["method"] == "TRACE"]
    assert trace_candidates, "expected TRACE to be a candidate"
    for c in trace_candidates:
        assert c["issue"] == "trace_enabled"
        assert c["status_code"] == 200


# ---------------------------------------------------------------------------
# TRACE -> 405 = not a finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trace_405_not_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(_build_responses(_path))  # defaults to 405 for all
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    assert all(c["method"] != "TRACE" for c in candidates), (
        f"unexpected TRACE candidates: {[c for c in candidates if c['method'] == 'TRACE']}"
    )


# ---------------------------------------------------------------------------
# PUT -> 401 (auth required) = not a finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_401_not_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, method_statuses={"PUT": 401})
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    assert all(c["method"] != "PUT" for c in candidates)


# ---------------------------------------------------------------------------
# PUT -> 200 = finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_200_is_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, method_statuses={"PUT": 200})
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    put_candidates = [c for c in candidates if c["method"] == "PUT"]
    assert put_candidates
    for c in put_candidates:
        assert c["issue"] == "method_allowed_without_auth"
        assert c["status_code"] == 200


# ---------------------------------------------------------------------------
# OPTIONS with Allow: GET, POST only -> no findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_options_allow_get_post_only_no_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, allow_header="GET, POST")
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    assert candidates == []


# ---------------------------------------------------------------------------
# OPTIONS with Allow including TRACE + DELETE -> findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_options_advertises_dangerous_methods_is_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(
                _path,
                allow_header="GET, POST, TRACE, DELETE",
            )
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    methods_found = {c["method"] for c in candidates}
    # Allow header advertising TRACE/DELETE generates candidates even if
    # direct probes return 405 (which they do in this fixture).
    assert "TRACE" in methods_found
    assert "DELETE" in methods_found
    for c in candidates:
        assert c["issue"] == "method_advertised_in_allow"


# ---------------------------------------------------------------------------
# Advertised-allow + proved-allowed upgrades the issue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_advertised_upgraded_to_proved_when_probe_succeeds():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(
                _path,
                allow_header="GET, POST, TRACE",
                method_statuses={"TRACE": 200},
            )
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    trace_candidates = [c for c in candidates if c["method"] == "TRACE"]
    assert trace_candidates
    # The direct probe supersedes the Allow-header candidate.
    for c in trace_candidates:
        assert c["issue"] == "trace_enabled"


# ---------------------------------------------------------------------------
# PUT/DELETE/PATCH -> 403 = not a finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_403_not_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, method_statuses={"PUT": 403})
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    assert all(c["method"] != "PUT" for c in candidates)


# ---------------------------------------------------------------------------
# PUT -> 501 = not a finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_501_not_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, method_statuses={"PUT": 501})
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    assert all(c["method"] != "PUT" for c in candidates)


# ---------------------------------------------------------------------------
# DELETE -> 204 = finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_204_is_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, method_statuses={"DELETE": 204})
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    delete_candidates = [c for c in candidates if c["method"] == "DELETE"]
    assert delete_candidates
    for c in delete_candidates:
        assert c["status_code"] == 204


# ---------------------------------------------------------------------------
# CONNECT -> 200 = HIGH finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_200_is_finding():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(_path, method_statuses={"CONNECT": 200})
        )
    _bind(check, responses)
    candidates = await check.discover(MagicMock())
    connect_candidates = [c for c in candidates if c["method"] == "CONNECT"]
    assert connect_candidates
    for c in connect_candidates:
        assert c["issue"] == "connect_enabled"


# ---------------------------------------------------------------------------
# Validate returns CONFIRMED
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_returns_confirmed():
    check = HTTPMethodsCheck()
    _bind(check, [_mock_response(headers={}, status=200) for _ in range(24)])
    result = await check.validate(
        MagicMock(),
        {
            "endpoint": "/",
            "method": "TRACE",
            "status_code": 200,
            "issue": "trace_enabled",
        },
    )
    assert result is not None
    assert result.outcome is ValidationOutcome.CONFIRMED


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_evidence_returns_probe_pair():
    check = HTTPMethodsCheck()
    responses: list[Response] = []
    for _path in ("/", "/api", "/api/data", "/api/v1"):
        responses.extend(
            _build_responses(
                _path,
                allow_header="GET, POST, TRACE",
                method_statuses={"TRACE": 200},
            )
        )
    _bind(check, responses)
    await check.discover(MagicMock())

    candidate = {
        "endpoint": "/",
        "method": "TRACE",
        "status_code": 200,
        "issue": "trace_enabled",
    }
    evidence = await check.collect_evidence(candidate)
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.method == "TRACE"
    assert ev.endpoint == "/"
    assert ev.status_code == 200
    assert ev.kind.value == "status_diff"


# ---------------------------------------------------------------------------
# Assess produces Finding with correct severity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_trace_is_medium():
    from redveil.findings.severity import Severity

    check = HTTPMethodsCheck()
    _bind(check, [_mock_response(headers={}, status=200) for _ in range(24)])
    finding = await check.assess(
        {
            "endpoint": "/",
            "method": "TRACE",
            "status_code": 200,
            "issue": "trace_enabled",
        }
    )
    assert finding is not None
    assert finding.severity == Severity.MEDIUM
    assert "CWE-650" in finding.cwe


@pytest.mark.asyncio
async def test_assess_put_is_high():
    from redveil.findings.severity import Severity

    check = HTTPMethodsCheck()
    _bind(check, [_mock_response(headers={}, status=200) for _ in range(24)])
    finding = await check.assess(
        {
            "endpoint": "/api",
            "method": "PUT",
            "status_code": 200,
            "issue": "method_allowed_without_auth",
        }
    )
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "CWE-284" in finding.cwe
    assert "A05:2021" in finding.owasp


@pytest.mark.asyncio
async def test_assess_connect_is_high():
    from redveil.findings.severity import Severity

    check = HTTPMethodsCheck()
    _bind(check, [_mock_response(headers={}, status=200) for _ in range(24)])
    finding = await check.assess(
        {
            "endpoint": "/",
            "method": "CONNECT",
            "status_code": 200,
            "issue": "connect_enabled",
        }
    )
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "Dangerous HTTP Method Allowed: CONNECT" in finding.title
