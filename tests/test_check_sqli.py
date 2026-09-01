"""Tests for TimeBasedSQLiCheck."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.sqli import _DELAY_PAYLOADS, TimeBasedSQLiCheck
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 10.0):
    return Response(request_id="r1", status_code=status, headers={}, body=body, elapsed_ms=elapsed_ms)


def _bind(check, side_effects, active: bool = True, ack: bool = True):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    mock_http.send = AsyncMock(side_effect=side_effects)
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_active_required():
    check = TimeBasedSQLiCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = TimeBasedSQLiCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_no_timing_delta_no_finding():
    check = TimeBasedSQLiCheck()
    # All responses fast: baseline ~50ms, payload ~50ms
    fast = _resp(elapsed_ms=50.0)
    _bind(check, [fast] * 200)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_timing_delta_3x_baseline_detected():
    check = TimeBasedSQLiCheck()
    # Baseline: 50ms. Payload: 3000ms (60x).
    fast = _resp(elapsed_ms=50.0)
    slow = _resp(elapsed_ms=3000.0)
    # First 2: baseline for first param. Then payload for first param should match.
    # We provide enough responses to cover all params.
    side_effects = []
    for _ in range(8):  # 8 params tested
        side_effects += [fast, fast]  # baseline
        # Then 8 payloads per param, but we expect first one to match and break
        side_effects += [slow]  # first payload matches → break
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    c = cands[0]
    assert c["ratio"] >= 3
    assert c["delay_ms"] >= 2000


@pytest.mark.asyncio
async def test_validate_confirmed_for_strong_delay():
    check = TimeBasedSQLiCheck()
    candidate = {"baseline_ms": 50.0, "delay_ms": 3000.0, "ratio": 60.0}
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = TimeBasedSQLiCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET", "db_family": "mysql",
        "payload": "1' AND SLEEP(3)-- -",
        "baseline_ms": 50.0, "delay_ms": 3000.0, "ratio": 60.0,
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-89" in f.cwe


def test_safety_no_data_extraction_payloads():
    """Payloads must not contain SELECT/UNION/OR 1=1 (data extraction)."""
    for db, payload in _DELAY_PAYLOADS:
        upper = payload.upper()
        # Sleep-style payloads should NOT have data extraction
        assert "UNION SELECT" not in upper, f"{payload} has UNION SELECT"
        assert "OR '1'='1" not in payload, f"{payload} has OR tautology"
        # '1 AND SLEEP(3)' is OK because it's just AND with SLEEP
        # But cap sleep at 5
        m_sleep = payload.upper().replace("SLEEP(", "").replace("PG_SLEEP(", "")
        # Check no number > 5 follows SLEEP(
        import re
        for n in re.findall(r"SLEEP\s*\(\s*(\d+)\s*\)", payload, re.IGNORECASE):
            assert int(n) <= 5, f"SLEEP({n}) exceeds cap of 5"
        for n in re.findall(r"PG_SLEEP\s*\(\s*(\d+)\s*\)", payload, re.IGNORECASE):
            assert int(n) <= 5, f"PG_SLEEP({n}) exceeds cap of 5"
        for m in re.findall(r"WAITFOR DELAY\s*'([^']+)'", payload, re.IGNORECASE):
            # Format: HH:MM:SS
            parts = m.split(":")
            assert int(parts[-1]) <= 5, f"WAITFOR DELAY seconds {parts[-1]} exceeds 5"


def test_safety_no_benchmark_high_count():
    """No BENCHMARK with iteration count > 1,000,000."""
    import re
    for db, payload in _DELAY_PAYLOADS:
        for n in re.findall(r"BENCHMARK\s*\(\s*(\d+)", payload, re.IGNORECASE):
            assert int(n) <= 1_000_000, f"BENCHMARK({n}) exceeds 1M cap"
