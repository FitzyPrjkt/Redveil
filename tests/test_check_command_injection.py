"""Tests for CommandInjectionCheck — CRITICAL SAFETY TESTS."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.command_injection import (
    _DELAY_PAYLOADS,
    _FORBIDDEN_SUBSTRINGS,
    CommandInjectionCheck,
)
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
    check = CommandInjectionCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = CommandInjectionCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_timing_delta_detected():
    check = CommandInjectionCheck()
    fast = _resp(elapsed_ms=50.0)
    slow = _resp(elapsed_ms=3000.0)
    # First param: 2 baseline + 1 payload (first one matches)
    side_effects = [fast, fast, slow] + [fast] * 200
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = CommandInjectionCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "host", "method": "GET",
        "payload": "; sleep 3", "separator": ";",
        "baseline_ms": 50.0, "delay_ms": 3000.0, "ratio": 60.0,
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "critical"
    assert "CWE-78" in f.cwe


def test_safety_no_destructive_payloads():
    """Every payload must be a benign sleep-only command. No destructive commands."""
    for payload in _DELAY_PAYLOADS:
        for bad in _FORBIDDEN_SUBSTRINGS:
            assert bad not in payload, f"payload {payload!r} contains forbidden substring {bad!r}"
        # Cap sleep at 5 seconds
        import re
        for n in re.findall(r"sleep\s+(\d+)", payload):
            assert int(n) <= 5, f"sleep {n} exceeds cap"


def test_safety_only_sleep_command():
    """Every payload should ONLY contain 'sleep N' (no other commands)."""
    for payload in _DELAY_PAYLOADS:
        import re
        # Strip leading/trailing separators and whitespace
        stripped = re.sub(r"^[\s;|&`$()]+", "", payload)
        stripped = re.sub(r"[\s;|&`$()]+$", "", stripped)
        # Should be just "sleep N"
        assert re.match(r"^sleep\s+\d+$", stripped), f"non-sleep payload: {payload!r} (stripped: {stripped!r})"


def test_safety_no_file_references():
    """No payload should reference real files."""
    for payload in _DELAY_PAYLOADS:
        for bad in ["/etc/", "passwd", "shadow", "system32", "boot.ini"]:
            assert bad not in payload, f"payload {payload!r} references {bad!r}"


def test_safety_no_reverse_shell():
    """No reverse shell patterns."""
    for payload in _DELAY_PAYLOADS:
        for bad in ["/dev/tcp", "bash -i", "python -c", "perl -e", "ruby -e", "nc -e", "ncat -e"]:
            assert bad not in payload, f"payload {payload!r} has reverse shell: {bad!r}"


def test_safety_no_disk_wipe():
    """No disk-wiping or destructive write commands."""
    for payload in _DELAY_PAYLOADS:
        for bad in ["dd if=", "mkfs", "fdisk", "rm -rf", "> /dev/", "chmod 777", "chown"]:
            assert bad not in payload, f"payload {payload!r} has destructive: {bad!r}"
