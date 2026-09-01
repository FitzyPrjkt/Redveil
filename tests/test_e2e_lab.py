"""End-to-end integration test.

This test starts the local Flask lab on a random port, runs redveil against
it with all 17 checks, and verifies:
- Lab starts and responds
- Orchestrator completes without errors
- Findings are produced
- Reports are written to disk (summary.md, findings.json, findings/*.md, report.html)
- Sanitization redacts sensitive material (cookies, known secret patterns)
- HTML report is generated
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

# Repo root used to locate the lab and import paths.
REPO_ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = REPO_ROOT / "tests" / "lab"


def _free_port() -> int:
    """Find a free port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def lab_url() -> str:
    """Start the local lab in a subprocess (module-scoped: shared by all tests).

    The lab binds to 127.0.0.1 only and shuts down cleanly on teardown.
    If the lab fails to start within ~15 seconds, the fixture raises.
    """
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "LAB_HOST": "127.0.0.1",
            "LAB_PORT": str(port),
            "LAB_FAST": "1",  # disable Flask debug mode for E2E speed
            "PATH": "/usr/bin:/bin",
        }
    )
    proc = subprocess.Popen(
        [sys.executable, str(LAB_DIR / "app.py")],
        cwd=str(LAB_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Poll the lab until it responds.
        for _ in range(30):
            try:
                r = httpx.get(f"http://127.0.0.1:{port}/", timeout=1.0)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            stdout = proc.stdout.read(2000).decode("utf-8", errors="replace") if proc.stdout else ""
            stderr = proc.stderr.read(2000).decode("utf-8", errors="replace") if proc.stderr else ""
            proc.kill()
            raise RuntimeError(
                f"lab failed to start on port {port}.\nstdout: {stdout}\nstderr: {stderr}"
            )
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _make_config(lab: str, **overrides: Any):
    """Build a RedVeilConfig pointed at the local lab.

    Defaults to PASSIVE profile so we don't need active_testing acknowledgement.
    """
    from redveil.config import (
        AuthConfig,
        AuthorizationConfig,
        LimitsConfig,
        RedVeilConfig,
        ReportingConfig,
        SafetyProfile,
        ScopeConfig,
        TargetConfig,
    )

    defaults: dict = {
        "target": TargetConfig(base_url=lab, name="E2E Lab"),
        "scope": ScopeConfig(allowed_hosts=["127.0.0.1"]),
        "limits": LimitsConfig(
            requests_per_second=50, max_requests=500, timeout_seconds=5
        ),
        "authorization": AuthorizationConfig(
            active_testing=False, acknowledged_safety_terms=False
        ),
        "auth": AuthConfig(),
        "profile": SafetyProfile.PASSIVE,
    }
    defaults.update(overrides)
    return RedVeilConfig(**defaults)


async def _run_scan(cfg):
    """Build the registry, http client, and orchestrator and run to completion.

    Returns the ScanContext and the populated Orchestrator.
    """
    from redveil.core.event_bus import EventBus
    from redveil.core.lifecycle import ScanContext
    from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
    from redveil.core.scope import ScopeController
    from redveil.http.client import HttpClient
    from redveil.http.session import build_auth_provider
    from redveil.plugins.loader import build_default_registry

    bus = EventBus()
    reg = build_default_registry()
    ctx = ScanContext(target_name=cfg.target.name or "E2E Lab", run_id="e2e")
    scope = ScopeController(cfg.scope)
    auth = build_auth_provider(cfg.auth)
    async with HttpClient(scope=scope, limits=cfg.limits, auth=auth) as http:
        deps = OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http)
        orch = Orchestrator(deps, ctx)
        await orch.run()
    return ctx, orch, bus, reg


# ---------------------------------------------------------------------------
# Module-scoped shared scan: run the orchestrator ONCE per test session,
# then run additional assertions off the same findings list.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scan_results(lab_url: str) -> dict[str, Any]:
    """Run the orchestrator against the lab once and capture the result.

    Returns a dict with the ScanContext, the Orchestrator's evidence store,
    and the configured RedVeilConfig — enough for every per-claim test below
    to share a single expensive scan.
    """
    import asyncio

    async def _go() -> dict[str, Any]:
        cfg = _make_config(lab_url)
        ctx, orch, bus, reg = await _run_scan(cfg)
        return {
            "ctx": ctx,
            "orch": orch,
            "bus": bus,
            "reg": reg,
            "cfg": cfg,
            "lab_url": lab_url,
        }

    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# 1. Lab is reachable & main route responds.
# ---------------------------------------------------------------------------


def test_lab_starts_and_home_route_responds(lab_url: str) -> None:
    """Verify the lab is up and the home page renders the test endpoints."""
    r = httpx.get(lab_url + "/", timeout=2.0)
    assert r.status_code == 200
    assert b"redveil" in r.content.lower()
    assert b"/api/profile" in r.content
    assert b"/debug" in r.content


def test_lab_session_cookie_authenticates_as_principal(lab_url: str) -> None:
    """Verify the lab supports `session=N` cookies for BOLA principal testing."""
    # Default (no cookie) → Alice (id 1)
    r = httpx.get(lab_url + "/api/profile/me", timeout=2.0)
    assert r.status_code == 200
    data = r.json()
    assert data["principal_id"] == "1"

    # session=2 → Bob
    r = httpx.get(
        lab_url + "/api/profile/me",
        cookies={"session": "2"},
        timeout=2.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["principal_id"] == "2"
    assert data["authenticated_as"]["name"] == "Bob"

    # session=3 → Admin
    r = httpx.get(
        lab_url + "/api/profile/me",
        cookies={"session": "3"},
        timeout=2.0,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["principal_id"] == "3"
    assert data["authenticated_as"]["role"] == "admin"


# ---------------------------------------------------------------------------
# 2. End-to-end passive run against the lab.
# ---------------------------------------------------------------------------


def test_e2e_passive_run_produces_findings_and_reports(
    scan_results: dict, tmp_path: Path
) -> None:
    """Run redveil against the lab, verify findings + reports are produced."""
    from redveil.reporting.markdown import write_report

    ctx = scan_results["ctx"]
    findings = ctx.findings

    # 1) Lab responded and scan produced findings.
    assert len(findings) > 0, "expected at least one finding from passive checks"
    print(f"\n[E2E] {len(findings)} findings produced")

    # 2) Each finding has the required fields.
    for f in findings:
        assert f.id, "finding missing id"
        assert f.title, "finding missing title"
        assert f.severity, "finding missing severity"
        assert f.target.endpoint, "finding missing target.endpoint"
        assert f.summary, "finding missing summary"
        assert f.technical_explanation, "finding missing technical_explanation"

    # 3) Reports are written to disk.
    target_dir = tmp_path / "E2E Lab"
    written = write_report(findings, "E2E Lab", target_dir)
    assert (target_dir / "summary.md").exists()
    assert (target_dir / "findings.json").exists()
    assert (target_dir / "report.html").exists()
    findings_dir = target_dir / "findings"
    assert findings_dir.exists()
    md_files = list(findings_dir.glob("*.md"))
    assert len(md_files) == len(findings)
    assert (target_dir / "report.html").stat().st_size > 0

    # 4) findings.json is well-formed.
    data = json.loads((target_dir / "findings.json").read_text())
    assert data["findings_count"] == len(findings)
    assert data["tool"] == "redveil"

    # 5) Sanitization: well-known secret patterns and cookies are redacted.
    report_text = (target_dir / "summary.md").read_text()
    for f in md_files:
        report_text += f.read_text()
    html_text = (target_dir / "report.html").read_text()

    # Cookie values must never appear in report text.
    assert "session=1" not in report_text
    assert "session=1" not in html_text

    # The lab's `config.ini` contains a fake password. The lab's /debug
    # endpoint echoes it back. The Finding produced by the disclosure check
    # only references the path /debug (not the body content), so the value
    # should not appear in the rendered reports.
    assert "FAKE_PASSWORD_FOR_TESTING_ONLY_NOT_REAL" not in report_text


# ---------------------------------------------------------------------------
# 3. Orchestrator emits the expected lifecycle events and ends in COMPLETED.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_orchestrator_state_transitions(scan_results: dict) -> None:
    """Verify the orchestrator walks through all expected states.

    Runs a SECOND scan with a recording event bus to capture lifecycle events.
    The second scan shares the lab process via the module-scoped lab_url fixture.
    """
    from redveil.config import LimitsConfig
    from redveil.core.event_bus import EventBus, EventType
    from redveil.core.lifecycle import ScanContext
    from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
    from redveil.core.scope import ScopeController
    from redveil.http.client import HttpClient
    from redveil.http.session import build_auth_provider

    cfg = _make_config(
        scan_results["lab_url"],
        limits=LimitsConfig(requests_per_second=50, max_requests=500, timeout_seconds=5),
    )

    # Collect every event the orchestrator publishes.
    bus = EventBus()
    events: list = []

    async def _collect(event) -> None:
        events.append(event)

    bus.subscribe_all(_collect)

    ctx = ScanContext(target_name="E2E Lab", run_id="e2e-state")
    scope = ScopeController(cfg.scope)
    auth = build_auth_provider(cfg.auth)
    async with HttpClient(scope=scope, limits=cfg.limits, auth=auth) as http:
        deps = OrchestratorDeps(bus=bus, registry=scan_results["reg"], config=cfg, http=http)
        orch = Orchestrator(deps, ctx)
        await orch.run()

    event_types = [e.type for e in events]
    # Required lifecycle events.
    assert EventType.SCAN_STARTED in event_types
    assert EventType.SCAN_FINISHED in event_types
    assert EventType.REPORT_GENERATED in event_types
    assert EventType.DISCOVERY_STARTED in event_types
    assert EventType.CHECK_STARTED in event_types
    # Terminal state.
    assert ctx.state.value == "completed"


# ---------------------------------------------------------------------------
# 4. Scope controller rejects out-of-scope hosts.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_scope_blocks_out_of_scope(scan_results: dict) -> None:
    """Verify ScopeController refuses requests to hosts not in allowed_hosts."""
    from redveil.core.scope import ScopeController, ScopeViolation
    from redveil.http.client import HttpClient
    from redveil.http.request import Request

    cfg = _make_config(scan_results["lab_url"])
    scope_ctrl = ScopeController(cfg.scope)
    async with HttpClient(scope=scope_ctrl, limits=cfg.limits) as http:
        with pytest.raises(ScopeViolation):
            req = Request(method="GET", url="http://192.168.1.1/", purpose="out-of-scope")
            await http.send(req)


# ---------------------------------------------------------------------------
# 5. Findings carry evidence references.
# ---------------------------------------------------------------------------


def test_e2e_findings_have_evidence(scan_results: dict) -> None:
    """Verify at least some findings reference captured evidence."""
    findings = scan_results["ctx"].findings
    findings_with_evidence = [f for f in findings if f.evidence_ids]
    assert len(findings_with_evidence) > 0, "expected at least one finding with evidence"
    # And the orchestrator's evidence store should be non-empty.
    assert len(scan_results["orch"].evidence_store) > 0


# ---------------------------------------------------------------------------
# 6. Sanitization: cookies always redact, known patterns redact.
# ---------------------------------------------------------------------------


def test_e2e_sanitizer_redacts_cookies_and_jwt() -> None:
    """Verify the sanitizer module does what the report relies on."""
    from redveil.evidence.sanitizer import (
        _redact_headers,
        _redact_text,
        sanitize_request,
    )
    from redveil.http.request import Request

    # Cookies are always [REDACTED] regardless of value.
    req = Request(
        method="GET",
        url="https://example.com/",
        headers={"Authorization": "Bearer abc", "Cookie": "session=secret"},
        cookies={"session": "real-session-value-123"},
        body="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    )
    out = sanitize_request(req)
    assert out.headers["Authorization"] == "[REDACTED]"
    assert out.headers["Cookie"] == "[REDACTED]"
    assert out.cookies == {"session": "[REDACTED]"}
    assert "eyJ" not in (out.body or "")

    # AWS access key, GitHub token and email all get redacted by _redact_text.
    body_text = (
        "AWS key: AKIAIOSFODNN7EXAMPLE; "
        "GitHub: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij; "
        "Email: contact alice@example.com please."
    )
    redacted = _redact_text(body_text)
    assert "[AWS_ACCESS_KEY_REDACTED]" in redacted
    assert "[GITHUB_TOKEN_REDACTED]" in redacted
    assert "[EMAIL_REDACTED]" in redacted
    assert "alice@" not in redacted

    # Sensitive headers map to [REDACTED] regardless of value.
    out_headers = _redact_headers(
        {"Authorization": "Bearer xyz", "X-API-Key": "k123", "Content-Type": "text/html"}
    )
    assert out_headers["Authorization"] == "[REDACTED]"
    assert out_headers["X-API-Key"] == "[REDACTED]"
    assert out_headers["Content-Type"] == "text/html"


# ---------------------------------------------------------------------------
# 7. lab_scope.yaml exists and is a valid config.
# ---------------------------------------------------------------------------


def test_lab_scope_yaml_is_valid() -> None:
    """Verify the lab_scope.yaml is a valid redveil config with BOLA principals."""
    cfg_path = REPO_ROOT / "tests" / "lab_scope.yaml"
    assert cfg_path.exists(), f"{cfg_path} not found"
    data = yaml.safe_load(cfg_path.read_text())
    assert "target" in data
    assert "scope" in data
    assert "auth" in data
    assert "principals" in data["auth"]
    assert len(data["auth"]["principals"]) >= 2, "need at least 2 principals for BOLA"
    # Each principal should set the session cookie.
    for p in data["auth"]["principals"]:
        assert p["cookies"], f"principal {p['name']} missing cookies"
        cookie = p["cookies"][0]
        assert cookie["name"] == "session", "expected session cookie for BOLA"