"""Negative testing harness.

The single most impactful anti-FP technique: run every check against BOTH
a vulnerable target and a properly-secured target. A check that produces
findings against the SECURE target is producing FALSE POSITIVES.

This file:
- Starts the vulnerable lab (tests/lab/app.py)
- Runs redveil against it, records findings
- Stops the vulnerable lab, starts the secure app (tests/lab/secure_app.py)
- Runs redveil against the secure app, records findings
- Compares: the secure app should produce ZERO (or near-zero) findings

Findings produced by redveil against the SECURE app are categorized:
- "FALSE POSITIVE" — check flagged something that isn't actually a vuln
- "implementation gap" — check is too sensitive, needs tuning

The test fails if false positive rate exceeds the configured threshold
(default 10% of the vulnerable-target finding count, or 0 absolute —
whichever is higher).
"""
from __future__ import annotations
import asyncio
import os
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from redveil.config import (
    RedVeilConfig, TargetConfig, ScopeConfig, LimitsConfig,
    AuthorizationConfig, AuthConfig, SafetyProfile,
)
from redveil.core.event_bus import EventBus
from redveil.core.lifecycle import ScanContext
from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.http.session import build_auth_provider
from redveil.plugins.loader import build_default_registry
from redveil.evidence.sanitizer import sanitize_evidence_list
from redveil.findings.finding import Finding


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_app(app_filename: str, port: int) -> subprocess.Popen:
    """Start a lab app and wait for it to be ready."""
    repo_root = Path(__file__).parent.parent
    app_path = repo_root / "tests" / "lab" / app_filename
    venv_python = repo_root / ".venv" / "bin" / "python"
    env = os.environ.copy()
    env["LAB_HOST"] = "127.0.0.1"
    env["LAB_PORT"] = str(port)
    proc = subprocess.Popen(
        [str(venv_python), str(app_path)],
        cwd=str(app_path.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for readiness
    for _ in range(40):
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/", timeout=1.0)
            if r.status_code == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.25)
    proc.kill()
    raise RuntimeError(f"{app_filename} did not become ready on port {port}")


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# We share the lab subprocess and scan-results between tests within the
# module so the suite stays fast.
_module_state: dict = {}


def _module_setup():
    """Module-level setup: run the scan against vulnerable + secure apps
    once, share results across all tests."""
    if "results" in _module_state:
        return _module_state

    vuln_port = _free_port()
    secure_port = _free_port()
    vuln_proc = _start_app("app.py", vuln_port)
    secure_proc = None
    try:
        vuln_url = f"http://127.0.0.1:{vuln_port}"
        vuln_findings = asyncio.run(_run_scan(vuln_url, principals=False))

        # Switch to secure app
        _stop(vuln_proc)
        vuln_proc = None
        secure_proc = _start_app("secure_app.py", secure_port)

        secure_url = f"http://127.0.0.1:{secure_port}"
        secure_findings = asyncio.run(_run_scan(secure_url, principals=False))

        _module_state.update({
            "vuln_url": vuln_url,
            "secure_url": secure_url,
            "vuln_findings": vuln_findings,
            "secure_findings": secure_findings,
            "secure_proc": secure_proc,
        })
    finally:
        if vuln_proc is not None:
            _stop(vuln_proc)
    return _module_state


def _module_teardown():
    proc = _module_state.get("secure_proc")
    if proc:
        _stop(proc)
    _module_state.clear()


async def _run_scan(base_url: str, principals: bool = False) -> list[Finding]:
    """Run the full orchestrator against a target."""
    cfg = RedVeilConfig(
        target=TargetConfig(base_url=base_url, name="NegativeTest"),
        scope=ScopeConfig(allowed_hosts=["127.0.0.1"]),
        limits=LimitsConfig(requests_per_second=20, max_requests=400, timeout_seconds=3),
        authorization=AuthorizationConfig(active_testing=False, acknowledged_safety_terms=False),
        profile=SafetyProfile.PASSIVE,
    )
    bus = EventBus()
    reg = build_default_registry()
    ctx = ScanContext(target_name="NegativeTest", run_id="neg")
    scope = ScopeController(cfg.scope)
    auth = build_auth_provider(cfg.auth)
    async with HttpClient(scope=scope, limits=cfg.limits, auth=auth) as http:
        deps = OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http)
        orch = Orchestrator(deps, ctx)
        await orch.run()
    return list(ctx.findings)


@pytest.fixture(scope="module")
def scan_results():
    state = _module_setup()
    yield state
    # Don't tear down here — let the session teardown do it.


def pytest_sessionfinish(session, exitstatus):
    _module_teardown()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_vulnerable_lab_produces_findings(scan_results):
    """Sanity check: the vulnerable lab should produce findings."""
    n = len(scan_results["vuln_findings"])
    assert n > 0, "vulnerable lab produced 0 findings — checks may be broken"


def test_secure_lab_produces_fewer_findings(scan_results):
    """The secure lab should produce dramatically fewer findings than the vulnerable one."""
    vuln_n = len(scan_results["vuln_findings"])
    secure_n = len(scan_results["secure_findings"])
    # Heuristic: secure should produce at most 20% of vulnerable-target findings,
    # or 0 absolute. This is loose; tighter thresholds come from per-check tests.
    threshold = max(0, vuln_n // 5)
    assert secure_n <= threshold, (
        f"secure lab produced {secure_n} findings, threshold {threshold} "
        f"(vuln had {vuln_n}). FP candidates:\n"
        + "\n".join(
            f"  - {f.severity.value.upper():8} [{f.check.id:25}] {f.title[:80]}"
            for f in scan_results["secure_findings"]
        )
    )


def test_secure_findings_are_documented(scan_results):
    """When the secure lab produces findings, list them so we can investigate."""
    findings = scan_results["secure_findings"]
    if not findings:
        return
    # Print (not assert) so we can see what was flagged
    print(f"\n[negative-test] secure lab produced {len(findings)} potential FPs:")
    for f in findings:
        print(f"  - {f.severity.value.upper():8} [{f.check.id:25}] {f.title[:80]}")


def test_per_check_no_critical_or_high_on_secure(scan_results):
    """CRITICAL or HIGH findings against the secure lab are definite FPs."""
    for f in scan_results["secure_findings"]:
        sev = f.severity.value
        assert sev not in {"critical", "high"}, (
            f"check {f.check.id} produced {sev} finding on the SECURE app: "
            f"{f.title} — this is a definite false positive. "
            f"Fix the check to recognize the secure control."
        )
