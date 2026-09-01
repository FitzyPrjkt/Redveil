"""Tests for the orchestrator and its coordination with the event bus.

A fake Check class implements the discover -> candidate protocol so the
tests can drive the orchestrator without depending on real vulnerability
checks. The fake lets us simulate plugin errors and candidate emissions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from redveil.config import (
    AuthorizationConfig,
    LimitsConfig,
    RedVeilConfig,
    SafetyProfile,
    ScopeConfig,
    TargetConfig,
)
from redveil.core.event_bus import EventBus, EventType
from redveil.core.lifecycle import ScanContext, ScanState
from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.plugins.base import Check, CheckCategory, CheckMeta
from redveil.plugins.registry import Registry


def _make_deps():
    """Build a minimal (config, http) pair for orchestrator tests."""
    cfg = RedVeilConfig(
        target=TargetConfig(base_url="https://test.invalid"),
        scope=ScopeConfig(allowed_hosts=["test.invalid"]),
        limits=LimitsConfig(requests_per_second=10, max_requests=100),
        authorization=AuthorizationConfig(active_testing=False, acknowledged_safety_terms=False),
        profile=SafetyProfile.PASSIVE,
    )
    http = HttpClient(scope=ScopeController(cfg.scope), limits=cfg.limits)
    return cfg, http


# --- Test doubles -----------------------------------------------------------


@dataclass
class FakeFinding:
    """Stand-in for the real Finding model (Phase 2)."""

    id: str
    title: str = "fake finding"


class _FakeCheckBase(Check):
    """Base for the configurable fake checks used by these tests."""

    meta: CheckMeta

    def __init__(self, check_id: str, candidates: list[Any] | None = None) -> None:
        super().__init__()
        self.meta = CheckMeta(
            id=check_id,
            name=f"Fake {check_id}",
            category=CheckCategory.HEADERS,
            safety_profile=SafetyProfile.PASSIVE,
        )
        self._candidates = list(candidates or [])


class HappyCheck(_FakeCheckBase):
    """A check that emits the configured candidates."""

    async def discover(self, ctx: ScanContext) -> list[Any]:
        return list(self._candidates)


class BrokenCheck(_FakeCheckBase):
    """A check that raises during discovery to exercise the error path."""

    async def discover(self, ctx: ScanContext) -> list[Any]:
        raise RuntimeError("simulated plugin failure")


# --- Tests ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_runs_to_completion_through_all_states() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        result = await orch.run()

    assert result.state is ScanState.COMPLETED


@pytest.mark.asyncio
async def test_orchestrator_emits_events_in_expected_order() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        await orch.run()

    types = [e.type for e in bus.history]
    assert types[0] is EventType.SCAN_STARTED
    assert types[-1] is EventType.SCAN_FINISHED

    # Discovery is sandwiched by start/end events.
    assert EventType.DISCOVERY_STARTED in types
    assert EventType.DISCOVERY_ENDED in types
    assert types.index(EventType.DISCOVERY_STARTED) < types.index(
        EventType.DISCOVERY_ENDED
    )

    # Each registered check announces start and end.
    assert EventType.CHECK_STARTED in types
    assert EventType.CHECK_ENDED in types

    # Validation phase event and report event both fire.
    assert EventType.REPORT_GENERATED in types


@pytest.mark.asyncio
async def test_orchestrator_emits_scoped_events_with_target_metadata() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))

    ctx = ScanContext(target_name="example.com", run_id="run-xyz")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)
        await orch.run()

    started = next(e for e in bus.history if e.type is EventType.SCAN_STARTED)
    assert started.source == "orchestrator"
    assert started.data["target"] == "example.com"
    assert started.data["run_id"] == "run-xyz"

    finished = next(e for e in bus.history if e.type is EventType.SCAN_FINISHED)
    assert finished.data["run_id"] == "run-xyz"


@pytest.mark.asyncio
async def test_orchestrator_emits_finding_detected_per_candidate() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(
        HappyCheck(
            "cors-policy",
            candidates=["cand-a", "cand-b", "cand-c"],
        )
    )

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)
        await orch.run()

    detected = [e for e in bus.history if e.type is EventType.FINDING_DETECTED]
    assert len(detected) == 3
    assert [e.data["candidate"] for e in detected] == ["cand-a", "cand-b", "cand-c"]
    assert all(e.source == "cors-policy" for e in detected)


@pytest.mark.asyncio
async def test_orchestrator_emits_check_started_and_ended_per_plugin() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))
    reg.register(HappyCheck("x-content-type-options"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)
        await orch.run()

    started_sources = [
        e.source
        for e in bus.history
        if e.type is EventType.CHECK_STARTED
    ]
    ended_sources = [
        e.source
        for e in bus.history
        if e.type is EventType.CHECK_ENDED
    ]
    assert "cors-policy" in started_sources
    assert "x-content-type-options" in started_sources
    assert "cors-policy" in ended_sources
    assert "x-content-type-options" in ended_sources


@pytest.mark.asyncio
async def test_orchestrator_transitions_to_failed_on_plugin_error() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(BrokenCheck("broken"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        with pytest.raises(RuntimeError, match="simulated plugin failure"):
            await orch.run()

    assert ctx.state is ScanState.FAILED


@pytest.mark.asyncio
async def test_orchestrator_publishes_error_event_on_failure() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(BrokenCheck("broken"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        with pytest.raises(RuntimeError):
            await orch.run()

    errors = [e for e in bus.history if e.type is EventType.ERROR]
    assert len(errors) == 1
    assert errors[0].source == "orchestrator"
    assert "simulated plugin failure" in errors[0].data["error"]
    assert errors[0].data["type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_orchestrator_still_publishes_scan_finished_after_failure() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(BrokenCheck("broken"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        with pytest.raises(RuntimeError):
            await orch.run()

    finished = [e for e in bus.history if e.type is EventType.SCAN_FINISHED]
    assert len(finished) == 1
    assert finished[0].source == "orchestrator"


@pytest.mark.asyncio
async def test_findings_added_to_ctx_appear_in_scan_finished_data() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    # Pre-populate as if findings had been added during discovery/checking.
    ctx.findings.append(FakeFinding(id="WPOC-0001"))
    ctx.findings.append(FakeFinding(id="WPOC-0002"))
    ctx.findings.append(FakeFinding(id="WPOC-0003"))

    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)
        await orch.run()

    finished = next(e for e in bus.history if e.type is EventType.SCAN_FINISHED)
    assert finished.data["findings"] == 3


@pytest.mark.asyncio
async def test_orchestrator_emits_validation_started_per_finding() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    ctx.findings.append(FakeFinding(id="WPOC-0001"))
    ctx.findings.append(FakeFinding(id="WPOC-0002"))

    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)
        await orch.run()

    validations = [
        e for e in bus.history if e.type is EventType.VALIDATION_STARTED
    ]
    assert len(validations) == 2
    assert [e.data["finding_id"] for e in validations] == ["WPOC-0001", "WPOC-0002"]


@pytest.mark.asyncio
async def test_orchestrator_emits_report_generated_with_findings_count() -> None:
    bus = EventBus()
    reg = Registry()
    reg.register(HappyCheck("cors-policy"))

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    ctx.findings.append(FakeFinding(id="WPOC-0001"))

    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)
        await orch.run()

    report = next(e for e in bus.history if e.type is EventType.REPORT_GENERATED)
    assert report.source == "orchestrator"
    assert report.data["findings_count"] == 1


@pytest.mark.asyncio
async def test_orchestrator_with_empty_registry_runs_to_completion() -> None:
    bus = EventBus()
    reg = Registry()

    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        result = await orch.run()

    assert result.state is ScanState.COMPLETED
    # Even with no plugins, the lifecycle events fire.
    types = [e.type for e in bus.history]
    assert EventType.SCAN_STARTED in types
    assert EventType.SCAN_FINISHED in types


@pytest.mark.asyncio
async def test_orchestrator_does_not_silently_drop_plugin_exceptions() -> None:
    """Ensure unexpected exception types are not swallowed."""
    bus = EventBus()
    reg = Registry()

    class WeirdErrorCheck(_FakeCheckBase):
        async def discover(self, ctx: ScanContext) -> list[Any]:
            raise ValueError("weird")

    reg.register(WeirdErrorCheck("weird"))
    ctx = ScanContext(target_name="example.com", run_id="run-1")
    cfg, http = _make_deps()
    async with http:
        orch = Orchestrator(OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http), ctx)

        with pytest.raises(ValueError, match="weird"):
            await orch.run()

    assert ctx.state is ScanState.FAILED
