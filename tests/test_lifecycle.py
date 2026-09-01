"""Tests for the scan lifecycle state machine and ScanContext."""

from __future__ import annotations

import pytest

from redveil.core.lifecycle import (
    InvalidStateTransition,
    ScanContext,
    ScanState,
    assert_transition,
)


def test_scan_context_starts_in_initialized_state() -> None:
    ctx = ScanContext(target_name="example.com", run_id="run-1")
    assert ctx.state is ScanState.INITIALIZED
    assert ctx.target_name == "example.com"
    assert ctx.run_id == "run-1"
    assert ctx.findings == []
    assert ctx.metadata == {}


@pytest.mark.parametrize(
    "current,target",
    [
        (ScanState.INITIALIZED, ScanState.DISCOVERING),
        (ScanState.DISCOVERING, ScanState.DISCOVERY_COMPLETE),
        (ScanState.DISCOVERY_COMPLETE, ScanState.CHECKING),
        (ScanState.CHECKING, ScanState.VALIDATING),
        (ScanState.CHECKING, ScanState.REPORTING),
        (ScanState.VALIDATING, ScanState.REPORTING),
        (ScanState.REPORTING, ScanState.COMPLETED),
        (ScanState.INITIALIZED, ScanState.FAILED),
        (ScanState.INITIALIZED, ScanState.ABORTED),
        (ScanState.DISCOVERING, ScanState.FAILED),
        (ScanState.DISCOVERING, ScanState.ABORTED),
        (ScanState.DISCOVERY_COMPLETE, ScanState.FAILED),
        (ScanState.DISCOVERY_COMPLETE, ScanState.ABORTED),
        (ScanState.CHECKING, ScanState.FAILED),
        (ScanState.CHECKING, ScanState.ABORTED),
        (ScanState.VALIDATING, ScanState.FAILED),
        (ScanState.VALIDATING, ScanState.ABORTED),
        (ScanState.REPORTING, ScanState.FAILED),
        (ScanState.REPORTING, ScanState.ABORTED),
    ],
)
def test_valid_transitions_are_allowed(current: ScanState, target: ScanState) -> None:
    # Should not raise.
    assert_transition(current, target)


@pytest.mark.parametrize(
    "current,target",
    [
        # Skipping phases
        (ScanState.INITIALIZED, ScanState.CHECKING),
        (ScanState.INITIALIZED, ScanState.COMPLETED),
        (ScanState.INITIALIZED, ScanState.REPORTING),
        (ScanState.DISCOVERING, ScanState.CHECKING),
        (ScanState.DISCOVERY_COMPLETE, ScanState.VALIDATING),
        (ScanState.DISCOVERY_COMPLETE, ScanState.COMPLETED),
        # Backwards transitions
        (ScanState.CHECKING, ScanState.DISCOVERY_COMPLETE),
        (ScanState.VALIDATING, ScanState.CHECKING),
        (ScanState.REPORTING, ScanState.VALIDATING),
        # Self-transition (not in allowed set)
        (ScanState.INITIALIZED, ScanState.INITIALIZED),
        (ScanState.CHECKING, ScanState.CHECKING),
        # Terminal -> anything
        (ScanState.COMPLETED, ScanState.INITIALIZED),
        (ScanState.COMPLETED, ScanState.DISCOVERING),
        (ScanState.COMPLETED, ScanState.FAILED),
        (ScanState.FAILED, ScanState.INITIALIZED),
        (ScanState.FAILED, ScanState.CHECKING),
        (ScanState.FAILED, ScanState.COMPLETED),
        (ScanState.ABORTED, ScanState.INITIALIZED),
        (ScanState.ABORTED, ScanState.CHECKING),
        (ScanState.ABORTED, ScanState.COMPLETED),
    ],
)
def test_illegal_transitions_raise(
    current: ScanState, target: ScanState
) -> None:
    with pytest.raises(InvalidStateTransition):
        assert_transition(current, target)


def test_terminal_states_accept_no_further_transitions() -> None:
    for terminal in (ScanState.COMPLETED, ScanState.FAILED, ScanState.ABORTED):
        for target in ScanState:
            with pytest.raises(InvalidStateTransition):
                assert_transition(terminal, target)


def test_scan_context_transition_updates_state() -> None:
    ctx = ScanContext(target_name="example.com", run_id="run-1")
    assert ctx.state is ScanState.INITIALIZED

    ctx.transition(ScanState.DISCOVERING)
    assert ctx.state is ScanState.DISCOVERING

    ctx.transition(ScanState.DISCOVERY_COMPLETE)
    assert ctx.state is ScanState.DISCOVERY_COMPLETE

    ctx.transition(ScanState.CHECKING)
    assert ctx.state is ScanState.CHECKING

    ctx.transition(ScanState.REPORTING)
    assert ctx.state is ScanState.REPORTING

    ctx.transition(ScanState.COMPLETED)
    assert ctx.state is ScanState.COMPLETED


def test_scan_context_transition_rejects_illegal_moves() -> None:
    ctx = ScanContext(target_name="example.com", run_id="run-1")
    with pytest.raises(InvalidStateTransition):
        ctx.transition(ScanState.COMPLETED)


def test_findings_list_is_mutable_per_scan() -> None:
    ctx = ScanContext(target_name="example.com", run_id="run-1")
    ctx.findings.append("finding-a")
    ctx.findings.append("finding-b")
    assert ctx.findings == ["finding-a", "finding-b"]


def test_metadata_dict_is_mutable_per_scan() -> None:
    ctx = ScanContext(target_name="example.com", run_id="run-1")
    ctx.metadata["operator"] = "operator-a"
    assert ctx.metadata["operator"] == "operator-a"


def test_invalid_state_transition_message_mentions_both_states() -> None:
    try:
        assert_transition(ScanState.INITIALIZED, ScanState.COMPLETED)
    except InvalidStateTransition as e:
        msg = str(e)
        assert "initialized" in msg
        assert "completed" in msg
    else:
        pytest.fail("expected InvalidStateTransition")
