"""Tests for Wave 2: Oracle + multi-signal + confidence scoring."""
from __future__ import annotations
import math
import pytest
from redveil.validation.oracle import Oracle, Signal, SignalKind
from redveil.validation.confidence import ConfidenceScorer, ConfidenceScore
from redveil.findings.confidence import Confidence
from redveil.behavior.differential import DifferentialResult, compute_differential
from redveil.http.response import Response


def _resp(status=200, body="ok", elapsed=10.0, headers=None):
    return Response(
        request_id="r", status_code=status, headers=headers or {}, body=body, elapsed_ms=elapsed,
    )


# ---------------------------------------------------------------------------
# Oracle enum
# ---------------------------------------------------------------------------


def test_oracle_ordering():
    """Oracles are ranked by strength."""
    assert Oracle.STATUS_CODE_ONLY < Oracle.BODY_CONTENT
    assert Oracle.BODY_CONTENT < Oracle.STATE_TRANSITION
    assert Oracle.STATE_TRANSITION < Oracle.OWNERSHIP_VIOLATION


# ---------------------------------------------------------------------------
# Signal
# ---------------------------------------------------------------------------


def test_signal_equality():
    """Two signals with same kind + dimension are equal (used for de-dup)."""
    s1 = Signal(kind=SignalKind.STATUS_DIFF, description="a")
    s2 = Signal(kind=SignalKind.STATUS_DIFF, description="b")  # different desc
    s3 = Signal(kind=SignalKind.STATUS_DIFF, description="a", dimension="state")
    assert s1 == s2  # same kind + (default) dimension
    assert s1 != s3  # different dimension


def test_signal_kind_dimension_mapping():
    """Each standard kind has a known dimension."""
    assert SignalKind.DIMENSION[SignalKind.STATUS_DIFF] == "response"
    assert SignalKind.DIMENSION[SignalKind.STATE_TRANSITION] == "state"
    assert SignalKind.DIMENSION[SignalKind.OWNERSHIP_VIOLATION] == "ownership"
    assert SignalKind.DIMENSION[SignalKind.WEAK_TOKEN_ENTROPY] == "behavior"


# ---------------------------------------------------------------------------
# ConfidenceScorer
# ---------------------------------------------------------------------------


def test_no_signals_zero_score():
    scorer = ConfidenceScorer()
    score = scorer.score([], Oracle.BODY_CONTENT)
    assert score.signals_count == 0
    assert score.distinct_dimensions == 0
    assert score.score == 0.0
    assert score.to_confidence() == Confidence.TENTATIVE


def test_single_signal_low_confidence():
    scorer = ConfidenceScorer()
    score = scorer.score(
        [Signal(kind="x", description="y", weight=1.0, dimension="response")],
        Oracle.STATUS_CODE_ONLY,  # weak oracle
    )
    # 1 * 1.0 (mult) * (1 + 0.05) = 1.05
    assert score.signals_count == 1
    assert score.distinct_dimensions == 1
    assert score.to_confidence() == Confidence.LOW


def test_multi_signal_correlation_higher_confidence():
    """More distinct dimensions → higher confidence."""
    scorer = ConfidenceScorer()
    one_dim = scorer.score(
        [Signal(kind="a", description="x", dimension="response")],
        Oracle.BODY_CONTENT,  # medium oracle
    )
    two_dims = scorer.score(
        [
            Signal(kind="a", description="x", dimension="response"),
            Signal(kind="b", description="y", dimension="state"),
        ],
        Oracle.BODY_CONTENT,
    )
    # 2 * 1.5 = 3.0 vs 2 * 1.0 = 2.0
    assert two_dims.score > one_dim.score


def test_strong_oracle_higher_confidence():
    """Same signals, different oracle → different confidence."""
    scorer = ConfidenceScorer()
    sigs = [Signal(kind="a", description="x", dimension="response")]
    weak = scorer.score(sigs, Oracle.STATUS_CODE_ONLY)
    strong = scorer.score(sigs, Oracle.OWNERSHIP_VIOLATION)
    assert strong.score > weak.score


def test_environmental_penalty_reduces_confidence():
    scorer = ConfidenceScorer(environmental_penalty=0.0)
    base = scorer.score(
        [Signal(kind="a", description="x", weight=1.0, dimension="response")],
        Oracle.BODY_CONTENT,
    )
    scorer_penalized = ConfidenceScorer(environmental_penalty=2.0)
    penalized = scorer_penalized.score(
        [Signal(kind="a", description="x", weight=1.0, dimension="response")],
        Oracle.BODY_CONTENT,
    )
    assert penalized.score < base.score
    assert penalized.score >= 0.0  # clamped


def test_confidence_levels():
    """Mapping score → Confidence enum."""
    scorer = ConfidenceScorer()
    # 0 signals → 0 score → TENTATIVE
    assert scorer.score([], Oracle.STATUS_CODE_ONLY).to_confidence() == Confidence.TENTATIVE
    # Strong oracle + 3 distinct dims = CONFIRMED
    big = [
        Signal(kind="a", description="x", dimension="response"),
        Signal(kind="b", description="y", dimension="state"),
        Signal(kind="c", description="z", dimension="ownership"),
    ]
    score = scorer.score(big, Oracle.OWNERSHIP_VIOLATION)
    assert score.to_confidence() == Confidence.CONFIRMED


# ---------------------------------------------------------------------------
# DifferentialResult with signals
# ---------------------------------------------------------------------------


def test_differential_auto_signals_for_status_change():
    base = _resp(status=200)
    ctrl = _resp(status=403)
    diff = compute_differential(base, ctrl)
    assert any(s.kind == SignalKind.STATUS_DIFF for s in diff.signals)


def test_differential_auto_signals_for_body_change():
    base = _resp(body="alice owns this")
    ctrl = _resp(body="bob owns this")
    diff = compute_differential(base, ctrl)
    assert any(s.kind == SignalKind.BODY_DIFF for s in diff.signals)


def test_differential_auto_signals_for_timing():
    base = _resp(elapsed=50.0)
    ctrl = _resp(elapsed=3000.0)
    diff = compute_differential(base, ctrl)
    assert any(s.kind == SignalKind.TIMING_DELTA for s in diff.signals)


def test_differential_oracle_class_from_signals():
    """The oracle class is determined by signal dimensions."""
    base = _resp(status=200)
    ctrl = _resp(status=403)
    diff = compute_differential(base, ctrl)
    # Pure response signal → BODY_CONTENT or STATUS_CODE_ONLY
    assert diff.oracle() in (Oracle.BODY_CONTENT, Oracle.STATUS_CODE_ONLY)

    # Add an ownership signal → upgrades to OWNERSHIP_VIOLATION
    diff.add_signal(SignalKind.OWNERSHIP_VIOLATION, "alice accessed bob's data", weight=1.0)
    assert diff.oracle() == Oracle.OWNERSHIP_VIOLATION


def test_differential_oracle_class_for_state_signal():
    diff = DifferentialResult()
    diff.add_signal(SignalKind.STATE_TRANSITION, "authed → invalidated")
    assert diff.oracle() == Oracle.STATE_TRANSITION


# ---------------------------------------------------------------------------
# Integration: ConfidenceScorer + DifferentialResult
# ---------------------------------------------------------------------------


def test_session_xss_chain_high_confidence():
    """Simulate a session-cookie xss_steals_session finding being scored.

    The check emits REFLECTION_DIFF + cookie_flag_missing signals. Both are
    in 'response' dimension (auto-populated from header diff). Oracle is
    BODY_CONTENT. Score: 2 (oracle) * 1.0 (1 dim) * 1.04 (weight) = 2.08
    → MEDIUM. To get HIGH, the finding needs a state or ownership signal
    in addition.
    """
    diff = DifferentialResult()
    diff.add_signal(SignalKind.REFLECTION_DIFF, "canary reflected unescaped", weight=1.0)
    diff.add_signal("cookie_flag_missing", "HttpOnly missing", weight=0.8)
    oracle = diff.oracle()
    assert oracle == Oracle.BODY_CONTENT  # both signals are response dim
    score = ConfidenceScorer().score(diff.signals, oracle)
    # 2 * 1.0 * 1.04 = 2.08 → MEDIUM
    assert score.to_confidence() == Confidence.MEDIUM


def test_hardening_gap_only_low_confidence():
    """Without attack chain, hardening gaps should be LOW confidence."""
    diff = DifferentialResult()
    diff.add_signal("cookie_flag_missing", "HttpOnly missing (no XSS)", weight=0.4)
    oracle = diff.oracle()
    # STATUS_CODE_ONLY = 1, 1 dim, 0.4 weight
    # 1 * 1.0 * (1 + 0.05*0.4) = 1.02 → LOW
    score = ConfidenceScorer().score(diff.signals, oracle)
    assert score.to_confidence() == Confidence.LOW


def test_ownership_signal_promotes_to_confirmed():
    """An ownership-violation signal alone (without other signals) is enough
    to push a strong-oracle finding to CONFIRMED.
    """
    diff = DifferentialResult()
    diff.add_signal(SignalKind.OWNERSHIP_VIOLATION, "alice accessed bob's order", weight=1.0)
    oracle = diff.oracle()
    assert oracle == Oracle.OWNERSHIP_VIOLATION
    score = ConfidenceScorer().score(diff.signals, oracle)
    # 5 * 1.0 * 1.05 = 5.25 → CONFIRMED
    assert score.to_confidence() == Confidence.CONFIRMED
