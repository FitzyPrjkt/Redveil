"""Tests for Wave 6: Environment awareness + Uncertainty propagation."""
from __future__ import annotations
import pytest
from redveil.validation.environment import (
    Environment, EnvironmentProfile, Uncertainty,
)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def test_environment_from_string_basic():
    assert Environment.from_string("dev") == Environment.DEV
    assert Environment.from_string("production") == Environment.PRODUCTION
    assert Environment.from_string("waf") == Environment.WAF


def test_environment_from_string_aliases():
    """Common aliases resolve to canonical environment."""
    assert Environment.from_string("prod") == Environment.PRODUCTION
    assert Environment.from_string("live") == Environment.PRODUCTION
    assert Environment.from_string("qa") == Environment.STAGING
    assert Environment.from_string("test") == Environment.STAGING
    assert Environment.from_string("localhost") == Environment.DEV


def test_environment_from_string_unknown_defaults_to_production():
    assert Environment.from_string("garbage") == Environment.PRODUCTION


def test_environment_profile_dev_zero_penalty():
    """Dev environment has 0 penalty — findings are real."""
    profile = EnvironmentProfile(environments=(Environment.DEV,))
    assert profile.environmental_penalty == 0.0
    assert not profile.is_noisy


def test_environment_profile_production_penalty():
    profile = EnvironmentProfile(environments=(Environment.PRODUCTION,))
    assert profile.environmental_penalty == 0.5
    assert profile.is_noisy


def test_environment_profile_waf_highest_penalty():
    profile = EnvironmentProfile(environments=(Environment.WAF,))
    assert profile.environmental_penalty == 0.6
    assert profile.is_noisy


def test_environment_profile_stacked():
    """Multiple environments sum their penalties."""
    profile = EnvironmentProfile(environments=(Environment.PRODUCTION, Environment.WAF, Environment.CDN))
    # 0.5 + 0.6 + 0.3 = 1.4
    assert profile.environmental_penalty == 1.4
    assert profile.is_noisy


def test_environment_profile_from_config_string():
    profile = EnvironmentProfile.from_config("production,waf")
    assert Environment.PRODUCTION in profile.environments
    assert Environment.WAF in profile.environments


def test_environment_profile_from_config_empty():
    """Empty config string → default to production."""
    profile = EnvironmentProfile.from_config("")
    assert Environment.PRODUCTION in profile.environments


def test_environment_profile_str():
    profile = EnvironmentProfile(environments=(Environment.PRODUCTION, Environment.WAF))
    assert str(profile) == "production,waf"


# ---------------------------------------------------------------------------
# Uncertainty
# ---------------------------------------------------------------------------


def test_uncertainty_empty_zero():
    u = Uncertainty()
    assert u.total == 0.0
    assert u.to_penalty() == 0.0
    assert not u  # falsy when empty
    assert u.is_acceptable()


def test_uncertainty_single_source():
    u = Uncertainty()
    u.add("flaky", 0.5)
    assert u.total == 0.5
    assert u.is_acceptable()  # 0.5 is at the threshold
    assert u.to_penalty() == 1.0  # 0.5 * 2


def test_uncertainty_max_source_dominates():
    """Total uncertainty is the max of all sources (weakest link)."""
    u = Uncertainty()
    u.add("flaky", 0.3)
    u.add("network", 0.8)
    u.add("cache", 0.1)
    assert u.total == 0.8  # max wins


def test_uncertainty_clamped_to_unit_interval():
    u = Uncertainty()
    u.add("flaky", 1.5)  # above 1.0
    assert u.sources["flaky"] == 1.0
    u.add("network", -0.5)  # below 0.0
    assert u.sources["network"] == 0.0


def test_uncertainty_is_acceptable_threshold():
    u = Uncertainty()
    u.add("flaky", 0.4)
    assert u.is_acceptable(threshold=0.5)
    assert not u.is_acceptable(threshold=0.3)


def test_uncertainty_to_penalty_scales():
    u = Uncertainty()
    u.add("x", 0.0)
    assert u.to_penalty() == 0.0
    u.add("x", 0.5)
    assert u.to_penalty() == 1.0
    u.add("x", 1.0)
    assert u.to_penalty() == 2.0


# ---------------------------------------------------------------------------
# Integration: environment + uncertainty in confidence scoring
# ---------------------------------------------------------------------------


def test_environment_penalty_reduces_confidence():
    """Same signals, but in different environments → different confidence."""
    from redveil.validation.oracle import Oracle, Signal
    from redveil.validation.confidence import ConfidenceScorer

    sigs = [
        Signal(kind="x", weight=1.0, dimension="response", description="xss"),
        Signal(kind="y", weight=0.8, dimension="state", description="cookie"),
    ]

    # Dev: no penalty
    dev_profile = EnvironmentProfile(environments=(Environment.DEV,))
    dev_scorer = ConfidenceScorer(environmental_penalty=dev_profile.environmental_penalty)
    dev_score = dev_scorer.score(sigs, Oracle.STATE_TRANSITION).score

    # Production: penalty
    prod_profile = EnvironmentProfile(environments=(Environment.PRODUCTION,))
    prod_scorer = ConfidenceScorer(environmental_penalty=prod_profile.environmental_penalty)
    prod_score = prod_scorer.score(sigs, Oracle.STATE_TRANSITION).score

    # Same signals, same oracle — but production adds a 0.5 penalty → lower
    assert prod_score < dev_score
    assert dev_score - prod_score == pytest.approx(0.5, abs=0.01)


def test_uncertainty_propagates_to_penalty():
    """A single high-uncertainty step in the pipeline should lower confidence."""
    from redveil.validation.oracle import Oracle, Signal
    from redveil.validation.confidence import ConfidenceScorer

    sigs = [
        Signal(kind="x", weight=1.0, dimension="response", description="xss"),
    ]
    oracle = Oracle.STATE_TRANSITION

    # No uncertainty
    clean = ConfidenceScorer(environmental_penalty=0.0).score(sigs, oracle).score

    # High uncertainty → big penalty
    u = Uncertainty()
    u.add("flaky_endpoint", 0.9)  # very flaky
    uncertain = ConfidenceScorer(environmental_penalty=u.to_penalty()).score(
        sigs, oracle
    ).score

    assert uncertain < clean
    # Penalty of 0.9 * 2 = 1.8 → score should drop by 1.8
    assert clean - uncertain == pytest.approx(1.8, abs=0.01)
