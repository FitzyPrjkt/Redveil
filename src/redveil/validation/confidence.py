"""ConfidenceScorer — compute Finding confidence from multi-signal evidence.

A finding's confidence is NOT a fixed value per check. It depends on:
- The Oracle class (how strong the evidence is)
- The number of independent signals from different dimensions
- Signal weights
- Optional environmental penalties (flakiness, low-quality responses)

Formula:
    mult = 1.0 + (distinct - 1) * 0.5  # 1 dim=1.0, 2=1.5, 3=2.0, 4+=2.5
    raw = oracle * mult * (1.0 + 0.05 * aggregated_weight)
    final = max(0.0, raw - environmental_penalty)

Mapping back to Confidence enum:
    score >= 4   → CONFIRMED
    score >= 3   → HIGH
    score >= 2   → MEDIUM
    score >= 1   → LOW
    score <  1   → TENTATIVE
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable

from redveil.findings.confidence import Confidence
from redveil.validation.oracle import Oracle, Signal


@dataclass
class ConfidenceScore:
    """Numeric confidence score + breakdown."""
    score: float
    base_oracle: float
    distinct_dimensions: int
    environmental_penalty: float
    signals_count: int

    def to_confidence(self) -> Confidence:
        if self.score >= 4.0:
            return Confidence.CONFIRMED
        if self.score >= 3.0:
            return Confidence.HIGH
        if self.score >= 2.0:
            return Confidence.MEDIUM
        if self.score >= 1.0:
            return Confidence.LOW
        return Confidence.TENTATIVE


class ConfidenceScorer:
    """Compute Confidence from signals + oracle + environment."""

    def __init__(self, environmental_penalty: float = 0.0):
        self.environmental_penalty = environmental_penalty

    def score(self, signals: Iterable[Signal], oracle: Oracle) -> ConfidenceScore:
        sigs = list(signals)
        if not sigs:
            return ConfidenceScore(
                score=0.0,
                base_oracle=float(oracle),
                distinct_dimensions=0,
                environmental_penalty=self.environmental_penalty,
                signals_count=0,
            )

        # Aggregate per-dimension. Take max weight per dimension so
        # multiple signals from the same dimension don't inflate confidence.
        per_dim: dict[str, float] = {}
        for s in sigs:
            per_dim[s.dimension] = max(per_dim.get(s.dimension, 0.0), s.weight)
        aggregated = sum(per_dim.values())
        distinct = len(per_dim)

        # Multi-signal correlation. 1 dim = 1.0x, 2 = 1.5x, 3 = 2.0x, 4+ = 2.5x.
        # Strong oracles benefit more from multi-signal because they have a
        # higher base; weak oracles stay low unless we have many independent
        # signals.
        if distinct >= 4:
            mult = 2.5
        elif distinct == 3:
            mult = 2.0
        elif distinct == 2:
            mult = 1.5
        else:
            mult = 1.0

        raw = float(oracle) * mult * (1.0 + 0.05 * aggregated)
        final = max(0.0, raw - self.environmental_penalty)

        return ConfidenceScore(
            score=round(final, 3),
            base_oracle=float(oracle),
            distinct_dimensions=distinct,
            environmental_penalty=self.environmental_penalty,
            signals_count=len(sigs),
        )

    def confidence(self, signals: Iterable[Signal], oracle: Oracle) -> Confidence:
        return self.score(signals, oracle).to_confidence()
