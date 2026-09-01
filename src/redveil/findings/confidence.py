from __future__ import annotations

from enum import Enum


class Confidence(str, Enum):
    """How certain we are the finding is real (independent of severity)."""
    CONFIRMED = "confirmed"   # direct proof, reproducible
    HIGH = "high"             # strong evidence, minor doubt
    MEDIUM = "medium"         # plausible, needs manual review
    LOW = "low"               # weak signal, likely false positive
    TENTATIVE = "tentative"   # heuristic only
