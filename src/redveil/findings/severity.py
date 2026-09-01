from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """CVSS-inspired severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0: return cls.CRITICAL
        if score >= 7.0: return cls.HIGH
        if score >= 4.0: return cls.MEDIUM
        if score > 0.0: return cls.LOW
        return cls.INFO
