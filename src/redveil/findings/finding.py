from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from redveil.findings.confidence import Confidence
from redveil.findings.severity import Severity


class FindingStatus(str, Enum):
    DISCOVERED = "discovered"
    SUSPECTED = "suspected"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"


class CheckRef(BaseModel):
    id: str
    name: str
    version: str = "0.1.0"
    category: str | None = None


class TargetRef(BaseModel):
    host: str
    port: int | None = None
    scheme: str = "https"
    endpoint: str
    method: str = "GET"
    parameter: str | None = None


class ReproductionStep(BaseModel):
    step: int
    description: str
    request: str | None = None  # cURL form
    response_excerpt: str | None = None


class Finding(BaseModel):
    """A structured security finding with full evidence and reproduction context."""
    id: str = Field(default_factory=lambda: f"WPOC-{uuid.uuid4().hex[:6].upper()}")
    check: CheckRef
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus = FindingStatus.DISCOVERED

    target: TargetRef
    parameter: str | None = None
    input_used: str | None = None  # the actual payload/parameter value used

    summary: str
    technical_explanation: str
    impact: str

    evidence_ids: list[str] = Field(default_factory=list)  # references to Evidence
    reproduction: list[ReproductionStep] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)

    cwe: list[str] = Field(default_factory=list)  # e.g. ["CWE-79"]
    owasp: list[str] = Field(default_factory=list)  # e.g. ["A03:2021"]
    references: list[str] = Field(default_factory=list)  # URLs

    # Rich content from the vulnerability knowledge base. Optional — checks
    # populate these when the knowledge base has an entry for their issue.
    attack_scenario: str | None = None
    code_examples: dict[str, str] = Field(default_factory=dict)

    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    confirmed_at: datetime | None = None
    testing_principal: str | None = None  # who issued the request (for multi-principal tests)
    fingerprint: str | None = None  # for deduplication

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
