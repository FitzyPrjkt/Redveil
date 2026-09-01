"""TimeBasedSQLiCheck — detects time-based blind SQL injection.

ACTIVE check. Uses ONLY time-delay payloads (SLEEP/pg_sleep/WAITFOR DELAY).
No data extraction. No SELECT/UNION/OR 1=1 exploitation. The proof is the
OBSERVED response delay, not data exfiltration.
"""
from __future__ import annotations

import statistics
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, FindingStatus, TargetRef
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)
from redveil.util.urls import join_url

# Time-delay payloads (NO data extraction, NO SELECT/UNION/OR)
# Capped at 3 seconds delay — observable but bounded.
_DELAY_PAYLOADS = [
    ("mysql", "1' AND SLEEP(3)-- -"),
    ("mysql", "1) AND SLEEP(3)-- -"),
    ("mysql", "1 AND SLEEP(3)"),
    ("postgresql", "1' AND pg_sleep(3)-- -"),
    ("postgresql", "1; SELECT pg_sleep(3)-- -"),
    ("mssql", "1'; WAITFOR DELAY '00:00:03'-- -"),
    ("mssql", "1' WAITFOR DELAY '00:00:03'-- -"),
    ("sqlite", "1' AND 1=randomblob(500000000)-- -"),  # CPU delay, not data extraction
]

_COMMON_PARAM_NAMES = [
    "q", "s", "search", "query", "id", "name", "input", "user", "username",
    "email", "page", "cat", "category", "filter", "sort", "order",
    "from", "to", "date", "year", "month",
]

_BASELINE_SAMPLES = 2
_DELAY_THRESHOLD_MS = 2000.0
_DELAY_RATIO = 3.0


class TimeBasedSQLiCheck(Check):
    meta = CheckMeta(
        id="sqli-time-based",
        name="Time-Based Blind SQL Injection Check",
        category=CheckCategory.SQLI,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects time-based blind SQL injection via bounded SLEEP/pg_sleep/WAITFOR DELAY probes. No data extraction.",
        references=["CWE-89", "OWASP A03:2021"],
    )

    async def _measure_median(self, url: str, param: str, value: str) -> float:
        samples: list[float] = []
        for _ in range(_BASELINE_SAMPLES):
            try:
                test_url = f"{url}?{param}={value}"
                req = Request(method="GET", url=test_url, purpose="baseline")
                resp = await self.deps.http.send(req)
                samples.append(resp.elapsed_ms)
            except Exception:
                pass
        return statistics.median(samples) if samples else 0.0

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # Test a few common parameter names
        params_to_test = _COMMON_PARAM_NAMES[:8]  # cap to keep scan bounded
        endpoint = join_url(base, "/")

        for param in params_to_test:
            try:
                baseline_ms = await self._measure_median(endpoint, param, "redveil_baseline")
                if baseline_ms <= 0:
                    continue
            except Exception:
                continue

            for db_family, payload in _DELAY_PAYLOADS:
                # Import urllib.parse.quote to encode payload
                from urllib.parse import quote
                try:
                    test_url = f"{endpoint}?{param}={quote(payload, safe='')}"
                    req = Request(method="GET", url=test_url, purpose="probe", purpose_extra=f"sqli_{db_family}")
                    resp = await self.deps.http.send(req)
                except Exception:
                    continue
                delay_ms = resp.elapsed_ms
                if delay_ms <= 0:
                    continue
                if delay_ms >= baseline_ms + _DELAY_THRESHOLD_MS and delay_ms >= baseline_ms * _DELAY_RATIO:
                    candidates.append({
                        "endpoint": "/",
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "db_family": db_family,
                        "baseline_ms": baseline_ms,
                        "delay_ms": delay_ms,
                        "ratio": delay_ms / max(baseline_ms, 1.0),
                        "request": req,
                        "response": resp,
                    })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        ratio = candidate.get("ratio", 0)
        delay = candidate.get("delay_ms", 0)
        if ratio >= 3 and delay >= 2000:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=f"baseline={candidate['baseline_ms']:.0f}ms; delay={delay:.0f}ms; ratio={ratio:.1f}x — strong indicator",
            )
        if ratio >= 2 and delay >= 1500:
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=f"baseline={candidate['baseline_ms']:.0f}ms; delay={delay:.0f}ms; ratio={ratio:.1f}x",
            )
        return ValidationResult(outcome=ValidationOutcome.FALSE_POSITIVE, confidence="low", observation="delay below threshold")

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.TIMING_DELTA,
            endpoint=candidate.get("endpoint", "/"),
            method="GET",
            parameter=candidate.get("parameter"),
            input_used=candidate.get("payload", ""),
            status_code=resp.status_code,
            timing_ms=resp.elapsed_ms,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"baseline={candidate['baseline_ms']:.0f}ms; delay={candidate['delay_ms']:.0f}ms; ratio={candidate['ratio']:.1f}x",
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry(self.meta.id, "time_based")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Time-based SQL injection detected in '{candidate['parameter']}' parameter ({candidate['db_family']} family)."
            technical = f"Injecting a SLEEP-equivalent payload causes the response to delay by {candidate['delay_ms']:.0f}ms (baseline {candidate['baseline_ms']:.0f}ms)."
            impact = "Attacker can extract database content character-by-character via timing differences."
            remediation = ["Use parameterized queries.", "Use an ORM.", "Apply input validation."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Time-Based Blind SQL Injection via '{candidate['parameter']}' Parameter",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint="/",
                method="GET",
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("payload", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-89"],
            owasp=["A03:2021"],
        )
