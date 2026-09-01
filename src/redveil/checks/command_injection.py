"""CommandInjectionCheck — detects command injection via time-based observation.

ACTIVE check. Uses ONLY `sleep` payloads (a benign binary that just waits).
NO destructive commands, NO file reads, NO data exfiltration. The proof is
the OBSERVED response delay, not exploitation.

ABSOLUTELY FORBIDDEN payloads (anywhere in this file or its tests):
- rm, cat, ls, wget, curl, nc, ncat, ssh, scp, rsync (any side-effect binary)
- Reading files: /etc/passwd, /etc/shadow, system32, SAM, boot.ini
- Writing files: >, >>, tee, dd of=
- Reverse shells: /dev/tcp, bash -i, python -c '...'
- Disk wiping: dd if=/dev/zero, mkfs, fdisk
"""
from __future__ import annotations

import statistics
from typing import Any
from urllib.parse import quote, urlparse

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

# ONLY safe sleep-based payloads. NO destructive commands.
# Each payload is just a sleep call with a separator, capped at 3 seconds.
_DELAY_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "& sleep 3",
    "&& sleep 3",
    "|| sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
]

# Safety assertion — fail loudly if anyone tries to add a destructive payload
_FORBIDDEN_SUBSTRINGS = (
    "rm ", "rm\t", "cat ", "wget", "curl ", "nc ", "ncat",
    "/etc/passwd", "/etc/shadow", "system32", "SAM",
    "> /", ">>", "tee ", "dd if=", "mkfs", "fdisk",
    "/dev/tcp", "bash -i", "python -c", "perl -e", "ruby -e",
    "chmod 777", "chmod -R", "chown",
    "uname -a",  # not destructive but exposes system info
)
for _payload in _DELAY_PAYLOADS:
    for _bad in _FORBIDDEN_SUBSTRINGS:
        if _bad in _payload:
            raise RuntimeError(f"FORBIDDEN payload fragment {_bad!r} in {_payload!r}")

_COMMON_PARAM_NAMES = [
    "q", "s", "search", "query", "id", "name", "input", "host", "ip",
    "target", "addr", "address", "domain", "file", "path", "url",
]


class CommandInjectionCheck(Check):
    meta = CheckMeta(
        id="command-injection",
        name="Command Injection Check (Time-Based)",
        category=CheckCategory.COMMAND_INJECTION,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects command injection via time-based observation using only `sleep` payloads. No destructive commands.",
        references=["CWE-78", "OWASP A03:2021"],
    )

    async def _measure_baseline(self, url: str, param: str) -> float:
        samples: list[float] = []
        for _ in range(2):
            try:
                req = Request(method="GET", url=f"{url}?{param}=redveil_baseline", purpose="baseline")
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

        # Optional ActionGate: present the sleep-probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Sleep probes are
        # LOW risk (only `sleep N` payloads, no destructive commands), so this
        # is auto-approved. Per-parameter baseline + controlled comparison.
        # Only GET requests, no body modification. Capped at sleep 3-5s max.
        # No shell metacharacters that do anything besides delay.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="cmdi-time-based-probe",
            description=(
                "Send time-based command-injection probes (only `sleep N` payloads, "
                "capped at sleep 3-5 seconds) to base URL parameters and measure "
                "response time. Per-parameter baseline + controlled comparison. "
                "Only GET requests, no body modification. No shell metacharacters "
                "that do anything besides delay. No destructive commands — only "
                "the sleep binary."
            ),
            risk=Risk.LOW,
            target=str(self.deps.config.target.base_url).rstrip("/") + "/",
            purpose="Detect command injection by measuring response time after sleep payloads.",
            expected_effect=(
                "200 OK responses; delayed (>1s) responses when sleep-equivalent "
                "payload is interpreted by a shell."
            ),
            potential_side_effects=(
                "Logged in server access log.",
                "May trigger WAF if present.",
                "Slight increase in response time for affected requests.",
            ),
            max_requests=len(_DELAY_PAYLOADS) * len(_COMMON_PARAM_NAMES),
            timeout_seconds=10.0,
            destructive=False,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                # User denied or auto-denied (destructive in non-interactive).
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []
        endpoint = join_url(base, "/")

        for param in _COMMON_PARAM_NAMES:
            try:
                baseline_ms = await self._measure_baseline(endpoint, param)
            except Exception:
                continue
            if baseline_ms <= 0:
                continue

            for payload in _DELAY_PAYLOADS:
                try:
                    test_url = f"{endpoint}?{param}={quote(payload, safe='')}"
                    req = Request(method="GET", url=test_url, purpose="probe", purpose_extra="cmdi_sleep")
                    resp = await self.deps.http.send(req)
                except Exception:
                    continue
                delay_ms = resp.elapsed_ms
                if delay_ms <= 0:
                    continue
                if delay_ms >= baseline_ms + 2000 and delay_ms >= baseline_ms * 3:
                    # Identify separator
                    separator = (
                        "backtick" if "`" in payload
                        else "$()" if "$(" in payload
                        else "&&" if "&&" in payload
                        else "||" if "||" in payload
                        else ";" if ";" in payload
                        else "|" if "|" in payload
                        else "&" if "&" in payload
                        else "unknown"
                    )
                    candidates.append({
                        "endpoint": "/",
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "separator": separator,
                        "baseline_ms": baseline_ms,
                        "delay_ms": delay_ms,
                        "ratio": delay_ms / max(baseline_ms, 1.0),
                        "request": req,
                        "response": resp,
                    })
                    # One delay per param is enough evidence — stop testing this param
                    break

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=f"baseline={candidate['baseline_ms']:.0f}ms; delay={candidate['delay_ms']:.0f}ms; ratio={candidate['ratio']:.1f}x — strong indicator",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.TIMING_DELTA,
            endpoint="/",
            method="GET",
            parameter=candidate.get("parameter"),
            input_used=candidate.get("payload", ""),
            status_code=resp.status_code,
            timing_ms=resp.elapsed_ms,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"time-based cmdi via '{candidate['separator']}' separator; baseline={candidate['baseline_ms']:.0f}ms; delay={candidate['delay_ms']:.0f}ms",
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
            summary = f"Time-based command injection detected in '{candidate['parameter']}' parameter."
            technical = f"Injecting a shell command separator caused the response to delay by {candidate['delay_ms']:.0f}ms."
            impact = "Attacker can execute arbitrary commands on the server."
            remediation = ["Avoid invoking shell commands with user input.", "Use parameterized APIs."]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Command Injection via '{candidate['parameter']}' Parameter (Time-Based)",
            severity=Severity.CRITICAL,
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
            cwe=["CWE-78"],
            owasp=["A03:2021"],
        )
