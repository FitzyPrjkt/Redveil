"""SessionCookieCheck — vector-based session-token exposure detection.

PASSIVE check. Identifies the session cookie, then for each of three attack
vectors (browser, network, server), tests whether the cookie is exposed.

The check is structured around the threat model:

                SESSION COOKIE
                       │
     ┌─────────────────┼─────────────────┐
     ▼                 ▼                 ▼
 🌐 Browser        📡 Network        🖥️  Server
     │                 │                 │
 XSS?              HTTPS?             Weak entropy?
 no HttpOnly?      no Secure?         Token leaked
 no SameSite?      in URL?            in debug?
     │                 │                 │
     └─────────────────┼─────────────────┘
                       ▼
              Confirmed / Likely / False positive

The old flat check reported any missing flag as a finding regardless of
whether the flag was actually exploitable. The vector-based design only
escalates severity when the missing flag aligns with a reachable attack
path. This reduces false positives and produces findings that already
include the full attack chain for the dev team.
"""
from __future__ import annotations

import re
from collections import Counter
from math import log2
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, FindingStatus, TargetRef
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)
from redveil.util.urls import join_url
from redveil.validation.confidence import ConfidenceScorer
from redveil.validation.oracle import Oracle, Signal, SignalKind

# Token-like query parameter names — common leak vectors.
_TOKEN_PARAM_NAMES = (
    "token", "session", "auth", "apikey", "api_key", "access_token",
    "sid", "secret", "key", "jwt",
)

# Cookie names that suggest a session/auth identifier.
_SESSION_COOKIE_NAMES = (
    "session", "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "aspsessionid", "auth", "auth_token", "token",
    "user_token", "csrf_token", "remember_me", "remember_token", "connect.sid",
)

# Entropy thresholds (bits per character).
_ENTROPY_CONFIRMED = 3.0
_ENTROPY_LIKELY = 3.5

# Minimum acceptable session-token length (chars).
_MIN_TOKEN_LEN = 16

# Canary strings for the inline XSS reflection probe (browser vector).
# Plain alphanumeric, HTML-encoded quote, angle brackets. Cannot execute JS.
_XSS_CANARIES = (
    "redveilXSSProbe12345",
    "redv&quot;ail12345",
    "redveilXSSanglebracketless12345",
)
_REFLECTED_THRESHOLD = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * log2(c / length) for c in counts.values())


def _split_set_cookie(combined: str) -> list[str]:
    if not combined:
        return []
    return [
        p.strip()
        for p in re.split(r", (?=[A-Za-z0-9_.\-]+=)", combined)
        if p.strip()
    ]


def _parse_set_cookie(value: str) -> dict[str, str] | None:
    if not value or "=" not in value:
        return None
    segments = [s.strip() for s in value.split(";") if s.strip()]
    if not segments:
        return None
    name, _, val = segments[0].partition("=")
    name, val = name.strip(), val.strip()
    if not name:
        return None
    out = {"name": name, "value": val}
    for seg in segments[1:]:
        if "=" in seg:
            k, _, v = seg.partition("=")
            out[k.strip().lower()] = v.strip()
        else:
            out[seg.strip().lower()] = "true"
    return out


def _iter_set_cookies(headers: dict[str, str]) -> list[dict[str, str]]:
    raw = next(
        (v for k, v in headers.items() if k.lower() == "set-cookie"),
        None,
    )
    if not raw:
        return []
    return [
        p
        for p in (_parse_set_cookie(seg) for seg in _split_set_cookie(raw))
        if p
    ]


def _is_session_cookie_name(name: str) -> bool:
    return any(tok in name.lower() for tok in _SESSION_COOKIE_NAMES)


def _is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


def _redact(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "..." + ("[REDACTED]" if len(value) > keep + 8 else "")


def _canary_reflected(resp_body: str) -> bool:
    """True if any canary string appears verbatim in the response body."""
    return any(canary in resp_body for canary in _XSS_CANARIES)


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------


class SessionCookieCheck(Check):
    """Vector-based session-token exposure detection."""

    meta = CheckMeta(
        id="session-cookie",
        name="Session Token Exposure (Vector-Based)",
        category=CheckCategory.SESSION,
        safety_profile=SafetyProfile.PASSIVE,
        version="0.2.0",
        description=(
            "Detects session-token exposure via three attack vectors: "
            "Browser (XSS + missing HttpOnly), Network (missing Secure over "
            "HTTPS, token in URL), and Server (weak entropy, token in debug "
            "log). Findings include the full attack chain, not just a "
            "missing flag."
        ),
        references=[
            "CWE-1004: Sensitive Cookie Without HttpOnly Flag",
            "CWE-614: Sensitive Cookie Without Secure Attribute",
            "CWE-1275: Sensitive Cookie with SameSite None",
            "CWE-330: Use of Insufficiently Random Values",
            "CWE-598: Information Exposure Through Query Strings",
            "CWE-384: Session Fixation",
            "OWASP A05:2021 — Security Misconfiguration",
            "OWASP A07:2021 — Identification and Authentication Failures",
        ],
    )

    def __init__(self) -> None:
        super().__init__()
        # Per-session cookie, hold the most recent request/response for
        # collect_evidence() and assess() to reference.
        self._captured: dict[str, tuple[Request, Response]] = {}

    # -- discover --------------------------------------------------------

    async def discover(self, ctx) -> list[dict[str, Any]]:  # type: ignore[override]
        base = str(self.deps.config.target.base_url).rstrip("/")
        self._captured = {}
        candidates: list[dict[str, Any]] = []

        try:
            home_req = Request(method="GET", url=join_url(base, "/"), purpose="discovery")
            home_resp = await self.deps.http.send(home_req)
        except Exception:
            return candidates

        self._captured["home"] = (home_req, home_resp)
        session_cookies = [
            c for c in _iter_set_cookies(home_resp.headers)
            if _is_session_cookie_name(c["name"]) and c["value"]
        ]
        if not session_cookies:
            # No session cookies on homepage; still check the body for
            # leaked tokens (in case a token appears in a URL or response).
            candidates.extend(self._token_leakage_candidates(home_req, home_resp))
            return candidates

        # Quick inline XSS reflection probe — cheap, single GET with a canary.
        xss_evidence = await self._quick_xss_probe(base, home_resp)

        for cookie in session_cookies:
            # Run each vector test for this cookie.
            candidates.extend(
                self._check_browser_vector(cookie, home_req, home_resp, xss_evidence)
            )
            candidates.extend(
                self._check_network_vector(cookie, home_req, home_resp)
            )
            candidates.extend(
                self._check_server_vector(cookie, home_req, home_resp)
            )

        candidates.extend(self._token_leakage_candidates(home_req, home_resp))
        return candidates

    # -- vector: browser --------------------------------------------------

    def _check_browser_vector(
        self,
        cookie: dict[str, str],
        home_req: Request,
        home_resp: Response,
        xss_evidence: Evidence | None,
    ) -> list[dict[str, Any]]:
        """Browser-side attack vector: XSS reads the cookie via document.cookie.

        Severity escalates if XSS reflection is observed on the same origin —
        then missing HttpOnly is a *confirmed* exposure, not just a hardening
        gap.
        """
        findings: list[dict[str, Any]] = []
        has_httponly = cookie.get("httponly") == "true"
        samesite = cookie.get("samesite")

        if not has_httponly:
            if xss_evidence is not None:
                findings.append({
                    "vector": "browser",
                    "subkind": "xss_steals_session",
                    "cookie_name": cookie["name"],
                    "cookie_value": cookie["value"],
                    "xss_evidence": xss_evidence,
                    "request": xss_evidence.request,
                    "response": xss_evidence.response,
                    "endpoint": xss_evidence.endpoint,
                    "title": (
                        f"Session Token Exposed via Browser Vector: "
                        f"XSS reads cookie '{cookie['name']}' (HttpOnly missing)"
                    ),
                    "issue_key": "session_xss_steals",
                })
            else:
                findings.append({
                    "vector": "browser",
                    "subkind": "httponly_missing_no_xss",
                    "cookie_name": cookie["name"],
                    "cookie_value": cookie["value"],
                    "request": home_req,
                    "response": home_resp,
                    "endpoint": home_req.url,
                    "title": (
                        f"Session Token Hardening Gap: cookie '{cookie['name']}' "
                        f"missing HttpOnly (no XSS observed yet)"
                    ),
                    "issue_key": "cookie_httponly_missing",
                })

        if not samesite or samesite.lower() == "none":
            if xss_evidence is not None:
                findings.append({
                    "vector": "browser",
                    "subkind": "csrf_via_xss",
                    "cookie_name": cookie["name"],
                    "cookie_value": cookie["value"],
                    "xss_evidence": xss_evidence,
                    "request": xss_evidence.request,
                    "response": xss_evidence.response,
                    "endpoint": xss_evidence.endpoint,
                    "title": (
                        f"Session Token Exposed via Browser Vector: "
                        f"XSS + SameSite={samesite or 'unset'} enables CSRF chain"
                    ),
                    "issue_key": "session_csrf_chain",
                })
            else:
                findings.append({
                    "vector": "browser",
                    "subkind": "samesite_missing",
                    "cookie_name": cookie["name"],
                    "cookie_value": cookie["value"],
                    "request": home_req,
                    "response": home_resp,
                    "endpoint": home_req.url,
                    "title": (
                        f"Session Token Hardening Gap: cookie '{cookie['name']}' "
                        f"missing SameSite (no CSRF surface observed)"
                    ),
                    "issue_key": "cookie_samesite_missing",
                })

        return findings

    # -- vector: network --------------------------------------------------

    def _check_network_vector(
        self,
        cookie: dict[str, str],
        home_req: Request,
        home_resp: Response,
    ) -> list[dict[str, Any]]:
        """Network-side attack vector: MITM reads the cookie on the wire.

        Severity escalates if HTTPS is used but the Secure flag is missing
        — that's a *real* MITM exposure. Plaintext over HTTP is reported
        separately as a transport-level issue.
        """
        findings: list[dict[str, Any]] = []
        has_secure = cookie.get("secure") == "true"

        if _is_https(home_req.url) and not has_secure:
            findings.append({
                "vector": "network",
                "subkind": "secure_missing_over_https",
                "cookie_name": cookie["name"],
                "cookie_value": cookie["value"],
                "request": home_req,
                "response": home_resp,
                "endpoint": home_req.url,
                "title": (
                    f"Session Token Exposed via Network Vector: "
                    f"HTTPS site sends cookie '{cookie['name']}' without "
                    f"Secure flag (MITM-readable on HTTP downgrade)"
                ),
                "issue_key": "session_mitm_exposure",
            })

        return findings

    # -- vector: server ---------------------------------------------------

    def _check_server_vector(
        self,
        cookie: dict[str, str],
        home_req: Request,
        home_resp: Response,
    ) -> list[dict[str, Any]]:
        """Server-side attack vector: weak randomness, predictable tokens,
        brute-forceable sessions."""
        findings: list[dict[str, Any]] = []
        value = cookie["value"]

        # Skip trivially-numeric or very short values (not real session tokens).
        if not value or value.isdigit() or len(value) < 4:
            return findings

        entropy = shannon_entropy(value)
        if entropy < _ENTROPY_CONFIRMED or len(value) < _MIN_TOKEN_LEN:
            findings.append({
                "vector": "server",
                "subkind": "weak_token",
                "cookie_name": cookie["name"],
                "cookie_value": value,
                "entropy_bits": round(entropy, 3),
                "token_length": len(value),
                "request": home_req,
                "response": home_resp,
                "endpoint": home_req.url,
                "title": (
                    f"Session Token Exposed via Server Vector: "
                    f"weak entropy on '{cookie['name']}' "
                    f"({entropy:.2f} bits/char, {len(value)} chars)"
                ),
                "issue_key": "session_weak_token",
            })

        return findings

    # -- inline XSS probe ------------------------------------------------

    async def _quick_xss_probe(
        self,
        base: str,
        home_resp: Response,
    ) -> Evidence | None:
        """Send a benign canary in a common reflection point. If the canary
        appears unescaped in the response, we have evidence that an XSS
        attack chain is feasible on this origin.
        """
        # Prefer a reflection point that exists in the homepage HTML.
        # Common param names that often reflect in title or error messages.
        candidate_params = ("q", "search", "query", "id", "name", "input")
        for param in candidate_params:
            canary = _XSS_CANARIES[0]
            try:
                test_url = f"{base}/?{param}={canary}"
                req = Request(method="GET", url=test_url, purpose="xss_canary_probe")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code == 200 and canary in resp.body:
                self._captured["xss_probe"] = (req, resp)
                return Evidence(
                    request=req,
                    response=resp,
                    kind=ObservationKind.REFLECTION,
                    endpoint=test_url,
                    method="GET",
                    parameter=param,
                    input_used=canary,
                    status_code=resp.status_code,
                    relevant_headers={"content-type": resp.headers.get("content-type", "")},
                    body_excerpt=resp.body_excerpt,
                    observation="benign canary reflected unescaped — XSS chain feasible",
                )
        return None

    # -- token leakage (server vector side-effect) -----------------------

    def _token_leakage_candidates(
        self, req: Request, resp: Response
    ) -> list[dict[str, Any]]:
        body = resp.body or ""
        if not body:
            return []
        candidates: list[dict[str, Any]] = []
        for name in _TOKEN_PARAM_NAMES:
            pattern = re.compile(
                rf"(?:^|[?&;\s])(?:{re.escape(name)})\s*=\s*"
                rf"(?P<value>[A-Za-z0-9_\-/.+=%]{{8,}})",
                re.IGNORECASE,
            )
            for m in pattern.finditer(body):
                value = m.group("value")
                if len(value) < 8:
                    continue
                candidates.append({
                    "vector": "server",
                    "subkind": "token_in_response_body",
                    "cookie_name": "(none — token in body)",
                    "parameter": name,
                    "value": value,
                    "request": req,
                    "response": resp,
                    "endpoint": req.url,
                    "title": (
                        f"Session Token Exposed via Server Vector: "
                        f"token-like parameter '{name}' reflected in response"
                    ),
                    "issue_key": "token_in_url",
                })
                break
        return candidates

    # -- validate --------------------------------------------------------

    async def validate(  # type: ignore[override]
        self, ctx, candidate: dict[str, Any]
    ) -> ValidationResult | None:
        subkind = candidate.get("subkind", "")
        # XSS chain confirmed: directly observed
        if subkind == "xss_steals_session":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="canary reflection + missing HttpOnly = direct attack chain",
            )
        if subkind == "csrf_via_xss":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="XSS observed on same origin + SameSite unset enables CSRF chain",
            )
        # MITM: HTTPS site with non-Secure cookie
        if subkind == "secure_missing_over_https":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="HTTPS site sets cookie without Secure flag — MITM-readable",
            )
        # Weak token: entropy-driven
        if subkind == "weak_token":
            entropy = candidate.get("entropy_bits", 0.0)
            token_len = candidate.get("token_length", 0)
            if entropy < _ENTROPY_CONFIRMED or token_len < 8:
                return ValidationResult(
                    outcome=ValidationOutcome.CONFIRMED,
                    confidence="high",
                    observation=f"token entropy {entropy} bits/char, length {token_len}",
                )
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=f"token entropy {entropy} bits/char — borderline",
            )
        # Token in body: directly observable
        if subkind == "token_in_response_body":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation="token-like parameter reflected in response body",
            )
        # Hardening gaps with no observed attack chain
        if subkind in {"httponly_missing_no_xss", "samesite_missing"}:
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="low",
                observation="hardening gap; no observed attack chain — defense in depth",
            )
        return ValidationResult(
            outcome=ValidationOutcome.INCONCLUSIVE,
            confidence="low",
            observation="unknown subkind",
        )

    # -- evidence --------------------------------------------------------

    async def collect_evidence(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> list[Evidence]:
        req: Request | None = candidate.get("request")
        resp: Response | None = candidate.get("response")
        if req is None or resp is None:
            return []

        relevant: dict[str, str] = {
            k: v for k, v in resp.headers.items()
            if k.lower() in {"set-cookie", "location", "referer"}
        }

        subkind = candidate.get("subkind", "")
        if subkind == "token_in_response_body":
            param = candidate.get("parameter", "")
            value = candidate.get("value", "")
            idx = resp.body.find(f"{param}={value}")
            if idx < 0:
                excerpt = resp.body_excerpt
            else:
                start = max(0, idx - 100)
                end = min(len(resp.body), idx + len(param) + len(value) + 50)
                excerpt = resp.body[start:end]
            return [Evidence(
                request=req,
                response=resp,
                kind=ObservationKind.ERROR_DISCLOSURE,
                endpoint=req.url,
                method=req.method,
                parameter=param,
                input_used=value,
                status_code=resp.status_code,
                relevant_headers=relevant,
                body_excerpt=excerpt,
                observation=f"token-like parameter '{param}' reflected in response body",
            )]

        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.COOKIE_FLAG,
            endpoint=req.url,
            method=req.method,
            parameter=candidate.get("cookie_name", ""),
            input_used=_redact(candidate.get("cookie_value", "")),
            status_code=resp.status_code,
            relevant_headers=relevant,
            body_excerpt=resp.body_excerpt,
            observation=f"{candidate.get('vector', '?')}/{subkind} for cookie '{candidate.get('cookie_name', '?')}'",
        )]

    # -- assess ----------------------------------------------------------

    async def assess(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> Finding | None:
        title = candidate.get("title", "Session Token Exposure")
        subkind = candidate.get("subkind", "")
        vector = candidate.get("vector", "?")

        # Severity by subkind. Vector-based, contextual.
        severity_map = {
            "xss_steals_session": Severity.CRITICAL,
            "csrf_via_xss": Severity.HIGH,
            "secure_missing_over_https": Severity.HIGH,
            "weak_token": Severity.HIGH,
            "token_in_response_body": Severity.HIGH,
            "httponly_missing_no_xss": Severity.LOW,
            "samesite_missing": Severity.LOW,
        }
        severity = severity_map.get(subkind, Severity.MEDIUM)

        # Build the signal list for ConfidenceScorer. Each subkind emits
        # 1-2 signals from different dimensions — the multi-signal
        # correlation then weights them according to the Oracle class.
        signals = self._signals_for_subkind(subkind, candidate)

        # Determine Oracle class
        oracle = self._oracle_for_subkind(subkind)

        # Score via ConfidenceScorer
        scorer = ConfidenceScorer()
        confidence = scorer.confidence(signals, oracle)

        if subkind in {"httponly_missing_no_xss", "samesite_missing"}:
            status = FindingStatus.LIKELY  # hardening gap, no chain observed
        elif subkind in {"xss_steals_session", "csrf_via_xss", "secure_missing_over_https",
                          "token_in_response_body"}:
            status = FindingStatus.CONFIRMED
        else:
            status = FindingStatus.LIKELY

        # Pull rich content from knowledge base
        issue_key = candidate.get("issue_key", subkind)
        entry = get_entry(self.meta.id, issue_key) or get_entry(self.meta.id, subkind)
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = title
            technical = (
                f"Session cookie '{candidate.get('cookie_name', '?')}' is exposed "
                f"via the {vector} attack vector. {subkind.replace('_', ' ')}."
            )
            impact = "Session hijack via the documented attack vector."
            remediation = [
                "Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                "Use a CSPRNG to generate session tokens (>=128 bits).",
            ]
            attack_scenario = None
            code_examples = {}

        # Add vector-prefix to summary for clarity
        summary = f"[{vector.upper()} VECTOR] {summary}"

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)

        return Finding(
            check=CheckRef(
                id=self.meta.id,
                name=self.meta.name,
                version=self.meta.version,
                category=self.meta.category.value,
            ),
            title=title,
            severity=severity,
            confidence=confidence,
            status=status,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=candidate.get("endpoint", "/"),
                method="GET",
                parameter=candidate.get("cookie_name") or candidate.get("parameter", ""),
            ),
            parameter=candidate.get("cookie_name") or candidate.get("parameter", ""),
            input_used=_redact(candidate.get("cookie_value", "")) or _redact(candidate.get("value", "")),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=self._cwes_for_subkind(subkind),
            owasp=self._owasp_for_subkind(subkind),
        )

    def _signals_for_subkind(
        self, subkind: str, candidate: dict
    ) -> list[Signal]:
        """Build the signal list for a given subkind.

        Each subkind emits 1-3 signals from different dimensions. The
        ConfidenceScorer aggregates them and applies the Oracle multiplier.
        """
        sigs: list[Signal] = []
        if subkind == "xss_steals_session":
            # XSS reflection + missing HttpOnly = direct attack chain
            sigs.append(Signal(
                kind=SignalKind.REFLECTION_DIFF,
                description="canary reflection unescaped in response",
                weight=1.0, dimension="response",
            ))
            sigs.append(Signal(
                kind="cookie_flag_missing",
                description=f"cookie '{candidate.get('cookie_name')}' missing HttpOnly",
                weight=0.8, dimension="response",
            ))
        elif subkind == "csrf_via_xss":
            sigs.append(Signal(
                kind=SignalKind.REFLECTION_DIFF,
                description="XSS reflection enables CSRF chain",
                weight=1.0, dimension="response",
            ))
            sigs.append(Signal(
                kind="cookie_flag_missing",
                description=f"cookie '{candidate.get('cookie_name')}' SameSite unset/None",
                weight=0.8, dimension="response",
            ))
        elif subkind == "secure_missing_over_https":
            sigs.append(Signal(
                kind=SignalKind.HEADER_DIFF,
                description="HTTPS response but Set-Cookie missing Secure flag",
                weight=1.0, dimension="response",
            ))
        elif subkind == "weak_token":
            entropy = candidate.get("entropy_bits", 0.0)
            token_len = candidate.get("token_length", 0)
            weight = 1.0 if entropy < _ENTROPY_CONFIRMED or token_len < 8 else 0.5
            sigs.append(Signal(
                kind=SignalKind.WEAK_TOKEN_ENTROPY,
                description=f"token entropy {entropy} bits/char, length {token_len}",
                weight=weight, dimension="behavior",
            ))
        elif subkind == "token_in_response_body":
            sigs.append(Signal(
                kind=SignalKind.TOKEN_IN_BODY,
                description="token-like parameter reflected in response",
                weight=1.0, dimension="response",
            ))
        elif subkind == "httponly_missing_no_xss":
            sigs.append(Signal(
                kind="cookie_flag_missing",
                description=f"cookie '{candidate.get('cookie_name')}' missing HttpOnly (no XSS chain observed)",
                weight=0.4, dimension="response",
            ))
        elif subkind == "samesite_missing":
            sigs.append(Signal(
                kind="cookie_flag_missing",
                description=f"cookie '{candidate.get('cookie_name')}' SameSite unset (no CSRF surface observed)",
                weight=0.4, dimension="response",
            ))
        return sigs

    def _oracle_for_subkind(self, subkind: str) -> Oracle:
        """Pick the Oracle class for a given subkind.

        XSS-steals-session and ownership violations are very strong
        evidence. Plain flag-missing is weak (could be hardening gap).
        """
        if subkind in {"xss_steals_session", "csrf_via_xss"}:
            return Oracle.STATE_TRANSITION  # both produce attack chain
        if subkind == "secure_missing_over_https":
            return Oracle.BODY_CONTENT
        if subkind in {"weak_token", "token_in_response_body"}:
            return Oracle.BODY_CONTENT
        # Hardening gaps — no chain observed
        return Oracle.STATUS_CODE_ONLY

    def _cwes_for_subkind(self, subkind: str) -> list[str]:
        return {
            "xss_steals_session": ["CWE-1004", "CWE-79"],
            "csrf_via_xss": ["CWE-1275", "CWE-352"],
            "secure_missing_over_https": ["CWE-614", "CWE-319"],
            "weak_token": ["CWE-330", "CWE-340"],
            "token_in_response_body": ["CWE-598"],
            "httponly_missing_no_xss": ["CWE-1004"],
            "samesite_missing": ["CWE-1275"],
        }.get(subkind, ["CWE-1004"])

    def _owasp_for_subkind(self, subkind: str) -> list[str]:
        if subkind.startswith("xss") or subkind.startswith("csrf"):
            return ["A05:2021", "A03:2021"]
        if "secure" in subkind or "mitm" in subkind:
            return ["A02:2021", "A05:2021"]
        if "weak" in subkind:
            return ["A07:2021"]
        return ["A05:2021"]
