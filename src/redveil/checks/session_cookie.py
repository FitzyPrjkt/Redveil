"""SessionCookieCheck — detects session and cookie misconfigurations.

PASSIVE check. Inspects Set-Cookie headers from a single GET to the homepage
and a passive GET to the login page. No mutation, no actual authentication.

Detects:

1. Cookies without the ``HttpOnly`` flag — readable from JavaScript, enabling
   session theft via XSS.
2. Cookies without the ``Secure`` flag — sent over plaintext HTTP, exposing
   them to network attackers.
3. Cookies without ``SameSite`` — vulnerable to cross-site request forgery
   and session-riding attacks.
4. Weak session token entropy — short tokens or low Shannon entropy indicate
   predictable session identifiers that can be brute-forced or guessed.
5. Token leakage in URLs — API keys or session tokens placed in query
   parameters leak via ``Referer``, browser history, server logs, and
   third-party scripts.

Session fixation is NOT actively tested (would require a real login attempt).
The check only notes when a session cookie is issued on the login page
without changing — that is a strong indicator of fixation, but the operator
must perform the active test themselves.
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

# Endpoints probed to detect session cookies. We probe the homepage and a
# small set of common login URLs. The check only GETs these — no POSTs, no
# credentials, no actual login.
_LOGIN_PATHS = ("/login", "/auth/login", "/signin", "/auth", "/account/login")

# Query parameter names that look like session tokens / API keys. These are
# the most common names observed in real leaks.
_TOKEN_PARAM_NAMES = ("token", "session", "auth", "apikey", "api_key", "access_token", "sid")

# Entropy thresholds (bits per character).
# 3.5  — the "borderline" boundary from the spec. Below this, treat as weak.
# 3.0  — strongly weak; CONFIRMED weakness.
_ENTROPY_LIKELY = 3.5
_ENTROPY_CONFIRMED = 3.0

# Minimum acceptable session token length (chars).
_MIN_TOKEN_LEN = 16

# Heuristic: cookie names that look like session identifiers.
_SESSION_COOKIE_NAMES = (
    "session", "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "aspsessionid", "auth", "auth_token", "token",
    "user_token", "csrf_token", "remember_me", "remember_token", "connect.sid",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of ``s`` in bits per character.

    Returns 0.0 for empty strings. The result is the average number of bits
    needed to encode each character given the empirical distribution of
    characters in ``s``.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * log2(p)
    return entropy


def _looks_like_session_cookie(name: str) -> bool:
    """True if the cookie name suggests a session identifier."""
    lower = name.lower()
    return any(token in lower for token in _SESSION_COOKIE_NAMES)


def _split_set_cookie(combined: str) -> list[str]:
    """Split a comma-joined Set-Cookie header back into individual cookies.

    httpx's ``dict(Headers)`` collapses multiple ``Set-Cookie`` headers into a
    single string by joining with ``", "``. We re-split here using a regex
    that only matches commas followed by a valid cookie ``name=value`` pair,
    so ``Expires=Wdy, DD-Mon-YY ...`` is not mis-split.
    """
    if not combined:
        return []
    # `, ` followed by a name=value pair where name is a valid cookie-name char.
    parts = re.split(r", (?=[A-Za-z0-9_.\-]+=)", combined)
    return [p.strip() for p in parts if p.strip()]


def _parse_set_cookie(value: str) -> dict[str, str] | None:
    """Parse one ``Set-Cookie`` value into ``{name, value, ...attrs}``.

    Returns None if the value cannot be parsed (no ``name=value``).
    """
    if not value:
        return None
    segments = [s.strip() for s in value.split(";")]
    if not segments or "=" not in segments[0]:
        return None
    name, _, val = segments[0].partition("=")
    name = name.strip()
    val = val.strip()
    if not name:
        return None
    out: dict[str, str] = {"name": name, "value": val}
    for seg in segments[1:]:
        if "=" in seg:
            k, _, v = seg.partition("=")
            out[k.strip().lower()] = v.strip()
        else:
            # boolean attribute like "HttpOnly" or "Secure"
            out[seg.strip().lower()] = "true"
    return out


def _iter_set_cookies(headers: dict[str, str]) -> list[dict[str, str]]:
    """Yield parsed Set-Cookie entries from a response headers dict."""
    raw_value = None
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw_value = v
            break
    if raw_value is None:
        return []
    cookies: list[dict[str, str]] = []
    for piece in _split_set_cookie(raw_value):
        parsed = _parse_set_cookie(piece)
        if parsed is not None:
            cookies.append(parsed)
    return cookies


def _is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


def _redact(value: str, keep: int = 4) -> str:
    """Redact a secret-bearing value, keeping only the first ``keep`` chars."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "..." + ("[REDACTED]" if len(value) > keep + 8 else "")


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup. Returns the value or None."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------


class SessionCookieCheck(Check):
    """Detects cookie misconfiguration, weak session tokens, and token leakage."""

    meta = CheckMeta(
        id="session-cookie",
        name="Session and Cookie Configuration Check",
        category=CheckCategory.SESSION,
        safety_profile=SafetyProfile.PASSIVE,
        version="0.1.0",
        description=(
            "Detects cookie misconfiguration (missing HttpOnly / Secure / "
            "SameSite), weak session token entropy, token leakage in URLs, "
            "and indicators of session fixation. Strictly passive — never "
            "authenticates or mutates state."
        ),
        references=[
            "CWE-1004: Sensitive Cookie Without HttpOnly Flag",
            "CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute",
            "CWE-1275: Sensitive Cookie with SameSite Attribute None",
            "CWE-330: Use of Insufficiently Random Values",
            "CWE-598: Information Exposure Through Query Strings in GET Request",
            "OWASP A05:2021 - Security Misconfiguration",
            "OWASP A07:2021 - Identification and Authentication Failures",
        ],
    )

    def __init__(self) -> None:
        super().__init__()
        # Cache request/response pairs collected during discover() so that
        # collect_evidence() can reference them without re-issuing requests.
        self._captured: dict[str, tuple[Request, Response]] = {}

    # -- discover --------------------------------------------------------

    async def discover(self, ctx) -> list[dict[str, Any]]:  # type: ignore[override]
        """Inspect Set-Cookie headers from the homepage + login pages.

        Strictly passive: only GETs, no authentication.
        """
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []
        self._captured = {}

        # 1. Homepage — sets initial session cookies / tracking cookies.
        home_url = join_url(base, "/")
        try:
            home_req = Request(method="GET", url=home_url, purpose="discovery")
            home_resp = await self.deps.http.send(home_req)
        except Exception:
            home_resp = None  # type: ignore[assignment]
            home_req = None  # type: ignore[assignment]

        if home_resp is not None and home_req is not None:
            self._captured["home"] = (home_req, home_resp)
            candidates.extend(self._candidates_from_response("home", home_req, home_resp))

            # 2. Token leakage in URL — search the response body for token-like
            #    query parameters reflected anywhere. Only check if we have a body.
            candidates.extend(self._token_leakage_candidates(home_req, home_resp))

            # 3. Session fixation indicator — if a session cookie is present on
            #    the homepage, fetch a login page passively. If the same cookie
            #    comes back unchanged, that is a strong indicator of fixation.
            fixation = await self._check_fixation_indicator(base, home_resp)
            if fixation is not None:
                candidates.append(fixation)

        return candidates

    def _candidates_from_response(
        self,
        endpoint: str,
        req: Request,
        resp: Response,
    ) -> list[dict[str, Any]]:
        """Inspect Set-Cookie headers from a single response."""
        candidates: list[dict[str, Any]] = []
        cookies = _iter_set_cookies(resp.headers)
        for cookie in cookies:
            name = cookie["name"]
            value = cookie["value"]

            # Cookie flag checks: only emit HttpOnly/Secure/SameSite candidates
            # for cookies that LOOK like session/auth tokens. Plain tracking
            # cookies (analytics, preferences) are out of scope.
            if not _looks_like_session_cookie(name):
                continue

            # HttpOnly flag missing.
            if cookie.get("httponly") != "true":
                candidates.append({
                    "kind": "cookie_httponly_missing",
                    "cookie_name": name,
                    "cookie_value": value,
                    "request": req,
                    "response": resp,
                    "endpoint": endpoint,
                })

            # Secure flag missing — only relevant when the connection is HTTPS.
            if cookie.get("secure") != "true" and _is_https(req.url):
                candidates.append({
                    "kind": "cookie_secure_missing",
                    "cookie_name": name,
                    "cookie_value": value,
                    "request": req,
                    "response": resp,
                    "endpoint": endpoint,
                })

            # SameSite attribute missing. Note: SameSite=None alone is not a
            # weakness (modern browsers default to Lax for unset SameSite,
            # but explicitly setting "None" without Secure is a weakness —
            # we report both as candidates).
            samesite = cookie.get("samesite")
            if not samesite:
                candidates.append({
                    "kind": "cookie_samesite_missing",
                    "cookie_name": name,
                    "cookie_value": value,
                    "request": req,
                    "response": resp,
                    "endpoint": endpoint,
                })

            # Entropy / length analysis. Only meaningful for opaque tokens.
            # Skip empty or trivially short numeric values like "1".
            if value and not value.isdigit() and len(value) >= 4:
                entropy = shannon_entropy(value)
                if entropy < _ENTROPY_LIKELY or len(value) < _MIN_TOKEN_LEN:
                    candidates.append({
                        "kind": "weak_session_token",
                        "cookie_name": name,
                        "cookie_value": value,
                        "entropy_bits": round(entropy, 3),
                        "token_length": len(value),
                        "request": req,
                        "response": resp,
                        "endpoint": endpoint,
                    })

        return candidates

    def _token_leakage_candidates(
        self, req: Request, resp: Response
    ) -> list[dict[str, Any]]:
        """Look for token-like query parameters reflected in the response body."""
        candidates: list[dict[str, Any]] = []
        body = resp.body or ""
        if not body:
            return candidates

        # Pattern: ?token=abc123  or  &session=xyz  in raw HTML/JSON/text
        # (search the raw body, not just URLs in href).
        for name in _TOKEN_PARAM_NAMES:
            # Look for `name=` followed by a token-looking value. The value
            # must NOT be a JavaScript identifier / generic word like "true" or
            # "false" — require at least 8 hex/base64/url-safe chars.
            pattern = re.compile(
                rf"(?P<full>(?:^|[?&;\s])(?:{re.escape(name)})\s*=\s*"
                rf"(?P<value>[A-Za-z0-9_\-/.+=%]{{8,}}))",
                re.IGNORECASE,
            )
            for m in pattern.finditer(body):
                # Skip if the matched "value" looks like it's part of a code
                # snippet (e.g. property=value in JavaScript) — heuristic:
                # require a value that is mostly alphanumeric and long.
                value = m.group("value")
                if len(value) < 8:
                    continue
                candidates.append({
                    "kind": "token_in_url",
                    "context": "body",
                    "parameter": name,
                    "value": value,
                    "request": req,
                    "response": resp,
                    "endpoint": req.url,
                })
                break  # one candidate per parameter name per response

        return candidates

    async def _check_fixation_indicator(
        self, base: str, home_resp: Response
    ) -> dict[str, Any] | None:
        """PASSIVE session-fixation indicator.

        If the homepage issues a session cookie, fetch a login page. If the
        login page also sets a session cookie WITHOUT changing the existing
        one (i.e. the same token is honored), the application is *likely*
        vulnerable to session fixation. We do NOT actually log in — we only
        verify that the login page accepts the existing token.

        Returns a candidate dict, or None if no signal is observable.
        """
        home_cookies = _iter_set_cookies(home_resp.headers)
        session_cookie = next(
            (c for c in home_cookies if _looks_like_session_cookie(c["name"])),
            None,
        )
        if session_cookie is None:
            return None

        for path in _LOGIN_PATHS:
            try:
                login_url = join_url(base, path)
                login_req = Request(
                    method="GET",
                    url=login_url,
                    cookies={session_cookie["name"]: session_cookie["value"]},
                    purpose="passive_session_fixation_check",
                )
                login_resp = await self.deps.http.send(login_req)
            except Exception:
                continue

            self._captured[f"login:{path}"] = (login_req, login_resp)

            # If the login page sets a NEW cookie with the SAME name and a
            # different value, the application rotates — fixation unlikely.
            login_cookies = _iter_set_cookies(login_resp.headers)
            issued = next(
                (c for c in login_cookies if c["name"] == session_cookie["name"]),
                None,
            )
            if issued is not None and issued["value"] != session_cookie["value"]:
                # New value issued on login — looks fine.
                continue

            # Same cookie accepted, not rotated — fixation indicator.
            if 200 <= login_resp.status_code < 400:
                return {
                    "kind": "session_fixation_indicator",
                    "cookie_name": session_cookie["name"],
                    "endpoint": path,
                    "request": login_req,
                    "response": login_resp,
                }

        return None

    # -- validate --------------------------------------------------------

    async def validate(  # type: ignore[override]
        self, ctx, candidate: dict[str, Any]
    ) -> ValidationResult | None:
        """Validate based on candidate kind."""
        kind = candidate.get("kind")

        # Cookie flag issues are directly observable.
        if kind in {"cookie_httponly_missing", "cookie_secure_missing", "cookie_samesite_missing"}:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=(
                    f"cookie '{candidate['cookie_name']}' lacks the "
                    f"{kind.split('_', 1)[1].replace('_', ' ')} attribute"
                ),
            )

        # Weak tokens: CONFIRMED if very weak, LIKELY if borderline.
        if kind == "weak_session_token":
            entropy = candidate.get("entropy_bits", 0.0)
            token_len = candidate.get("token_length", 0)
            if entropy < _ENTROPY_CONFIRMED or token_len < 8:
                return ValidationResult(
                    outcome=ValidationOutcome.CONFIRMED,
                    confidence="high",
                    observation=(
                        f"session token entropy {entropy} bits/char and "
                        f"length {token_len} — easily guessable"
                    ),
                )
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=(
                    f"session token entropy {entropy} bits/char and "
                    f"length {token_len} — borderline; manual review recommended"
                ),
            )

        # Session fixation indicator: passive only, manual confirmation required.
        if kind == "session_fixation_indicator":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="low",
                observation=(
                    "session cookie accepted on login page without rotation; "
                    "active login test required for confirmation"
                ),
            )

        # Token leakage — directly observable in the response body.
        if kind == "token_in_url":
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=(
                    f"token-like parameter '{candidate['parameter']}' "
                    f"observed in response body"
                ),
            )

        return ValidationResult(
            outcome=ValidationOutcome.INCONCLUSIVE,
            confidence="low",
            observation="unknown candidate kind",
        )

    # -- evidence --------------------------------------------------------

    async def collect_evidence(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> list[Evidence]:
        """Attach the originating request/response and the cookie header."""
        req: Request | None = candidate.get("request")
        resp: Response | None = candidate.get("response")
        if req is None or resp is None:
            return []

        kind = candidate.get("kind", "")
        cookie_name = candidate.get("cookie_name", "")

        # Build the relevant-headers dict: only cookie-related + a couple of
        # context headers. We always redact the cookie value.
        relevant: dict[str, str] = {}
        for k, v in resp.headers.items():
            if k.lower() in {"set-cookie", "location", "referer"}:
                relevant[k] = v

        if kind == "token_in_url":
            # Body excerpt: 200-char window around the matched token-like parameter.
            param = candidate.get("parameter", "")
            value = candidate.get("value", "")
            idx = resp.body.find(f"{param}={value}")
            if idx < 0:
                excerpt = resp.body_excerpt
            else:
                start = max(0, idx - 100)
                end = min(len(resp.body), idx + len(param) + len(value) + 50)
                excerpt = resp.body[start:end]
            observation = (
                f"token-like parameter '{param}' reflected in response body"
            )
            parameter = param
            input_used = value
        else:
            excerpt = ""
            observation = f"{kind} for cookie '{cookie_name}'"
            parameter = cookie_name
            input_used = _redact(candidate.get("cookie_value", ""))

        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.COOKIE_FLAG,
            endpoint=candidate.get("endpoint", req.url),
            method=req.method,
            parameter=parameter,
            input_used=input_used,
            status_code=resp.status_code,
            relevant_headers=relevant,
            body_excerpt=excerpt,
            observation=observation,
        )]

    # -- assess ----------------------------------------------------------

    async def assess(  # type: ignore[override]
        self, candidate: dict[str, Any]
    ) -> Finding | None:
        """Build a Finding from a validated session-cookie candidate."""
        kind = candidate.get("kind", "")
        cookie_name = candidate.get("cookie_name", "") or "(unknown)"
        endpoint = candidate.get("endpoint", "/")

        # Title and severity by kind.
        if kind == "cookie_httponly_missing":
            title = f"Session Cookie '{cookie_name}' Missing HttpOnly Flag"
            severity = Severity.MEDIUM
            issue_key = "cookie_httponly_missing"
            cwe = ["CWE-1004"]
        elif kind == "cookie_secure_missing":
            title = f"Session Cookie '{cookie_name}' Missing Secure Flag"
            severity = Severity.MEDIUM
            issue_key = "cookie_secure_missing"
            cwe = ["CWE-614"]
        elif kind == "cookie_samesite_missing":
            title = f"Session Cookie '{cookie_name}' Missing SameSite Attribute"
            severity = Severity.MEDIUM
            issue_key = "cookie_samesite_missing"
            cwe = ["CWE-1275"]
        elif kind == "weak_session_token":
            entropy = candidate.get("entropy_bits", 0.0)
            token_len = candidate.get("token_length", 0)
            title = (
                f"Weak Session Token Entropy on Cookie '{cookie_name}' "
                f"({entropy} bits/char, {token_len} chars)"
            )
            severity = Severity.HIGH
            issue_key = "weak_session_token"
            cwe = ["CWE-330"]
        elif kind == "token_in_url":
            param = candidate.get("parameter", "")
            title = f"Sensitive Token '{param}' Present in Response Body / URL"
            severity = Severity.HIGH
            issue_key = "token_in_url"
            cwe = ["CWE-598"]
        elif kind == "session_fixation_indicator":
            title = (
                f"Possible Session Fixation on Cookie '{cookie_name}' "
                f"(login page accepts pre-existing session)"
            )
            severity = Severity.MEDIUM
            issue_key = "session_fixation_indicator"
            cwe = ["CWE-384"]
        else:
            return None

        # Pull rich content from the knowledge base.
        entry = get_entry(self.meta.id, issue_key)
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                f"{title}. See response headers for the cookie definition."
            )
            technical = (
                f"Cookie '{cookie_name}' is missing recommended security "
                "attributes."
            )
            impact = (
                "Missing flags or weak tokens increase the risk of session "
                "hijacking or fixation."
            )
            remediation = [
                "Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                "Use a CSPRNG to generate session tokens of at least 128 bits.",
            ]
            attack_scenario = None
            code_examples = {}

        # Confidence by kind.
        confidence_map = {
            "cookie_httponly_missing": Confidence.HIGH,
            "cookie_secure_missing": Confidence.HIGH,
            "cookie_samesite_missing": Confidence.HIGH,
            "weak_session_token": Confidence.HIGH
                if candidate.get("entropy_bits", 0.0) < _ENTROPY_CONFIRMED
                else Confidence.MEDIUM,
            "token_in_url": Confidence.HIGH,
            "session_fixation_indicator": Confidence.LOW,
        }
        confidence = confidence_map.get(kind, Confidence.MEDIUM)

        # Status: weak tokens above the CONFIRMED threshold are LIKELY;
        # everything else observed directly is CONFIRMED; the fixation
        # indicator is LIKELY until actively verified.
        if kind == "weak_session_token" and candidate.get("entropy_bits", 0.0) >= _ENTROPY_CONFIRMED:
            status = FindingStatus.LIKELY
        elif kind == "session_fixation_indicator":
            status = FindingStatus.LIKELY
        else:
            status = FindingStatus.CONFIRMED

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
                endpoint=endpoint,
                method="GET",
                parameter=cookie_name,
            ),
            parameter=cookie_name,
            input_used=_redact(candidate.get("cookie_value", "") or candidate.get("value", "")),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=cwe,
            owasp=["A05:2021"],
        )
