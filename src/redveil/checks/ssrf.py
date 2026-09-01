"""SSRFCheck — detects Server-Side Request Forgery via OOB callback probing.

ACTIVE check. This is the only check in redveil that performs true payload
injection against the target. It does so because SSRF detection inherently
requires the server to fetch a controlled URL — there is no signal that
distinguishes a benign URL parameter from a vulnerable one without making
the server reach the network.

SAFETY MODEL (CRITICAL — read before touching this file):

    * NO internal IP targeting. We do NOT probe 10.0.0.0/8, 172.16.0.0/12,
      192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 (including the AWS
      metadata IP 169.254.169.254), ::1, link-local, or any other private
      range. Probing internal targets could exfiltrate secrets from the
      operator's own infrastructure, which is the opposite of what an
      authorized security test should do.

    * We only use the OOB domain configured by the operator in
      ``cfg.authorization.out_of_band_callback_domain``. This is the user's
      own OAST endpoint (e.g. interactsh). We do NOT hardcode any external
      callback service.

    * The check REQUIRES ``active_testing=True`` AND
      ``out_of_band_callback_domain`` to be set. Without these, the check
      silently returns no candidates. There is no passive fallback — SSRF
      cannot be detected passively.

    * Each request uses a fresh per-canary random token so distinct
      callback hits in OOB logs can be matched back to the request that
      caused them.

    * We only OBSERVE. We do not exploit, do not chain with auth bypass,
      do not chain with IDOR or other bugs. The actual confirmation that
      a callback was received requires the operator to inspect their OOB
      logs. Manual log review is documented in the finding's reproduction
      steps.

ATTACK SURFACE TESTED:

    * URL parameters on GET endpoints (e.g. ``?url=...``, ``?next=...``).
    * URL parameters in HTML href attributes on the homepage.
    * POST form fields that take a URL (action/inputs).

For each, we inject a unique-canary URL pointing at the operator's OOB
domain and inspect the response. We mark a candidate when:

    * 30x with ``Location`` matching the injected OOB URL (``redirect``).
    * The injected OOB URL appears in the response body (``body_reference``).
    * The response appears to mirror the OOB URL's content (status 200 with
      body bytes resembling the canary token) (``successful_fetch``).
"""

from __future__ import annotations

import re
import secrets
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

# Parameter names that frequently carry URL values and are worth probing for
# SSRF. Conservative list — these are common sink names seen in real-world
# SSRF findings. Probe every name we recognise; do NOT fabricate names that
# aren't commonly used as URL sinks.
_URL_PARAM_NAMES: tuple[str, ...] = (
    "url", "uri", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "callback", "return", "next",
    "returnurl", "return_to", "goto", "continue", "out", "view", "dir",
    "show", "navigation", "target", "rurl", "link", "feed", "host",
    "site", "domain", "proxy", "img", "image", "fetch", "load", "path",
    "endpoint", "api", "api_url", "service", "url_src",
)

# Form actions worth probing for URL-sink POST behavior. Conservative; we
# only test paths explicitly hinted at by the homepage HTML.
_FORM_SELECTOR = re.compile(
    r'<form[^>]+action=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# Inputs of type=url or with a name in our URL-sink list.
_INPUT_SELECTOR = re.compile(
    r'<input[^>]+(?:name=["\']([^"\']+)["\']|type=["\']url["\'])',
    re.IGNORECASE,
)
_HREF_SELECTOR = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


# Hard-blocked host patterns. The check must NEVER embed these in payloads.
# This is the last line of defense — if a regression slips a literal IP
# into a probe URL, the safety test in tests/test_check_ssrf.py catches it.
_INTERNAL_HOST_PATTERNS: tuple[str, ...] = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "169.254.",
    "0.0.0.0",
    "::1",
    "localhost",
    "metadata.google.internal",
    "metadata.azure.com",
    "169.254.169.254",
    "fd00:", "fe80:",  # IPv6 ULA / link-local prefixes (prefix match)
)


def _generate_canary() -> str:
    """Return a fresh, high-entropy canary token for this probe.

    12 hex chars (6 bytes) — collision-resistant enough for OOB matching
    while staying short enough to fit inside most URL length budgets.
    """
    return secrets.token_hex(6)


def _build_oob_url(oob_domain: str, canary: str) -> str:
    """Build a unique OOB callback URL.

    Format: ``https://<canary>.<oob_domain>/``

    The canary lives in the subdomain so OOB services that log Host headers
    (most do) can record it. The trailing slash keeps the URL well-formed
    regardless of how the application parses it.
    """
    return f"https://{canary}.{oob_domain}/"


def _oob_url_in_response(resp, oob_url: str) -> bool:
    """Return True if the OOB URL appears in headers or body."""
    # Check headers first — Location and refresh are common SSRF leak sites.
    for k, v in resp.headers.items():
        if oob_url in v:
            return True
    return oob_url in (resp.body or "")


def _classify_indicator(resp, oob_url: str, canary: str) -> str | None:
    """Classify a candidate response.

    Returns one of: ``"redirect"``, ``"body_reference"``, ``"successful_fetch"``,
    or ``None`` if no SSRF indicator is present.

    Note: ``successful_fetch`` requires the response to contain the canary
    token somewhere — a generic 200 with no OOB evidence is treated as a
    non-indicator (the parameter may simply be ignored).
    """
    status = resp.status_code
    location = ""
    for k, v in resp.headers.items():
        if k.lower() == "location":
            location = v
            break

    # Indicator 1: redirect to the OOB URL.
    if 300 <= status < 400 and location and oob_url in location:
        return "redirect"

    # Indicator 2: OOB URL or canary in response body.
    body = resp.body or ""
    if oob_url in body or canary in body:
        return "body_reference"

    # Indicator 3: response appears to mirror OOB content. We require the
    # canary token to appear in either headers or body — without that,
    # a generic 200 is too ambiguous (the parameter may have been ignored
    # and the response is the page's default state).
    for k, v in resp.headers.items():
        if canary in v:
            return "successful_fetch"

    return None


class SSRFCheck(Check):
    """Detects Server-Side Request Forgery via OOB callback injection.

    ACTIVE safety profile. Requires ``active_testing=True`` and a configured
    ``out_of_band_callback_domain``. The check injects a unique-canary URL
    into URL parameters and form fields; if the server fetches that URL,
    the operator's OOB service will see a hit on the canary subdomain. The
    check itself only observes the response — it does NOT verify that the
    OOB service received the callback. Manual OOB log review is required.
    """

    meta = CheckMeta(
        id="ssrf",
        name="Server-Side Request Forgery Check",
        category=CheckCategory.SSRF,
        safety_profile=SafetyProfile.ACTIVE,
        description=(
            "Detects SSRF by injecting safe callback URLs (pointing to the "
            "user-controlled OOB endpoint configured in scope) into URL "
            "parameters and form fields. If the server fetches the URL, the "
            "OOB endpoint logs the connection — that is the evidence. Does "
            "NOT target internal networks or external services without "
            "explicit OOB configuration."
        ),
        references=["CWE-918", "OWASP A10:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []

        # --- SAFETY GATE 1: active_testing must be enabled.
        auth = getattr(self.deps.config, "authorization", None)
        active_testing = bool(getattr(auth, "active_testing", False))
        if not active_testing:
            return []

        # --- SAFETY GATE 2: an OOB callback domain must be configured.
        oob_domain = getattr(auth, "out_of_band_callback_domain", None)
        if not oob_domain:
            return []

        # --- SAFETY GATE 3: the OOB domain must not be a hardcoded internal
        # target. This is a defense-in-depth check; if someone misconfigures
        # the OOB domain to an internal hostname we refuse to probe.
        for bad in _INTERNAL_HOST_PATTERNS:
            if bad in oob_domain.lower():
                return []

        # Optional ActionGate: present the OOB probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. OOB SSRF probes
        # are LOW risk (no internal IP targets, no metadata endpoints) so
        # this is auto-approved.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="ssrf-oob-probe",
            description=(
                "Send SSRF OOB (out-of-band) callback probes via the "
                "operator-configured OOB domain. No internal IP targets, "
                "no metadata endpoints. ONLY uses the operator-configured "
                "out_of_band_callback_domain (no 10.0.0.0/8, "
                "192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, ::1, AWS "
                "metadata). No direct exploitation — just observes whether "
                "the server fetches the URL. Bounded outbound traffic."
            ),
            risk=Risk.LOW,
            target=f"{self.deps.config.target.base_url}/",
            purpose=(
                "Detect Server-Side Request Forgery by checking if the "
                "server fetches operator-configured callback URLs."
            ),
            expected_effect=(
                "200 OK responses to the probe; OOB callback hits recorded "
                "in operator's OOB log."
            ),
            potential_side_effects=(
                "Logged in server access log.",
                "Outbound HTTP/HTTPS requests to operator's OOB domain "
                "(DNS lookup + connection).",
                "May trigger WAF if present.",
            ),
            max_requests=len(_URL_PARAM_NAMES) * 2 + 5,
            timeout_seconds=10.0,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                # User denied or auto-denied (destructive in non-interactive).
                # In this case, deny is the right behavior.
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # 1. Pull homepage — extract GET params from href attributes and
        #    any forms for POST probing.
        try:
            home_url = join_url(base, "/")
            home_req = Request(method="GET", url=home_url, purpose="discovery")
            home_resp = await self.deps.http.send(home_req)
        except Exception:
            return candidates

        body = home_resp.body or ""

        # Collect GET candidates: href attributes with query strings, plus
        # synthetic probes on common path shapes.
        get_targets: list[tuple[str, str, str]] = []  # (endpoint, param, base_value)
        seen_targets: set[tuple[str, str]] = set()
        for m in _HREF_SELECTOR.finditer(body):
            href = m.group(1)
            if "?" not in href:
                continue
            try:
                path, qs = href.split("?", 1)
            except ValueError:
                continue
            for pair in qs.split("&"):
                if "=" not in pair:
                    continue
                name, _, value = pair.partition("=")
                if name.lower() in _URL_PARAM_NAMES:
                    key = (path, name.lower())
                    if key in seen_targets:
                        continue
                    seen_targets.add(key)
                    get_targets.append((path, name, value))

        # 2. Collect POST candidates: form action + URL-sink inputs.
        post_targets: list[tuple[str, str]] = []  # (form_action, input_name)
        seen_post: set[tuple[str, str]] = set()
        for action_m in _FORM_SELECTOR.finditer(body):
            action = action_m.group(1)
            # Re-extract inputs within the form's section. For simplicity
            # (and to avoid HTML parsing complexity) we scan all inputs
            # and accept those whose names are URL-sink candidates.
            for input_m in _INPUT_SELECTOR.finditer(body):
                iname = input_m.group(1)
                if iname and iname.lower() in _URL_PARAM_NAMES:
                    key = (action, iname.lower())
                    if key in seen_post:
                        continue
                    seen_post.add(key)
                    post_targets.append((action, iname))

        # 3. Probe every GET candidate with a fresh canary.
        for endpoint, param, _orig_value in get_targets:
            canary = _generate_canary()
            oob_url = _build_oob_url(oob_domain, canary)
            try:
                probe_url = join_url(base, endpoint)
                req = Request(
                    method="GET",
                    url=probe_url,
                    params={param: oob_url},
                    purpose="probe",
                    purpose_extra="ssrf_test",
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            indicator = _classify_indicator(resp, oob_url, canary)
            if indicator is None:
                continue
            candidates.append({
                "endpoint": endpoint,
                "parameter": param,
                "method": "GET",
                "canary": canary,
                "oob_url": oob_url,
                "oob_domain": oob_domain,
                "request": req,
                "response": resp,
                "indicator": indicator,
            })

        # 4. Probe every POST candidate with a fresh canary.
        for action, param in post_targets:
            canary = _generate_canary()
            oob_url = _build_oob_url(oob_domain, canary)
            try:
                probe_url = join_url(base, action)
                # Build a minimal form body — the canary is the only sink
                # we're exercising. urlencoded form format.
                body_str = f"{param}={oob_url}"
                req = Request(
                    method="POST",
                    url=probe_url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body_str,
                    purpose="probe",
                    purpose_extra="ssrf_test",
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            indicator = _classify_indicator(resp, oob_url, canary)
            if indicator is None:
                continue
            candidates.append({
                "endpoint": action,
                "parameter": param,
                "method": "POST",
                "canary": canary,
                "oob_url": oob_url,
                "oob_domain": oob_domain,
                "request": req,
                "response": resp,
                "indicator": indicator,
            })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        indicator = candidate.get("indicator")
        if indicator == "redirect":
            # 30x with Location matching the OOB URL is the strongest
            # signal we can collect without OOB log access. We can only
            # mark this LIKELY — a definite confirmation requires the
            # operator to see the canary subdomain in their OOB logs.
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=(
                    "server returned a redirect whose Location matches the "
                    "injected OOB URL; manual OOB log review required to "
                    "confirm the callback was received"
                ),
            )
        if indicator == "body_reference":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="low",
                observation=(
                    "response body references the injected OOB URL; could "
                    "be reflected input rather than a real fetch — manual "
                    "OOB log review required"
                ),
            )
        if indicator == "successful_fetch":
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="low",
                observation=(
                    "response content references the injected canary; "
                    "possible fetch — manual OOB log review required"
                ),
            )
        return ValidationResult(
            outcome=ValidationOutcome.FALSE_POSITIVE,
            observation="no SSRF indicator observed",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        indicator = candidate.get("indicator", "")
        relevant_headers: dict[str, str] = {}
        for k, v in resp.headers.items():
            if k.lower() in {"location", "refresh", "content-type"}:
                relevant_headers[k] = v
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.OOB_CALLBACK,
            endpoint=candidate.get("endpoint", "/"),
            method=candidate.get("method", "GET"),
            parameter=candidate.get("parameter"),
            input_used=candidate.get("oob_url"),
            status_code=resp.status_code,
            relevant_headers=relevant_headers,
            body_excerpt=(resp.body or "")[:200],
            observation=(
                f"server referenced OOB URL via indicator '{indicator}'; "
                f"check OOB logs for canary={candidate.get('canary')} on "
                f"domain {candidate.get('oob_domain')} to confirm"
            ),
        )]

    async def assess(self, candidate) -> Finding | None:
        # Pull rich content from the knowledge base.
        entry = get_entry(self.meta.id, "ssrf")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                "An endpoint reflects or fetches a user-controlled URL, "
                "indicating a potential Server-Side Request Forgery (SSRF) "
                "vulnerability."
            )
            technical = (
                "The server took a URL supplied by the client and either "
                "returned it directly (reflection), redirected to it, or "
                "fetched it server-side. Server-side fetches can be used "
                "to reach internal-only services, cloud metadata endpoints, "
                "or other network resources the attacker cannot reach "
                "directly."
            )
            impact = (
                "If exploitable, an attacker can use SSRF to pivot into "
                "internal network services, exfiltrate cloud metadata "
                "(IAM credentials), or chain with other vulnerabilities "
                "for full compromise."
            )
            remediation = [
                "Validate user-supplied URLs against an allowlist of "
                "permitted schemes and hosts.",
                "Resolve hostnames and reject private/loopback/link-local "
                "addresses before issuing the outbound request.",
                "Use a network-level egress proxy that blocks internal "
                "CIDR ranges.",
                "Disable HTTP redirects from the fetcher or pin each "
                "redirect to an allowlisted destination.",
            ]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)

        return Finding(
            check=CheckRef(
                id=self.meta.id,
                name=self.meta.name,
                category=self.meta.category.value,
                version=self.meta.version,
            ),
            title=f"Potential SSRF via '{candidate['parameter']}' Parameter",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.LIKELY,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=candidate["endpoint"],
                method=candidate.get("method", "GET"),
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("oob_url"),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-918"],
            owasp=["A10:2021"],
        )
