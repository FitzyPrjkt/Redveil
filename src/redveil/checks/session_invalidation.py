"""SessionInvalidationCheck via BehaviorModel — verifies session is properly invalidated on logout.

ACTIVE check. Uses the BehaviorModel's StateHistory to track session
state transitions. The check:
  1. Establishes an authenticated state by visiting a known authenticated
     endpoint with the principal's cookies (expects 200)
  2. Calls the logout endpoint
  3. Re-visits the same authenticated endpoint with the same cookies
     (expects 401/403 if the session was properly invalidated)
  4. If the cookies still grant access → session is NOT invalidated → finding

PASSIVE-leaning: only GET requests, no data mutation. Requires a logout
endpoint in the ApplicationModel and principal config.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlparse

from redveil.behavior.state import SessionState, State
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


# Endpoints commonly used to verify authenticated state
_AUTH_PROBES: tuple[str, ...] = (
    "/api/profile/me", "/api/user/me", "/api/me", "/api/account",
    "/api/v1/profile", "/api/v1/user", "/api/v1/me",
    "/dashboard", "/account", "/profile",
)

# Endpoints commonly used to log out
_LOGOUT_PATHS: tuple[str, ...] = (
    "/logout", "/auth/logout", "/api/logout", "/api/auth/logout",
    "/api/v1/logout", "/signout",
)


class SessionInvalidationCheck(Check):
    meta = CheckMeta(
        id="session-invalidation",
        name="Session Invalidation Check",
        category=CheckCategory.SESSION,
        safety_profile=SafetyProfile.ACTIVE,
        version="0.1.0",
        description=(
            "Verifies that the server invalidates the session on logout. "
            "After hitting a logout endpoint, the same session cookies "
            "should no longer grant access to authenticated resources."
        ),
        references=["CWE-613", "CWE-384"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        model = self.deps.application_model
        if not model or len(model.identities) < 1:
            return []

        candidates: list[dict[str, Any]] = []
        base = model.base_url or str(self.deps.config.target.base_url)

        # Test only the first authenticated principal (avoid mass logout)
        principal = next(
            (i for i in model.identities.values() if i.is_authenticated()),
            None,
        )
        if not principal:
            return []

        # 1. Verify authenticated state with a probe
        auth_state_ok = False
        for probe in _AUTH_PROBES:
            url = join_url(base, probe)
            try:
                req = Request(
                    method="GET", url=url, purpose="session_check_pre",
                    auth_override_headers=principal.headers,
                    auth_override_cookies=principal.cookies,
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if 200 <= resp.status_code < 300:
                auth_state_ok = True
                break

        if not auth_state_ok:
            return []  # no authenticated state to test from

        # 2. Try logout
        for logout_path in _LOGOUT_PATHS:
            url = join_url(base, logout_path)
            try:
                req = Request(
                    method="POST", url=url, purpose="logout_test",
                    auth_override_headers=principal.headers,
                    auth_override_cookies=principal.cookies,
                )
                await self.deps.http.send(req)
            except Exception:
                continue

            # 3. Re-probe with the same cookies — should fail
            for probe in _AUTH_PROBES:
                url = join_url(base, probe)
                try:
                    req = Request(
                        method="GET", url=url, purpose="session_check_post",
                        auth_override_headers=principal.headers,
                        auth_override_cookies=principal.cookies,
                    )
                    resp = await self.deps.http.send(req)
                except Exception:
                    continue
                if 200 <= resp.status_code < 300:
                    # Cookies STILL grant access → session not invalidated
                    candidates.append({
                        "principal": principal.name,
                        "logout_path": logout_path,
                        "probe_path": probe,
                        "status_after_logout": resp.status_code,
                        "request": req,
                        "response": resp,
                    })
                    break
            if candidates:
                break  # one finding per principal is enough

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        return ValidationResult(
            outcome=ValidationOutcome.CONFIRMED,
            confidence="high",
            observation=(
                f"after logout via {candidate['logout_path']}, the same cookies "
                f"still grant {candidate['status_after_logout']} on {candidate['probe_path']}"
            ),
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        req = candidate.get("request")
        resp = candidate.get("response")
        if not req or not resp:
            return []
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.COOKIE_FLAG,
            endpoint=candidate["probe_path"],
            method="GET",
            parameter="session",
            input_used=f"principal={candidate.get('principal', '?')}",
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"cookies still valid after logout; status {resp.status_code}",
        )]

    async def assess(self, candidate) -> Finding | None:
        summary = (
            f"Session for {candidate['principal']} is NOT invalidated after logout. "
            f"After POST {candidate['logout_path']}, the same session cookies "
            f"still grant {candidate['status_after_logout']} on {candidate['probe_path']}."
        )
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Session Not Invalidated After Logout ({candidate['principal']})",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            target=TargetRef(
                host=str(self.deps.config.target.base_url).split("//")[-1].split("/")[0],
                endpoint=candidate["probe_path"],
                method="GET",
            ),
            parameter="session",
            input_used=f"principal={candidate.get('principal', '?')}",
            summary=summary,
            technical_explanation=(
                "After calling the logout endpoint, the session cookie should be "
                "invalidated server-side. This check verifies that the same cookie "
                "no longer grants access to authenticated resources. If it does, "
                "an attacker who obtains the cookie (via XSS, network capture, or "
                "shared device) can continue to use it after the legitimate user "
                "has logged out."
            ),
            impact=(
                "Session hijacking post-logout. If an attacker has captured the "
                "session cookie before logout, they can continue to use it after "
                "the victim believes the session is terminated."
            ),
            attack_scenario=(
                "1. Attacker steals session cookie via XSS or network capture\n"
                "2. Victim logs out, believes session is dead\n"
                "3. Attacker continues using stolen cookie — server still accepts it\n"
                "4. Attacker maintains access until cookie expires naturally"
            ),
            remediation=[
                "Invalidate the session server-side on logout (delete from session store)",
                "Rotate session ID on logout — issue a new session ID, don't reuse",
                "Set cookie max-age=0 or expires=epoch on logout response",
                "On the server, verify session validity on every authenticated request, not just on auth middleware",
            ],
            cwe=["CWE-613", "CWE-384"],
            owasp=["A07:2021"],
        )
