"""Tests for per-vuln DestructiveLevel mapping (Wave 13 #4 + #5)."""
import pytest
from redveil.knowledge.destructive_levels import (
    DESTRUCTIVE_PROFILES, get_destructive_profile,
)
from redveil.validation.risk import DestructiveLevel


def test_xss_profile():
    p = get_destructive_profile("xss-reflected")
    assert p is not None
    # XSS CAN enable takeover (cookie theft → session hijack)
    assert p.max_destructive_level == DestructiveLevel.TAKEOVER
    # But default recommendation is just data exfiltration
    assert p.recommended_max_level == DestructiveLevel.DATA_EXFILTRATION
    # Includes cookie theft as a typical action
    assert any("cookie" in a.lower() for a in p.typical_actions)


def test_sqli_profile():
    p = get_destructive_profile("sqli-time-based")
    assert p is not None
    assert p.max_destructive_level == DestructiveLevel.TAKEOVER
    # SQLi → RCE via xp_cmdshell
    assert any("xp_cmdshell" in a.lower() or "rce" in a.lower() for a in p.typical_actions)
    # DROP TABLE = level 3
    assert any("drop" in a.lower() for a in p.typical_actions)


def test_command_injection_profile():
    p = get_destructive_profile("command-injection")
    assert p is not None
    assert p.max_destructive_level == DestructiveLevel.TAKEOVER
    # rm -rf = level 3
    assert any("rm -rf" in a.lower() for a in p.typical_actions)
    # Reverse shell = level 6
    assert any("reverse" in a.lower() for a in p.typical_actions)


def test_ssrf_profile():
    p = get_destructive_profile("ssrf")
    assert p is not None
    # SSRF → cloud metadata → IAM = level 1+6 chain
    assert any("metadata" in a.lower() or "iam" in a.lower() for a in p.typical_actions)


def test_path_traversal_profile():
    p = get_destructive_profile("path-traversal")
    assert p is not None
    # /etc/passwd read = level 1
    assert any("passwd" in a.lower() for a in p.typical_actions)
    # SSH keys = level 5
    assert any("ssh" in a.lower() for a in p.typical_actions)


def test_bola_profile():
    p = get_destructive_profile("bola-idor")
    assert p is not None
    # BOLA → account takeover = level 6
    assert any("takeover" in a.lower() or "password" in a.lower() for a in p.typical_actions)


def test_bfla_profile():
    p = get_destructive_profile("bfla-behavior")
    assert p is not None
    assert p.max_destructive_level == DestructiveLevel.TAKEOVER


def test_session_invalidation_profile():
    p = get_destructive_profile("session-invalidation")
    assert p is not None
    # Session-invalidation is the lowest-risk check — it just observes
    assert p.max_destructive_level <= DestructiveLevel.DATA_EXFILTRATION


def test_unknown_check_returns_none():
    p = get_destructive_profile("nonexistent-check")
    assert p is None


def test_all_active_checks_have_profile():
    """Every active check in the project should have a destructive profile."""
    active_checks = [
        "xss-reflected", "sqli-time-based", "command-injection",
        "ssrf", "path-traversal", "bola-idor", "bfla-behavior",
        "bfla", "session-invalidation",
    ]
    for check in active_checks:
        assert get_destructive_profile(check) is not None, (
            f"missing destructive profile for {check}"
        )


def test_recommended_levels_are_within_max():
    """The recommended level should never exceed the max level."""
    for profile in DESTRUCTIVE_PROFILES.values():
        assert profile.recommended_max_level.value <= profile.max_destructive_level.value, (
            f"{profile.vuln_id}: recommended {profile.recommended_max_level} > "
            f"max {profile.max_destructive_level}"
        )


def test_max_levels_are_realistic():
    """Reality check: max levels should map to actual real-world damage."""
    for profile in DESTRUCTIVE_PROFILES.values():
        # Real-world attacks CAN cause this level of damage (not higher)
        # So if any profile says max=1, something's wrong.
        if profile.vuln_id in ("command-injection", "ssrf", "bola-idor"):
            assert profile.max_destructive_level >= DestructiveLevel.TAKEOVER
