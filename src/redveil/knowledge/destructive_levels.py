"""Per-vulnerability destructive level mapping.

Tells the operator (and the gate) what kind of destruction each
vulnerability class CAN enable, so they can set max_destructive_level
appropriately. The mapping is a CAP, not a guarantee — checks in
redveil use only the non-destructive variants by default.

Levels:
  1 = data_exfiltration
  2 = data_modification
  3 = data_destruction
  4 = persistence
  5 = lateral_movement
  6 = takeover

This is metadata for awareness + audit. The actual checks still ship
with curated, non-destructive payloads.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from redveil.validation.risk import DestructiveLevel


@dataclass(frozen=True)
class DestructiveProfile:
    """What a vulnerability class COULD enable if exploited at maximum."""
    vuln_id: str                         # check id (e.g. "sqli-time-based")
    vuln_name: str
    max_destructive_level: DestructiveLevel
    recommended_max_level: DestructiveLevel
    typical_actions: tuple[str, ...] = ()  # human-readable examples


# Per-vuln mapping. The "max" column tells the operator what the vuln
# class COULD do at maximum; redveil's checks by default only do
# non-destructive variants. The "recommended" column is what an
# authorized pentester might want to allow (typical: up to data_exfiltration
# or data_modification, rarely full takeover).
DESTRUCTIVE_PROFILES: dict[str, DestructiveProfile] = {
    "xss-reflected": DestructiveProfile(
        vuln_id="xss-reflected",
        vuln_name="Reflected XSS",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "Cookie theft → session hijack (level 6)",
            "Credential harvesting via fake login (level 6)",
            "Page defacement (level 3)",
            "Crypto miner injection (level 4 — persistence)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # we can do data_exfil via cookie theft
    ),
    "sqli-time-based": DestructiveProfile(
        vuln_id="sqli-time-based",
        vuln_name="Time-Based Blind SQL Injection",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "Dump entire database (level 1)",
            "UPDATE/INSERT rows (level 2)",
            "DROP TABLE (level 3)",
            "MySQL LOAD_FILE/INTO OUTFILE (level 1+3)",
            "xp_cmdshell → OS RCE (level 6)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # default: time-based only
    ),
    "command-injection": DestructiveProfile(
        vuln_id="command-injection",
        vuln_name="Command Injection",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "cat /etc/passwd (level 1)",
            "rm -rf / (level 3)",
            "crontab (level 4)",
            "useradd (level 4)",
            "ssh-keygen + write authorized_keys (level 5)",
            "Reverse shell (level 6)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # default: sleep only
    ),
    "ssrf": DestructiveProfile(
        vuln_id="ssrf",
        vuln_name="Server-Side Request Forgery",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "Read cloud metadata 169.254.169.254 (level 1+6)",
            "Read internal services (level 1)",
            "Internal port scan (level 1)",
            "AWS IAM credential theft (level 1+6)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # default: OOB only
    ),
    "path-traversal": DestructiveProfile(
        vuln_id="path-traversal",
        vuln_name="Path Traversal",
        max_destructive_level=DestructiveLevel.LATERAL_MOVEMENT,
        typical_actions=(
            "Read /etc/passwd, /etc/shadow (level 1)",
            "Read SSH keys ~/.ssh/id_rsa (level 5)",
            "Read cloud creds ~/.aws/credentials (level 1+6)",
            "Read app source/config (level 1)",
            "LFI → RCE (PHP include, Python exec) (level 6)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # default: canary filename only
    ),
    "bola-idor": DestructiveProfile(
        vuln_id="bola-idor",
        vuln_name="BOLA / IDOR",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "Read other users' data (level 1)",
            "Modify other users' data (level 2)",
            "Delete other users' data (level 3)",
            "Privilege escalation (change role) (level 2+6)",
            "Account takeover (change password/email) (level 6)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # default: GET only
    ),
    "bfla-behavior": DestructiveProfile(
        vuln_id="bfla-behavior",
        vuln_name="BFLA (Behavior Engine)",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "Read admin data (level 1)",
            "Create user (level 2)",
            "Delete user (level 3)",
            "Modify role/config (level 2)",
            "Mass operation (level 3)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,  # default: GET only
    ),
    "bfla": DestructiveProfile(
        vuln_id="bfla",
        vuln_name="BFLA",
        max_destructive_level=DestructiveLevel.TAKEOVER,
        typical_actions=(
            "Same as bfla-behavior: read (1), modify (2), delete (3), takeover (6)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,
    ),
    "session-invalidation": DestructiveProfile(
        vuln_id="session-invalidation",
        vuln_name="Session Invalidation",
        max_destructive_level=DestructiveLevel.DATA_EXFILTRATION,
        typical_actions=(
            "Read other users' session data (level 1)",
            "Confirm session is properly destroyed (level 1)",
        ),
        recommended_max_level=DestructiveLevel.DATA_EXFILTRATION,
    ),
}


def get_destructive_profile(vuln_id: str) -> DestructiveProfile | None:
    """Look up the destructive profile for a given check id."""
    return DESTRUCTIVE_PROFILES.get(vuln_id)
