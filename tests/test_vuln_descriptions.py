"""Tests for the vulnerability knowledge base.

Validates that every entry has substantive content (not boilerplate), the
required fields are present, and the cross-references between checks and
issue kinds are intact.
"""
from __future__ import annotations

import pytest

from redveil.knowledge.vuln_descriptions import (
    VULN_DB,
    get_entry,
    validate_entry,
)

# ---------------------------------------------------------------------------
# Shape: every entry has the required fields with substantive content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_every_entry_has_required_fields(key):
    check_id, kind = key
    entry = VULN_DB[key]
    errors = validate_entry(entry)
    assert not errors, f"entry ({check_id!r}, {kind!r}) invalid: {errors}"


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_every_entry_summary_is_substantive(key):
    check_id, kind = key
    entry = VULN_DB[key]
    summary = entry.get("summary", "")
    # >= 30 words
    assert len(summary.split()) >= 30, (
        f"({check_id!r}, {kind!r}) summary too short: {len(summary.split())} words"
    )


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_every_entry_technical_is_substantive(key):
    check_id, kind = key
    entry = VULN_DB[key]
    tech = entry.get("technical", "")
    assert len(tech.split()) >= 50, (
        f"({check_id!r}, {kind!r}) technical too short: {len(tech.split())} words"
    )


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_every_entry_attack_scenario_has_steps(key):
    check_id, kind = key
    entry = VULN_DB[key]
    scenario = entry.get("attack_scenario", "")
    # Must have at least 4 numbered steps
    step_count = sum(1 for line in scenario.splitlines() if line.strip()[:2].rstrip(".)").isdigit())
    assert step_count >= 4, (
        f"({check_id!r}, {kind!r}) attack_scenario has {step_count} steps (need >=4)"
    )


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_every_entry_remediation_has_three_or_more(key):
    check_id, kind = key
    entry = VULN_DB[key]
    remediation = entry.get("remediation", [])
    assert len(remediation) >= 3, (
        f"({check_id!r}, {kind!r}) remediation has only {len(remediation)} items"
    )


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_every_entry_has_two_or_more_code_examples(key):
    check_id, kind = key
    entry = VULN_DB[key]
    examples = entry.get("code_examples", {})
    assert len(examples) >= 2, (
        f"({check_id!r}, {kind!r}) code_examples has only {len(examples)} entries"
    )


# ---------------------------------------------------------------------------
# Coverage: every check has at least one entry per common issue kind
# ---------------------------------------------------------------------------


REQUIRED_CHECKS = {
    "security-headers": [
        "content-security-policy-missing",
        "content-security-policy-wildcard",
        "x-frame-options-missing",
        "strict-transport-security-missing",
        "strict-transport-security-short-max-age",
        "x-content-type-options-missing",
        "referrer-policy-unsafe",
    ],
    "cors-policy": ["wildcard_origin", "reflected_origin", "wildcard_with_credentials"],
    "information-disclosure": [
        "version_banner",
        "stack_trace",
        "db_error",
        "html_comment",
        "exposed_env",
        "exposed_debug",
        "exposed_vcs",
        "backup_file",
    ],
    "http-methods": [
        "trace_enabled",
        "method_allowed_without_auth",
        "connect_enabled",
        "method_advertised_in_allow",
    ],
    "open-redirect-indicator": ["redirect_param"],
    "source-map-exposure": ["exposed_source_map", "inline_source_map_ref"],
}


@pytest.mark.parametrize("check_id", list(REQUIRED_CHECKS.keys()))
def test_check_has_required_kinds(check_id):
    """Each check covers its primary issue kinds."""
    kinds = REQUIRED_CHECKS[check_id]
    for kind in kinds:
        assert (check_id, kind) in VULN_DB, (
            f"missing knowledge-base entry: ({check_id!r}, {kind!r})"
        )


# ---------------------------------------------------------------------------
# get_entry() lookup behavior
# ---------------------------------------------------------------------------


def test_get_entry_returns_none_for_unknown():
    assert get_entry("nonexistent-check", "missing") is None
    assert get_entry("security-headers", "nonexistent-kind") is None


def test_get_entry_returns_entry_for_known():
    entry = get_entry("cors-policy", "wildcard_with_credentials")
    assert entry is not None
    assert "summary" in entry
    assert "code_examples" in entry


def test_get_entry_handles_empty_kind():
    assert get_entry("security-headers", "") is None
    assert get_entry("security-headers", None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Distinctness: ensure entries are not duplicated verbatim (each issue
# gets its own content, not a single shared boilerplate)
# ---------------------------------------------------------------------------


def test_entries_are_not_all_the_same_string():
    """A sanity check — if every summary looks identical, something is wrong."""
    summaries = {entry["summary"] for entry in VULN_DB.values()}
    # At least 30 unique summaries across the 44 entries
    assert len(summaries) >= 30, (
        f"only {len(summaries)} unique summaries across {len(VULN_DB)} entries"
    )


# ---------------------------------------------------------------------------
# Code examples are real code, not prose
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", list(VULN_DB.keys()))
def test_code_examples_look_like_code(key):
    """Each code example should be plausible as code, not a prose sentence."""
    check_id, kind = key
    entry = VULN_DB[key]
    for framework, snippet in entry["code_examples"].items():
        tokens = snippet.split()
        assert len(tokens) >= 2, (
            f"({check_id!r}, {kind!r}) {framework!r} snippet too short: {snippet!r}"
        )
        # Multi-line snippets (newlines) are clearly not single-line prose
        if "\n" not in snippet.strip():
            assert not snippet.strip().endswith("."), (
                f"({check_id!r}, {kind!r}) {framework!r} snippet ends with prose: {snippet!r}"
            )
        assert len(snippet) >= 8, (
            f"({check_id!r}, {kind!r}) {framework!r} snippet is too short: {snippet!r}"
        )
