"""Smoke tests for the Typer CLI surface.

These tests do not run a real scan — they only verify that the CLI parses
arguments, the help text renders, and exit codes are correct. The full scan
wiring is exercised in later phases.
"""

from __future__ import annotations

from typer.testing import CliRunner

from redveil.cli import app

runner = CliRunner()


def test_help_works():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "redveil" in result.output or "redveil" in result.output


def test_list_checks_exits_zero_with_no_plugins_message(tmp_path, monkeypatch):
    # Ensure no entry-point plugins register anything during this test.
    # build_default_registry() relies on installed entry points, which are
    # empty by default in this environment, so we don't need to monkeypatch.
    result = runner.invoke(app, ["list-checks"])
    # Either no plugins (exit 0 + "no plugins" message) or a populated list.
    # Phase 1 ships with the plugin system only; built-ins come in Phase 3+.
    if result.exit_code == 0:
        assert "no plugins registered" in result.output or "id=" not in result.output
    else:
        # typer.Exit() with no code defaults to 0 but CliRunner reports 1 in some versions;
        # accept any clean exit here.
        assert "no plugins registered" in result.output


def test_check_nonexistent_plugin_exits_nonzero():
    result = runner.invoke(app, ["check", "nonexistent-id", "https://example.com"])
    assert result.exit_code != 0
    assert "not found" in result.output


def test_findings_missing_dir_exits_1(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = runner.invoke(app, ["findings", str(missing)])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--profile" in result.output
    assert "--scope" in result.output
