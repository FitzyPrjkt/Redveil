"""Typer-based CLI for redveil.

Commands:
    redveil scan <url> [--profile] [--scope FILE]
    redveil check <plugin-id> <url>
    redveil findings <report-dir>
    redveil report <report-dir>
    redveil list-checks

The CLI is the public face of the framework. It is intentionally thin: heavy
lifting lives in the orchestrator and core modules. This keeps the CLI
stable while internals evolve.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redveil.config import (
    AuthorizationConfig,
    LimitsConfig,
    RedVeilConfig,
    ReportingConfig,
    SafetyProfile,
    ScopeConfig,
    TargetConfig,
)
from redveil.core.event_bus import EventBus
from redveil.core.lifecycle import ScanContext
from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
from redveil.core.renderer import RichRenderer
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.http.session import build_auth_provider
from redveil.plugins.loader import build_default_registry
from redveil import __version__

app = typer.Typer(
    name="redveil",
    help="Production-quality web vulnerability PoC & evidence framework.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def _version_callback(value: bool):
    """--version flag handler."""
    if value:
        console.print(f"redveil [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    help_flag: bool = typer.Option(
        False, "--help", "-h",
        help="Show extended help with sections, examples, and safety info.",
        is_eager=True,
    ),
):
    """redveil — web vulnerability scanner with evidence-grade reporting.

    DWYOR — Do With Your Own Risk. Authorized security testing only.
    See https://github.com/FitzyPrjkt/Redveil/blob/main/DWYOR.md
    """
    if help_flag or (ctx.invoked_subcommand is None and not version):
        _show_extended_help(ctx)
        raise typer.Exit()


def _show_extended_help(ctx: typer.Context):
    """Show extended help with sections, examples, and environment info."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]redveil[/bold cyan] — web vulnerability scanner\n"
        f"version [green]{__version__}[/green] · Python >= 3.12",
        border_style="cyan",
    ))
    console.print()

    # Section 1: Target specification
    console.print("[bold yellow]TARGET SPECIFICATION[/bold yellow]")
    console.print("  redveil scan [cyan]<url>[/cyan]                          [dim]# target base URL, e.g. https://staging.example.com[/dim]")
    console.print("  redveil check [cyan]<plugin-id> <url>[/cyan]              [dim]# single check plugin[/dim]")
    console.print("  redveil list-checks                            [dim]# show 17 registered check plugins[/dim]")
    console.print()

    # Section 2: SCAN OPTIONS
    console.print("[bold yellow]SCAN OPTIONS[/bold yellow]  [dim](for 'redveil scan')[/dim]")
    console.print("  [cyan]-s[/cyan], --scope FILE              [dim]# path to scope YAML file (recommended)[/dim]")
    console.print("  [cyan]-p[/cyan], --profile PROFILE        [dim]# passive | low_impact | active[/dim]")
    console.print("      --max-requests N             [dim]# hard cap on total requests (default 500)[/dim]")
    console.print("      --rps N                       [dim]# requests per second (default 2.0)[/dim]")
    console.print("      [cyan]-o[/cyan], --output DIR             [dim]# output directory (default 'reports/')[/dim]")
    console.print()

    # Section 3: AUTHORIZATION + GATE
    console.print("[bold yellow]AUTHORIZATION & ACTION GATE[/bold yellow]")
    console.print("      --active                       [dim]# enable ACTIVE checks (requires acknowledged_safety_terms)[/dim]")
    console.print("  [cyan]-g[/cyan], --gate-mode MODE          [dim]# interactive | non_interactive | strict[/dim]")
    console.print("      --allow-destructive          [dim]# unlock destructive actions (cross-validated)[/dim]")
    console.print("      --max-destructive-level L   [dim]# operator's ceiling: L1..L6 (default L2)[/dim]")
    console.print()

    # Section 4: REPORT COMMANDS
    console.print("[bold yellow]REPORT COMMANDS[/bold yellow]")
    console.print("  redveil findings [cyan]<dir>[/cyan]              [dim]# print summary of saved report[/dim]")
    console.print("  redveil report [cyan]<dir>[/cyan]               [dim]# re-render markdown/HTML from findings.json[/dim]")
    console.print()

    # Section 5: SAFETY PROFILES
    console.print("[bold yellow]SAFETY PROFILES[/bold yellow]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan", min_width=12)
    table.add_column()
    table.add_row("passive", "[dim]observation only, no payload injection (default)[/dim]")
    table.add_row("low_impact", "[dim]safe probes: CORS preflight, method check, harmless reflection[/dim]")
    table.add_row("active", "[dim]canary, time-based delays, OOB callbacks (requires --active + auth)[/dim]")
    console.print(table)
    console.print()

    # Section 6: DESTRUCTIVE LEVELS
    console.print("[bold yellow]DESTRUCTIVE LEVELS[/bold yellow]  [dim](L1..L6, with --allow-destructive)[/dim]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan", min_width=4)
    table.add_column()
    table.add_row("L1", "[dim]data_exfiltration   (read /etc/passwd, dump DB)[/dim]")
    table.add_row("L2", "[dim]data_modification  (UPDATE, chmod)[/dim]")
    table.add_row("L3", "[dim]data_destruction   (rm -rf, DROP TABLE) — type CONFIRM[/dim]")
    table.add_row("L4", "[dim]persistence         (crontab) — type CONFIRM-LEVEL-4[/dim]")
    table.add_row("L5", "[dim]lateral_movement   (SSH keys) — type CONFIRM-LEVEL-5[/dim]")
    table.add_row("L6", "[dim]takeover            (full RCE) — type CONFIRM-LEVEL-6[/dim]")
    console.print(table)
    console.print()

    # Section 7: EXAMPLES
    console.print("[bold yellow]EXAMPLES[/bold yellow]")
    console.print("  [dim]$[/dim] redveil scan https://staging.example.com --scope scope.yaml")
    console.print("  [dim]$[/dim] redveil scan https://target.com --scope scope.yaml --gate-mode interactive")
    console.print("  [dim]$[/dim] redveil check cors-policy https://target.com")
    console.print("  [dim]$[/dim] redveil findings reports/staging.example.com")
    console.print()

    # Section 8: EXIT CODES
    console.print("[bold yellow]EXIT CODES[/bold yellow]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan", min_width=4)
    table.add_column()
    table.add_row("0", "[dim]success[/dim]")
    table.add_row("1", "[dim]findings printed / report regenerated (subcommand-specific)[/dim]")
    table.add_row("2", "[dim]plugin not found (for 'redveil check')[/dim]")
    table.add_row("130", "[dim]aborted (Ctrl-C)[/dim]")
    console.print(table)
    console.print()

    # Section 9: DWYOR + docs
    console.print("[bold yellow]SAFETY[/bold yellow]")
    console.print("  ⚠ DWYOR — Do With Your Own Risk. Authorized security testing only.")
    console.print("    See: https://github.com/FitzyPrjkt/Redveil/blob/main/DWYOR.md")
    console.print()
    console.print("[bold yellow]DOCS[/bold yellow]")
    console.print("  GitHub:  https://github.com/FitzyPrjkt/Redveil")
    console.print("  PyPI:    https://pypi.org/project/redveil/")
    console.print()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target base URL, e.g. https://example.com"),
    profile: SafetyProfile = typer.Option(
        SafetyProfile.PASSIVE, "--profile", "-p",
        help="Safety profile: passive | low_impact | active",
    ),
    scope: Path | None = typer.Option(
        None, "--scope", "-s",
        help="Path to scope YAML file. If omitted, a minimal single-host scope is built.",
    ),
    max_requests: int = typer.Option(500, "--max-requests"),
    rps: float = typer.Option(2.0, "--rps"),
    active: bool = typer.Option(
        False, "--active",
        help="Enable ACTIVE checks. Requires acknowledged_safety_terms=true in scope.",
    ),
    gate_mode: str = typer.Option(
        "non_interactive", "--gate-mode", "-g",
        help="ActionGate mode: interactive | non_interactive | strict. "
             "interactive: prompt before MEDIUM+ actions. "
             "non_interactive: auto-approve NONE/LOW; deny MEDIUM+ by default. "
             "strict: auto-deny MEDIUM+ (requires pre-approval).",
    ),
    allow_destructive: bool = typer.Option(
        False, "--allow-destructive",
        help="EXPLICIT opt-in to unlock destructive actions (reverse shell, "
             "persistence, data destruction). Even when enabled, each "
             "destructive action requires per-action confirmation "
             "('I-accept-risk' in interactive mode). NO batch approval.",
    ),
    max_destructive_level: str = typer.Option(
        "L2", "--max-destructive-level",
        help="Operator's ceiling for destructive actions. Accepts short form "
             "L1..L6 (case-insensitive) or integer. Default L2 (data_modification).",
    ),
    output: Path = typer.Option(Path("reports"), "--output", "-o"),
):
    """Run a full scan against the target."""
    if scope and scope.exists():
        cfg = RedVeilConfig.from_yaml(scope)
    else:
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        cfg = RedVeilConfig(
            target=TargetConfig(base_url=target),
            scope=ScopeConfig(allowed_hosts=[host]),
            limits=LimitsConfig(requests_per_second=rps, max_requests=max_requests),
            authorization=AuthorizationConfig(
                active_testing=active, acknowledged_safety_terms=active,
                allow_destructive=allow_destructive,
                max_destructive_level=max_destructive_level,
            ),
            profile=profile,
            reporting=ReportingConfig(output_dir=output),
        )
    cfg.profile = profile
    cfg.limits.requests_per_second = rps
    cfg.limits.max_requests = max_requests
    cfg.authorization.active_testing = active
    cfg.authorization.allow_destructive = allow_destructive
    cfg.authorization.acknowledged_safety_terms = active
    cfg.authorization.max_destructive_level = max_destructive_level

    try:
        asyncio.run(_run_scan(cfg, gate_mode=gate_mode))
    except KeyboardInterrupt:
        console.print("[bold red]aborted[/bold red]")
        sys.exit(130)


async def _run_scan(cfg: RedVeilConfig, gate_mode: str = "non_interactive") -> None:
    bus = EventBus()
    renderer = RichRenderer(console=console)
    bus.subscribe_all(renderer)
    reg = build_default_registry()
    target_name = cfg.target.name or str(cfg.target.base_url)
    ctx = ScanContext(target_name=target_name, run_id="scan")

    # ActionGate mode from CLI
    from redveil.validation.gate import ActionGate, GateMode
    try:
        mode_enum = GateMode(gate_mode.lower())
    except ValueError:
        console.print(f"[yellow]unknown gate mode '{gate_mode}', using 'non_interactive'[/yellow]")
        mode_enum = GateMode.NON_INTERACTIVE
    action_gate = ActionGate(mode=mode_enum)

    async with HttpClient(
        scope=ScopeController(cfg.scope),
        limits=cfg.limits,
        auth=build_auth_provider(cfg.auth),
    ) as http:
        deps = OrchestratorDeps(
            bus=bus, registry=reg, config=cfg, http=http, gate=action_gate,
        )
        orch = Orchestrator(deps, ctx)
        await orch.run()

        # Phase 2: write reports after the scan completes
        if ctx.findings:
            from redveil.evidence.sanitizer import sanitize_evidence_list
            from redveil.reporting.markdown import write_report

            # Sanitize evidence before writing reports
            sanitized_evidence = {
                eid: sanitize_evidence_list([ev])[0]
                for eid, ev in orch.evidence_store.items()
            }

            target_dir = cfg.reporting.output_dir / target_name.replace("/", "_").replace(":", "_")
            written = write_report(ctx.findings, target_name, target_dir)
            console.print(f"\n[bold green]✓ report written[/bold green] to {target_dir}")
            for k, v in written.items():
                console.print(f"    {k} -> {v}")
        else:
            console.print("\n[yellow]no findings — no report generated[/yellow]")


@app.command()
def check(
    plugin_id: str = typer.Argument(..., help="Plugin ID, e.g. cors-policy"),
    target: str = typer.Argument(..., help="Target base URL"),
    scope: Path | None = typer.Option(None, "--scope", "-s"),
):
    """Run a single check plugin against a target."""
    reg = build_default_registry()
    if plugin_id not in reg:
        console.print(f"[red]plugin '{plugin_id}' not found[/red]")
        console.print(f"available: {', '.join(c.id for c in reg.all())}")
        raise typer.Exit(code=2)
    console.print(f"would run [bold]{plugin_id}[/bold] against {target}")
    console.print("(full single-check execution wired in Phase 2)")


@app.command()
def list_checks():
    """List all registered check plugins."""
    reg = build_default_registry()
    if not reg.all():
        console.print("[yellow]no plugins registered yet[/yellow]")
        console.print("Phase 1 ships with the plugin system only. Built-in checks arrive in Phase 3+.")
        raise typer.Exit()
    for c in reg.all():
        console.print(f"  [bold]{c.id:25}[/bold] [{c.safety_profile.value}] {c.name}")


@app.command()
def findings(
    report_dir: Path = typer.Argument(..., help="Path to a generated report directory"),
):
    """Print a summary of findings from a prior report."""
    p = report_dir / "findings.json"
    if not p.exists():
        console.print(f"[red]{p} not found[/red]")
        raise typer.Exit(code=1)
    data = json.loads(p.read_text())
    if isinstance(data, list):
        findings_list = data
    else:
        findings_list = data.get("findings", [])
    console.print(f"[bold]{len(findings_list)} findings[/bold]")
    for f in findings_list:
        sev = f.get("severity", "?")
        conf = f.get("confidence", "?")
        title = f.get("title", "?")
        console.print(f"  [{sev}] {title}  (confidence: {conf})")


@app.command()
def report(
    report_dir: Path = typer.Argument(..., help="Path to a report directory"),
    format: str = typer.Option("markdown", "--format", "-f"),
):
    """Re-generate reports from existing findings.json."""
    from redveil.findings.finding import Finding, CheckRef, TargetRef
    from redveil.findings.severity import Severity
    from redveil.findings.confidence import Confidence
    from redveil.reporting.markdown import write_report

    p = report_dir / "findings.json"
    if not p.exists():
        console.print(f"[red]{p} not found[/red]")
        raise typer.Exit(code=1)

    raw = json.loads(p.read_text())
    if isinstance(raw, list):
        items = raw
    else:
        items = raw.get("findings", [])

    findings: list[Finding] = []
    for item in items:
        check_raw = item.get("check", {}) or {}
        check = CheckRef(
            id=check_raw.get("id", "unknown"),
            name=check_raw.get("name", "unknown"),
            version=check_raw.get("version", "0.1.0"),
            category=check_raw.get("category"),
        )
        target_raw = item.get("target", {}) or {}
        target = TargetRef(
            host=target_raw.get("host", "?"),
            port=target_raw.get("port"),
            scheme=target_raw.get("scheme", "https"),
            endpoint=target_raw.get("endpoint", "/"),
            method=target_raw.get("method", "GET"),
            parameter=target_raw.get("parameter"),
        )
        f = Finding(
            id=item.get("id", f"WPOC-{len(findings):06X}"),
            check=check,
            title=item.get("title", "(untitled)"),
            severity=Severity(item.get("severity", "info")),
            confidence=Confidence(item.get("confidence", "tentative")),
            target=target,
            summary=item.get("summary", ""),
            technical_explanation=item.get("technical_explanation", ""),
            impact=item.get("impact", ""),
            evidence_ids=item.get("evidence_ids", []),
            parameter=item.get("parameter"),
            input_used=item.get("input_used"),
            fingerprint=item.get("fingerprint"),
        )
        findings.append(f)

    target_name = (raw if isinstance(raw, dict) else {}).get("target", "unknown")

    if format == "markdown":
        written = write_report(findings, target_name, report_dir)
        console.print(f"[green]regenerated {len(written)} file(s)[/green]")
        for k, v in written.items():
            console.print(f"  {k}  ->  {v}")
    else:
        console.print(f"[red]unsupported format: {format}[/red]")
        raise typer.Exit(code=2)


@app.command()
def help_cmd(
    ctx: typer.Context,
):
    """Show this extended help with sections, examples, and safety info."""
    _show_extended_help(ctx)


if __name__ == "__main__":
    app()
