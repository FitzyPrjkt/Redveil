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

app = typer.Typer(
    name="redveil",
    help="Production-quality web vulnerability PoC & evidence framework.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


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
    output: Path = typer.Option(Path("reports"), "--output", "-o"),
):
    """Run a full scan against the target."""
    if scope and scope.exists():
        cfg = RedVeilConfig.from_yaml(scope)
    else:
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        cfg = RedVeilConfig(
            target=TargetConfig(base_url=target),  # type: ignore[arg-type]
            scope=ScopeConfig(allowed_hosts=[host]),
            limits=LimitsConfig(requests_per_second=rps, max_requests=max_requests),
            authorization=AuthorizationConfig(
                active_testing=active, acknowledged_safety_terms=active
            ),
            profile=profile,
            reporting=ReportingConfig(output_dir=output),
        )
    cfg.profile = profile
    cfg.limits.requests_per_second = rps
    cfg.limits.max_requests = max_requests
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = active

    try:
        asyncio.run(_run_scan(cfg))
    except KeyboardInterrupt:
        console.print("[bold red]aborted[/bold red]")
        sys.exit(130)


async def _run_scan(cfg: RedVeilConfig) -> None:
    bus = EventBus()
    renderer = RichRenderer(console=console)
    bus.subscribe_all(renderer)
    reg = build_default_registry()
    target_name = cfg.target.name or str(cfg.target.base_url)
    ctx = ScanContext(target_name=target_name, run_id="scan")

    scope_ctrl = ScopeController(cfg.scope)
    auth = build_auth_provider(cfg.auth)
    async with HttpClient(scope=scope_ctrl, limits=cfg.limits, auth=auth) as http:
        deps = OrchestratorDeps(bus=bus, registry=reg, config=cfg, http=http)
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
            # Ensure HTML is in the format list by default; respect explicit config otherwise
            if not cfg.reporting.formats:
                cfg.reporting.formats = ["markdown", "json", "html"]
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
        console.print(f"  [bold]{c.id}[/bold]  [{c.safety_profile.value}]  {c.name}")


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
    from redveil.findings.confidence import Confidence
    from redveil.findings.finding import CheckRef, Finding, TargetRef
    from redveil.findings.severity import Severity
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
        # Re-hydrate nested models
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


@app.callback()
def main():
    """redveil: vulnerability PoC & evidence framework."""
    pass


if __name__ == "__main__":
    app()
