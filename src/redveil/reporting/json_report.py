from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from redveil.findings.finding import Finding


def render_findings_json(findings: list[Finding], target_name: str) -> str:
    return json.dumps({
        "tool": "redveil",
        "version": "0.1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": target_name,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2, default=str)


def write_findings_json(findings: list[Finding], target_name: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    p = output_dir / "findings.json"
    p.write_text(render_findings_json(findings, target_name))
    return p
