"""REPORTING module: compile report from persisted session artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from bug_bounty_agent.modules.schemas import SessionLayout, ensure_layout


def compile_session_report(layout: SessionLayout, session_state: dict) -> str:
    ensure_layout(layout)
    out_file = layout.reports_dir / f"final_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%SZ')}.md"

    recon_payload = _load_json(layout.recon_profile_file)
    tests_index = _load_json(layout.tests_index_file)
    steps = session_state.get("steps", [])
    tested = session_state.get("tested_targets", [])
    artifacts = session_state.get("artifacts", [])
    findings = session_state.get("findings", [])

    lines = [
        "# Session Report",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Session ID: {layout.session_id}",
        f"- Program URL: {recon_payload.get('program_url', session_state.get('program_url', 'N/A'))}",
        "",
        "## Workflow Status",
        f"- RECON profile: {'present' if recon_payload else 'missing'}",
        f"- TEST index: {'present' if tests_index else 'missing'}",
        f"- Executed targets: {len(tested)}",
        f"- Findings highlighted: {len(findings)}",
        "",
        "## Steps Completed",
    ]
    if steps:
        lines.extend([f"- {step}" for step in steps])
    else:
        lines.append("- No step history recorded.")

    lines.extend(["", "## Test Runs"])
    runs = tests_index.get("runs", []) if tests_index else []
    if runs:
        for run in runs:
            lines.append(f"- Tool: `{run.get('tool', 'unknown')}` | Timestamp: `{run.get('timestamp', 'n/a')}` | Entries: {len(run.get('entries', []))}")
    else:
        lines.append("- No persisted test runs found.")

    lines.extend(["", "## Evidence Artifacts"])
    recorded_artifacts = set(artifacts)
    for run in runs:
        for entry in run.get("entries", []):
            output = entry.get("output")
            if output:
                recorded_artifacts.add(output)
    if recorded_artifacts:
        for item in sorted(recorded_artifacts):
            lines.append(f"- {item}")
    else:
        lines.append("- No artifacts recorded.")

    lines.extend(["", "## Findings"])
    if findings:
        lines.append("| Severity | Tool | Category | Target | Evidence |")
        lines.append("|---|---|---|---|---|")
        for finding in findings[:300]:
            lines.append(
                f"| {str(finding.get('severity', 'info')).upper()} | {finding.get('tool', 'n/a')} | "
                f"{finding.get('category', 'n/a')} | {finding.get('target', 'n/a')} | "
                f"{str(finding.get('evidence', 'n/a'))[:120]} |"
            )
    else:
        lines.append("- No findings captured in current session state.")

    out_file.write_text("\n".join(lines), encoding="utf-8")
    return str(out_file)


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

