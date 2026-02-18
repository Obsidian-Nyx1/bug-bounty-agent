"""Report generation for project intake."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bug_bounty_agent.discovery import DiscoveryData
from bug_bounty_agent.scope import DomainRecommendation, ScopeData


@dataclass
class ReportData:
    operator_id: str
    mode: str
    summary: str
    completed: list[str]
    pending: list[str]
    suggestions: list[str]
    notes: list[str]
    discovery: DiscoveryData
    recommendation: DomainRecommendation
    scope_data: ScopeData


def write_intake_report(data: ReportData) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_dir = Path(".bug_bounty_agent/reports") / data.operator_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{data.discovery.project_key}_{timestamp}.md"

    lines: list[str] = []
    lines.append(f"# Bug Bounty Intake Report: {data.discovery.project_key}")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Operator: {data.operator_id}")
    lines.append(f"- Mode: {data.mode}")
    lines.append(f"- Project URL: {data.discovery.project_url}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(data.summary)
    lines.append("")

    lines.append("## Step 2 Recommendation")
    lines.append(f"- Recommended domain: {data.recommendation.domain or 'None'}")
    lines.append(f"- Scope status: {data.recommendation.status}")
    lines.append(f"- Why: {data.recommendation.reason}")
    lines.append("")
    lines.append("### Allowed Tests (Next)")
    lines.extend(_as_bullets(data.recommendation.allowed_tests))
    lines.append("### Blocked / Not Allowed")
    lines.extend(_as_bullets(data.recommendation.blocked_tests))
    lines.append("")

    lines.append("## Parsed Scope Data")
    lines.append("### In-Scope Patterns")
    lines.extend(_as_bullets(data.scope_data.in_scope))
    lines.append("### Out-of-Scope Patterns")
    lines.extend(_as_bullets(data.scope_data.out_scope))
    lines.append("")

    lines.append("## Collected Information")
    lines.append("### Platform")
    lines.append(f"- {data.discovery.platform}")
    lines.append("### Program Handle")
    lines.append(f"- {data.discovery.program_handle or 'None detected'}")
    lines.append("### Program Tabs")
    lines.extend(_as_bullets(data.discovery.tab_links))
    lines.append("### Downloaded Artifacts")
    lines.extend(_as_bullets(data.discovery.downloaded_files))
    lines.append("### Download Reasons")
    lines.extend(_as_bullets(data.discovery.downloaded_artifact_reasons))
    lines.append("### Parsed In-Scope Domains")
    lines.extend(_as_bullets(data.discovery.in_scope_domains))
    lines.append("### Parsed Out-of-Scope Domains")
    lines.extend(_as_bullets(data.discovery.out_scope_domains))
    lines.append("### Allowed Signals")
    lines.extend(_as_bullets(data.discovery.allowed_scope_signals))
    lines.append("### Out-of-Scope Signals")
    lines.extend(_as_bullets(data.discovery.out_scope_signals))
    lines.append("### Policy Links")
    lines.extend(_as_bullets(data.discovery.candidate_policy_links))
    lines.append("### Scope Links")
    lines.extend(_as_bullets(data.discovery.candidate_scope_links))
    lines.append("### Documentation Links")
    lines.extend(_as_bullets(data.discovery.candidate_doc_links))
    lines.append("### Previous Bug/Write-up Links")
    lines.extend(_as_bullets(data.discovery.previous_bug_links))
    lines.append("### Social Discussion Links (Public)")
    lines.extend(_as_bullets(data.discovery.social_discussion_links))
    lines.append("### Domain Candidates")
    lines.extend(_as_bullets(data.discovery.domain_candidates))
    lines.append("")

    lines.append("## Checklist")
    for item in data.completed:
        lines.append(f"- [x] {item}")
    for item in data.pending:
        lines.append(f"- [ ] {item}")
    lines.append("")

    lines.append("## Recommended Next Actions")
    for idx, action in enumerate(data.suggestions, start=1):
        lines.append(f"{idx}. {action}")
    lines.append("")

    lines.append("## Notes")
    for note in data.notes:
        lines.append(f"- {note}")
    lines.append("")

    lines.append("## Source Index")
    lines.extend(_as_bullets(data.discovery.sources))
    lines.append("")

    out_file.write_text("\n".join(lines), encoding="utf-8")
    return out_file


def _as_bullets(items: list[str]) -> list[str]:
    if not items:
        return ["- None found in this run."]
    return [f"- {item}" for item in items]
