"""Report generation for project intake."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bug_bounty_agent.analysis import TestCase
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
    test_matrix: list[TestCase]
    test_matrix_path: str | None


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

    lines.append("## Step 3 Analysis")
    lines.append(f"- Test matrix file: {data.test_matrix_path or 'Not generated'}")
    lines.append(f"- Total tests generated: {len(data.test_matrix)}")
    lines.append("")
    lines.append("### Test Matrix Preview")
    if data.test_matrix:
        lines.append("| ID | Category | Test | Target | Scope Basis |")
        lines.append("|---|---|---|---|---|")
        for test in data.test_matrix[:100]:
            lines.append(
                f"| {test.test_id} | {test.category} | {test.test_name} | "
                f"{test.target} | {test.scope_basis} |"
            )
    else:
        lines.append("- No tests generated in this run.")
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
    lines.append("### Parsed Non-Web In-Scope Assets")
    lines.extend(_as_bullets(data.discovery.non_web_in_scope_assets))
    lines.append("### Parsed Non-Web Out-of-Scope Assets")
    lines.extend(_as_bullets(data.discovery.non_web_out_scope_assets))
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
    lines.append("### Internet Intel Links (Passive)")
    lines.extend(_as_bullets(data.discovery.internet_intel_links))
    lines.append("### Internet Intel Items (Top 15)")
    intel_items = list(data.discovery.internet_intel_items or [])
    if intel_items:
        lines.append("| Source | Score | URL | Query |")
        lines.append("|---|---|---|---|")
        for item in intel_items[:15]:
            lines.append(
                f"| {item.get('source_type', 'web')} | {item.get('combined_score', 0)} | "
                f"{item.get('url', '')} | {item.get('query', '')} |"
            )
    else:
        lines.append("- None found in this run.")
    lines.append("### Domain Candidates")
    lines.extend(_as_bullets(data.discovery.domain_candidates))
    lines.append("")
    lines.append("## Bug Bounty Recon Pipeline")
    recon_flow = data.discovery.recon_flow or {}
    stages = recon_flow.get("stages", {})
    lines.append(f"- Pipeline version: {recon_flow.get('pipeline_version', 'unknown')}")
    scope_stage = stages.get("scope_policy_check", {})
    lines.append(f"- Scope/policy stage status: {scope_stage.get('status', 'unknown')}")
    lines.append("### Scope/Policy Checks")
    for check in scope_stage.get("checks", []):
        name = str(check.get("name", "unknown"))
        ok = bool(check.get("ok", False))
        lines.append(f"- {name}: {'pass' if ok else 'fail'}")
    lines.append("### Prioritized Targets (Top 10)")
    top_targets = stages.get("prioritize", {}).get("top_targets", [])
    if top_targets:
        lines.append("| Target | Priority | Confidence | Exposure | Evidence |")
        lines.append("|---|---|---|---|---|")
        for target in top_targets[:10]:
            scores = target.get("scores", {}) if isinstance(target, dict) else {}
            evidence = ", ".join((target.get("evidence") or [])[:3]) if isinstance(target, dict) else ""
            lines.append(
                f"| {target.get('target', 'unknown')} | {scores.get('priority', 0)} | "
                f"{scores.get('confidence', 0)} | {scores.get('exposure', 0)} | {evidence or 'n/a'} |"
            )
    else:
        lines.append("- None found in this run.")
    lines.append("### Safe Validation Guardrails")
    lines.extend(_as_bullets(stages.get("safe_validation", {}).get("guardrails", [])))
    lines.append("### L-Point Learning")
    model = recon_flow.get("model", {})
    learning_stage = stages.get("learning_point", {})
    lines.append(f"- Model source: {model.get('source', 'unknown')}")
    lines.append(f"- Model version: {model.get('version', 'n/a')}")
    lines.append(f"- Model samples: {model.get('sample_count', 0)}")
    lines.append(f"- Model DB: {model.get('db_path', learning_stage.get('db_path', 'n/a'))}")
    if learning_stage:
        lines.append(
            f"- Last update: v{learning_stage.get('model_version_before', 0)} -> "
            f"v{learning_stage.get('model_version_after', 0)} "
            f"(samples={learning_stage.get('labeled_samples', 0)})"
        )
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
