"""Core execution model for the bug bounty agent."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List
from urllib.parse import urlparse
import ipaddress
from datetime import datetime, timezone

from bug_bounty_agent.ai_client import summarize_with_github_models
from bug_bounty_agent.discovery import discover_project_context
from bug_bounty_agent.learning import LearningStore
from bug_bounty_agent.planner import build_checklist, build_plan
from bug_bounty_agent.report import ReportData, write_intake_report
from bug_bounty_agent.scope import (
    DomainRecommendation,
    ScopeData,
    merge_scope_sources,
    parse_scope_file,
    recommend_domain,
)


@dataclass
class AgentInput:
    program_url: str | None
    program_hint: str | None
    scope_file: Path | None
    policy_file: Path | None
    mode: str
    operator_id: str


@dataclass
class AgentResult:
    status: str
    summary: str
    suggestions: List[str]
    completed: List[str]
    pending: List[str]
    sources: List[str]
    notes: List[str]
    report_path: str | None
    recommendation: DomainRecommendation
    scope_data: ScopeData
    downloaded_artifact_reasons: List[str]
    recommendation_rationale: List[str]


class BugBountyAgent:
    """Execute when possible, otherwise provide a clear manual path."""

    def run(self, data: AgentInput) -> AgentResult:
        if not data.program_url:
            memory = LearningStore(Path(".bug_bounty_agent/learning_memory.jsonl"))
            last_url = memory.get_last_program_url(data.operator_id)
            suggestions = [
                "Paste the target program URL.",
                "Re-run: ./bug_bounty --program-url <url>",
            ]
            notes: list[str] = []
            if last_url:
                suggestions.append(f"Resume with last target: ./bug_bounty --program-url {last_url}")
                notes.append(f"Respawn point found for operator '{data.operator_id}'.")
            return AgentResult(
                status="manual_required",
                summary="Missing project URL.",
                suggestions=suggestions,
                completed=[],
                pending=[
                    "Program intake",
                    "Policy and scope extraction",
                    "Internet context collection",
                    "Action plan generation",
                ],
                sources=[],
                notes=notes,
                report_path=None,
                recommendation=DomainRecommendation(
                    domain=None,
                    status="unknown",
                    reason="No URL provided yet.",
                    allowed_tests=[],
                    blocked_tests=[],
                ),
                scope_data=ScopeData(in_scope=[], out_scope=[], raw_lines=[]),
                downloaded_artifact_reasons=[],
                recommendation_rationale=[],
            )

        url_error = self._validate_project_url(data.program_url)
        if url_error:
            return AgentResult(
                status="manual_required",
                summary=f"Security precheck failed: {url_error}",
                suggestions=[
                    "Use a valid public HTTPS program URL.",
                    "Avoid localhost/private-network targets for this intake step.",
                ],
                completed=["Project URL provided"],
                pending=[
                    "Program intake",
                    "Policy and scope extraction",
                    "Internet context collection",
                    "Action plan generation",
                ],
                sources=[],
                notes=["Blocked before AI/model execution for safety."],
                report_path=None,
                recommendation=DomainRecommendation(
                    domain=None,
                    status="blocked",
                    reason="Security precheck failed; no recommendation generated.",
                    allowed_tests=[],
                    blocked_tests=[],
                ),
                scope_data=ScopeData(in_scope=[], out_scope=[], raw_lines=[]),
                downloaded_artifact_reasons=[],
                recommendation_rationale=[],
            )

        discovery = discover_project_context(data.program_url, data.program_hint)
        memory = LearningStore(Path(".bug_bounty_agent/learning_memory.jsonl"))
        prior = memory.load_checkpoint(data.operator_id, discovery.project_key)
        prompt = discovery.as_prompt()
        if prior:
            prompt += (
                "\nPrevious checkpoint context:\n"
                f"- Prior summary: {prior.get('summary', '')}\n"
                f"- Prior pending: {prior.get('pending', [])}\n"
                f"- Prior suggestions: {prior.get('suggestions', [])}\n"
            )

        ai_result = summarize_with_github_models(prompt)
        completed, pending = build_checklist(discovery)
        plan = build_plan(discovery, ai_result.summary)
        file_scope = parse_scope_file(data.scope_file)
        scope_data = merge_scope_sources(
            file_scope=file_scope,
            discovered_in=discovery.in_scope_domains,
            discovered_out=discovery.out_scope_domains,
        )
        recommendation = recommend_domain(
            project_url=data.program_url,
            candidates=discovery.domain_candidates,
            scope=scope_data,
        )

        learned = memory.record_run(
            operator_id=data.operator_id,
            project_key=discovery.project_key,
            mode=data.mode,
            program_url=data.program_url,
            completed=completed,
            pending=pending,
        )
        checkpoint_path = memory.save_checkpoint(
            operator_id=data.operator_id,
            project_key=discovery.project_key,
            payload={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operator_id": data.operator_id,
                "project_key": discovery.project_key,
                "program_url": data.program_url,
                "mode": data.mode,
                "summary": plan.summary,
                "suggestions": plan.next_actions,
                "completed": completed,
                "pending": pending,
                "sources": discovery.sources,
            },
        )

        notes = [
            f"Operator profile: {data.operator_id}",
            f"Learning profile runs for this project: {learned}",
            f"Respawn checkpoint saved: {checkpoint_path}",
            "Scope and policy findings are best-effort; verify before active testing.",
        ]
        if data.program_hint:
            notes.append(f"Program hint used: {data.program_hint}")
        if "hackerone.com/opportunities" in data.program_url and not discovery.program_handle:
            notes.append(
                "Generic opportunities URL detected. Paste project handle/title via --program-hint "
                "to resolve exact program tabs and downloads."
            )
        if prior:
            notes.append("Previous checkpoint restored and used for planning.")
        notes.extend(ai_result.notes)
        if ai_result.runs:
            ok_count = sum(1 for run in ai_result.runs if run.ok)
            notes.append(f"Model responses: {ok_count}/{len(ai_result.runs)} successful.")
            sample_models = [run.model for run in ai_result.runs[:8]]
            notes.append(f"Models attempted: {', '.join(sample_models)}")
        if not discovery.downloaded_files and not discovery.in_scope_domains:
            notes.append(
                "Could not find downloadable scope artifacts or parsed scope domains for this run."
            )
        if not discovery.candidate_policy_links and not discovery.candidate_scope_links:
            notes.append("Could not find policy/scope links from accessible content in this run.")
        notes.append(
            "Step 2 recommendation generated from checklist/discovery + parsed scope patterns."
        )

        rationale = [
            f"In-scope domains parsed: {len(discovery.in_scope_domains)}",
            f"Out-of-scope domains parsed: {len(discovery.out_scope_domains)}",
            f"Allowed scope signals: {len(discovery.allowed_scope_signals)}",
            f"Out-of-scope restriction signals: {len(discovery.out_scope_signals)}",
            f"Policy/Scope references discovered: {len(discovery.candidate_policy_links) + len(discovery.candidate_scope_links)}",
        ]

        report_path = write_intake_report(
            ReportData(
                operator_id=data.operator_id,
                mode=data.mode,
                summary=plan.summary,
                completed=completed,
                pending=pending,
                suggestions=plan.next_actions,
                notes=notes,
                discovery=discovery,
                recommendation=recommendation,
                scope_data=scope_data,
            )
        )
        notes.append(f"Intake report saved: {report_path}")

        return AgentResult(
            status="intake_complete",
            summary=plan.summary,
            suggestions=plan.next_actions,
            completed=completed,
            pending=pending,
            sources=discovery.sources,
            notes=notes,
            report_path=str(report_path),
            recommendation=recommendation,
            scope_data=scope_data,
            downloaded_artifact_reasons=discovery.downloaded_artifact_reasons,
            recommendation_rationale=rationale,
        )

    @staticmethod
    def _validate_project_url(url: str) -> str | None:
        try:
            parsed = urlparse(url)
        except Exception:
            return "Malformed URL."
        if parsed.scheme != "https":
            return "URL must use HTTPS."
        if not parsed.netloc:
            return "URL missing hostname."

        host = parsed.hostname or ""
        if host in {"localhost", "127.0.0.1"}:
            return "Localhost targets are not allowed."
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "Private or loopback IP targets are not allowed."
        except ValueError:
            pass
        return None
