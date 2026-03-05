"""Core execution model for the bug bounty agent."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List
from urllib.parse import urlparse
import ipaddress
from datetime import datetime, timezone

from bug_bounty_agent.ai_client import generate_test_ideas_with_github_models, summarize_with_github_models
from bug_bounty_agent.analysis import TestCase, analyze_information
from bug_bounty_agent.automation import AutomatedFinding, run_automated_tests
from bug_bounty_agent.discovery import discover_project_context
from bug_bounty_agent.learning import LearningStore
from bug_bounty_agent.lpoint import record_lpoint_cycle
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
    run_automated: bool
    progress_callback: Callable[[int, str], None] | None = None


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
    test_matrix: List[TestCase]
    test_matrix_path: str | None
    automated_findings: List[AutomatedFinding]
    automated_md_report: str | None
    automated_pdf_report: str | None
    discovery_data: dict | None = None


class BugBountyAgent:
    """Execute when possible, otherwise provide a clear manual path."""

    def run(self, data: AgentInput) -> AgentResult:
        self._progress(data, 4, "Validating input")
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
                test_matrix=[],
                test_matrix_path=None,
                automated_findings=[],
                automated_md_report=None,
                automated_pdf_report=None,
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
                test_matrix=[],
                test_matrix_path=None,
                automated_findings=[],
                automated_md_report=None,
                automated_pdf_report=None,
            )

        self._progress(data, 8, "Starting discovery and scope collection")
        discovery = discover_project_context(
            data.program_url,
            data.program_hint,
            progress_hook=data.progress_callback,
        )
        self._progress(data, 96, "Building plan, checklist, and report")
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
        pipeline_version = str(discovery.recon_flow.get("pipeline_version", "unknown"))
        top_targets = len(discovery.recon_flow.get("prioritized_targets", []))
        notes.append(f"Recon pipeline active: {pipeline_version} (prioritized targets: {top_targets}).")
        idea_prompt = (
            f"Project: {discovery.project_key}\n"
            f"In-scope domains: {discovery.in_scope_domains}\n"
            f"Out-of-scope domains: {discovery.out_scope_domains}\n"
            f"Allowed signals: {discovery.allowed_scope_signals}\n"
            f"Out-of-scope signals: {discovery.out_scope_signals}\n"
            f"Downloaded files: {discovery.downloaded_files}\n"
        )
        idea_result = generate_test_ideas_with_github_models(idea_prompt, target_count=20)
        notes.extend(idea_result.notes)
        analysis = analyze_information(
            discovery=discovery,
            scope_data=scope_data,
            ai_ideas=idea_result.ideas,
            target_count=100,
            operator_id=data.operator_id,
        )
        notes.extend(analysis.notes)

        automated = None
        if data.run_automated:
            self._progress(data, 97, "Running automated checks")
            automated = run_automated_tests(
                discovery=discovery,
                scope_data=scope_data,
                operator_id=data.operator_id,
            )
            notes.extend(automated.notes)
        else:
            notes.append("Automated checks skipped (use --run-automated test).")

        learning_update = record_lpoint_cycle(
            operator_id=data.operator_id,
            project_key=discovery.project_key,
            program_url=data.program_url,
            mode=data.mode,
            recon_flow=discovery.recon_flow,
            tests_generated=len(analysis.tests),
            automated_findings=automated.findings if automated else [],
        )
        if learning_update.get("labeled_samples", 0) > 0:
            notes.append(
                "L-point model updated: "
                f"v{learning_update.get('model_version_before', 0)} -> "
                f"v{learning_update.get('model_version_after', 0)} "
                f"using {learning_update.get('labeled_samples', 0)} labeled samples."
            )
        else:
            notes.append("L-point model update skipped: no labeled outcomes captured this run.")
        notes.append(f"L-point DB: {learning_update.get('db_path')}")
        try:
            discovery.recon_flow.setdefault("stages", {})["learning_point"] = {
                "enabled": True,
                "mode": "online_learning",
                "db_path": learning_update.get("db_path"),
                "run_id": learning_update.get("run_id"),
                "labeled_samples": learning_update.get("labeled_samples", 0),
                "model_version_before": learning_update.get("model_version_before", 0),
                "model_version_after": learning_update.get("model_version_after", 0),
                "sample_count_after": learning_update.get("sample_count_after", 0),
            }
        except Exception:
            pass

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
                test_matrix=analysis.tests,
                test_matrix_path=analysis.matrix_path,
            )
        )
        notes.append(f"Intake report saved: {report_path}")
        self._progress(data, 100, "Intake complete")

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
            test_matrix=analysis.tests,
            test_matrix_path=analysis.matrix_path,
            automated_findings=automated.findings if automated else [],
            automated_md_report=automated.markdown_report if automated else None,
            automated_pdf_report=automated.pdf_report if automated else None,
            discovery_data={
                "project_url": discovery.project_url,
                "project_key": discovery.project_key,
                "platform": discovery.platform,
                "program_handle": discovery.program_handle,
                "domain_candidates": list(discovery.domain_candidates),
                "in_scope_domains": list(discovery.in_scope_domains),
                "out_scope_domains": list(discovery.out_scope_domains),
                "allowed_scope_signals": list(discovery.allowed_scope_signals),
                "out_scope_signals": list(discovery.out_scope_signals),
                "non_web_in_scope_assets": list(discovery.non_web_in_scope_assets),
                "non_web_out_scope_assets": list(discovery.non_web_out_scope_assets),
                "normalized_scope_assets": list(discovery.normalized_scope_assets),
                "recon_flow": dict(discovery.recon_flow),
                "sources": list(discovery.sources),
                "downloaded_files": list(discovery.downloaded_files),
            },
        )

    @staticmethod
    def _progress(data: AgentInput, pct: int, message: str) -> None:
        if not data.progress_callback:
            return
        try:
            data.progress_callback(max(0, min(100, pct)), message)
        except Exception:
            return

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
