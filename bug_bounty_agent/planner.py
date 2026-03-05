"""Planning and checklist generation."""

from __future__ import annotations

from dataclasses import dataclass

from bug_bounty_agent.discovery import DiscoveryData


@dataclass
class Plan:
    summary: str
    next_actions: list[str]


def build_checklist(discovery: DiscoveryData) -> tuple[list[str], list[str]]:
    completed = [
        "Program URL captured",
        "Initial web context scan executed",
    ]
    pending: list[str] = []

    if discovery.candidate_policy_links:
        completed.append("Policy links discovered")
    else:
        pending.append("Policy links not discovered yet")

    if discovery.candidate_scope_links:
        completed.append("Scope links discovered")
    else:
        pending.append("Scope links not discovered yet")

    if discovery.candidate_doc_links:
        completed.append("Technical documentation links discovered")
    else:
        pending.append("Technical documentation links not discovered yet")

    if discovery.tab_links:
        completed.append("Program navigation tabs enumerated")
    else:
        pending.append("Program navigation tabs not discovered yet")

    if discovery.downloaded_files:
        completed.append("Downloadable program artifacts collected")
    else:
        pending.append("No downloadable artifacts found (CSV/Burp config)")

    if discovery.previous_bug_links:
        completed.append("Previous bug/write-up context discovered")
    else:
        pending.append("Previous bug/write-up context not discovered yet")

    if discovery.social_discussion_links:
        completed.append("Public social discussion links discovered")
    else:
        pending.append("Public social discussion links not discovered yet")

    if discovery.domain_candidates:
        completed.append("Candidate in-scope domains extracted")
    else:
        pending.append("Candidate in-scope domains not extracted yet")

    if discovery.in_scope_domains:
        completed.append("In-scope domains parsed from program artifacts")
    else:
        pending.append("In-scope domains could not be parsed from artifacts")

    if discovery.out_scope_domains:
        completed.append("Out-of-scope domains parsed from program artifacts")
    else:
        pending.append("Out-of-scope domains could not be parsed from artifacts")

    if discovery.allowed_scope_signals:
        completed.append("Allowed testing signals extracted from scope/policy")
    else:
        pending.append("Allowed testing signals not found in accessible content")

    if discovery.out_scope_signals:
        completed.append("Out-of-scope restrictions extracted from scope/policy")
    else:
        pending.append("Out-of-scope restrictions not found in accessible content")

    stages = discovery.recon_flow.get("stages", {})
    scope_stage = stages.get("scope_policy_check", {})
    if scope_stage.get("status") == "pass":
        completed.append("Recon Stage 1 complete: Scope & policy checks passed")
    else:
        pending.append("Recon Stage 1 partial: strengthen scope/policy evidence before active testing")
    if stages.get("prioritize", {}).get("top_targets"):
        completed.append("Recon Stage 4 complete: Prioritized target queue generated")
    else:
        pending.append("Recon Stage 4 incomplete: no ranked in-scope targets generated")
    if stages.get("safe_validation", {}).get("guardrails"):
        completed.append("Recon Stage 5 complete: Safe validation guardrails attached")
    else:
        pending.append("Recon Stage 5 incomplete: no safety guardrails captured")

    pending.extend(
        [
            "Validate all discovered links manually",
            "Build definitive in-scope asset list",
            "Start recon and testing against validated in-scope assets",
            "Collect evidence and draft report templates",
        ]
    )
    return completed, pending


def build_plan(discovery: DiscoveryData, ai_summary: str | None) -> Plan:
    stages = discovery.recon_flow.get("stages", {})
    top_targets = stages.get("prioritize", {}).get("top_targets", [])
    summary = (
        f"Project intake complete for {discovery.project_key}. "
        "Executed bug bounty recon pipeline: scope checks, collection, normalization, prioritization, and safe-validation prep."
    )
    if not (
        discovery.candidate_policy_links
        or discovery.candidate_scope_links
        or discovery.downloaded_files
        or discovery.in_scope_domains
    ):
        summary = (
            f"Project intake for {discovery.project_key} finished, but could not find usable "
            "scope/policy artifacts from accessible sources."
        )
    if ai_summary:
        summary = f"{summary} AI model insight: {ai_summary}"
    if top_targets:
        summary = f"{summary} Ranked targets ready: {len(top_targets)}."

    next_actions = [
        "Confirm policy and scope URLs before any active testing.",
        "Freeze approved in-scope and out-of-scope asset list from extracted artifacts.",
        "Start with top-ranked high-value targets (auth, APIs, uploads, payment, admin).",
        "Run non-destructive validation only, with strict rate limits.",
        "Track findings in reproducible checklist format.",
    ]

    if not discovery.candidate_policy_links:
        next_actions.insert(0, "Manually locate policy/guidelines page from the program portal.")
    if not discovery.candidate_scope_links:
        next_actions.insert(0, "Manually locate scope page/assets tab from the program portal.")

    return Plan(summary=summary, next_actions=next_actions[:8])
