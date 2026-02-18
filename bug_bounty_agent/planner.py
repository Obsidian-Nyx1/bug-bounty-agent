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
    summary = (
        f"Project intake complete for {discovery.project_key}. "
        "Collected candidate scope/policy/docs, prior bug context, social signals, and domains."
    )
    if ai_summary:
        summary = f"{summary} AI model insight: {ai_summary}"

    next_actions = [
        "Confirm policy and scope URLs before any active testing.",
        "Create in-scope and out-of-scope lists from verified sources.",
        "Map high-value assets (auth, APIs, uploads, payment, admin).",
        "Launch recon pipeline only against approved assets.",
        "Track findings in reproducible checklist format.",
    ]

    if not discovery.candidate_policy_links:
        next_actions.insert(0, "Manually locate policy/guidelines page from the program portal.")
    if not discovery.candidate_scope_links:
        next_actions.insert(0, "Manually locate scope page/assets tab from the program portal.")

    return Plan(summary=summary, next_actions=next_actions[:8])
