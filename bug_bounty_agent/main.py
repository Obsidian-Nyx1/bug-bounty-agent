#!/usr/bin/env python3
"""CLI entrypoint for the bug bounty agent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from bug_bounty_agent.agent import AgentInput, BugBountyAgent
from bug_bounty_agent.banner import render_banner


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="./bug_bounty",
        description="Authorized bug bounty agent with execute-or-guide behavior.",
    )
    parser.add_argument("--program-url", help="HackerOne program URL", default=None)
    parser.add_argument(
        "--program-hint",
        help="Program handle/title hint (useful when URL is generic like opportunities/all).",
        default=None,
    )
    parser.add_argument("--scope-file", help="Path to in-scope targets file", default=None)
    parser.add_argument("--policy-file", help="Path to program policy file", default=None)
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt for URL input when --program-url is missing.",
    )
    parser.add_argument(
        "--mode",
        choices=["safe", "balanced", "aggressive-safe"],
        default="balanced",
        help="Testing intensity while preserving policy guardrails.",
    )
    parser.add_argument(
        "--operator-id",
        default=os.getenv("BUG_BOUNTY_OPERATOR", os.getenv("USER", "default-operator")),
        help="Stable operator identity used for learning/respawn checkpoints.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print(render_banner())
    print("\n[Status] Starting ./bug_bounty\n")

    program_url = args.program_url
    if not program_url and not args.no_prompt:
        program_url = input("[Input] Paste project URL: ").strip()
    program_hint = args.program_hint
    if (
        program_url
        and "hackerone.com/opportunities" in program_url
        and not program_hint
        and not args.no_prompt
    ):
        program_hint = input(
            "[Input] Paste project handle/title from upper-left program header: "
        ).strip()

    agent = BugBountyAgent()
    result = agent.run(
        AgentInput(
            program_url=program_url or None,
            program_hint=program_hint or None,
            scope_file=Path(args.scope_file) if args.scope_file else None,
            policy_file=Path(args.policy_file) if args.policy_file else None,
            mode=args.mode,
            operator_id=args.operator_id,
        )
    )

    print(f"[Result] {result.status}")
    print(f"[Summary] {result.summary}")
    print("[Suggestions]")
    for idx, item in enumerate(result.suggestions, start=1):
        print(f"{idx}. {item}")
    print("[Step 2 Domain Recommendation]")
    print(f"Domain: {result.recommendation.domain or 'None'}")
    print(f"Scope status: {result.recommendation.status}")
    print(f"Reason: {result.recommendation.reason}")
    print("Allowed:")
    for idx, item in enumerate(result.recommendation.allowed_tests, start=1):
        print(f"{idx}. {item}")
    print("Blocked:")
    for idx, item in enumerate(result.recommendation.blocked_tests, start=1):
        print(f"{idx}. {item}")
    print("[Downloaded Artifacts]")
    if result.downloaded_artifact_reasons:
        for idx, item in enumerate(result.downloaded_artifact_reasons, start=1):
            print(f"{idx}. {item}")
    else:
        print("1. None downloaded in this run.")
    print("[Recommendation Rationale]")
    for idx, item in enumerate(result.recommendation_rationale, start=1):
        print(f"{idx}. {item}")
    print("[Checklist]")
    print("Completed:")
    for idx, item in enumerate(result.completed, start=1):
        print(f"{idx}. [x] {item}")
    print("Pending:")
    for idx, item in enumerate(result.pending, start=1):
        print(f"{idx}. [ ] {item}")
    print("[Sources]")
    for idx, item in enumerate(result.sources, start=1):
        print(f"{idx}. {item}")
    print("[Notes]")
    for idx, item in enumerate(result.notes, start=1):
        print(f"{idx}. {item}")
    if result.report_path:
        print(f"[Report] {result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
