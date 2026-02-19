#!/usr/bin/env python3
"""CLI entrypoint for the bug bounty agent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil

from bug_bounty_agent.agent import AgentInput, BugBountyAgent
from bug_bounty_agent.banner import render_banner

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[38;5;51m"
GREEN = "\033[38;5;46m"
YELLOW = "\033[38;5;220m"
RED = "\033[38;5;196m"
WHITE = "\033[38;5;255m"
GRAY = "\033[38;5;245m"


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


def _color(text: str, color: str, bold: bool = False) -> str:
    style = f"{BOLD}{color}" if bold else color
    return f"{style}{text}{RESET}"


def _terminal_width() -> int:
    return max(80, min(140, shutil.get_terminal_size((100, 20)).columns))


def _print_section(title: str) -> None:
    line = "-" * min(100, _terminal_width() - 2)
    print(_color(f"\n{title}", CYAN, bold=True))
    print(_color(line, GRAY))


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    if not rows:
        return
    string_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in string_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def render_row(items: list[str]) -> str:
        cells = [f" {items[i]:<{widths[i]}} " for i in range(len(items))]
        return "|" + "|".join(cells) + "|"

    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(_color(border, GRAY))
    print(_color(render_row(headers), WHITE, bold=True))
    print(_color(border, GRAY))
    for row in string_rows:
        print(render_row(row))
    print(_color(border, GRAY))


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

    _print_section("Workflow")
    _print_table(
        ["Step", "Action"],
        [
            ["1)", "Intake Program Information"],
            ["2)", "Review Scope and Recommend Target/Test Direction"],
            ["3)", "Analyze Artifacts and Generate Test Matrix"],
            ["4)", "Compile and Save Report"],
            ["Quit", "Exit after reviewing checklist and next actions"],
        ],
    )

    _print_section("1) Intake Program Information")
    overview_rows = [
        ["Status", result.status],
        ["Summary", result.summary],
        ["Report", result.report_path or "Not generated"],
    ]
    _print_table(["Field", "Value"], overview_rows)

    _print_section("2) Scope Recommendation")
    rec_rows = [
        ["Domain", result.recommendation.domain or "None"],
        ["Scope Status", result.recommendation.status],
        ["Reason", result.recommendation.reason],
    ]
    _print_table(["Field", "Value"], rec_rows)

    if result.recommendation.allowed_tests:
        _print_table(
            ["Allowed Next Tests", "Details"],
            [[str(idx), item] for idx, item in enumerate(result.recommendation.allowed_tests, start=1)],
        )
    if result.recommendation.blocked_tests:
        _print_table(
            ["Blocked / Not Allowed", "Details"],
            [[str(idx), item] for idx, item in enumerate(result.recommendation.blocked_tests, start=1)],
        )

    _print_section("2) Why This Recommendation")
    rationale_rows = [[str(idx), item] for idx, item in enumerate(result.recommendation_rationale, start=1)]
    if rationale_rows:
        _print_table(["#", "Evidence"], rationale_rows)

    _print_section("3) Analyze Information and Build Test Matrix")
    matrix_rows = [
        ["Total Tests", str(len(result.test_matrix))],
        ["Matrix File", result.test_matrix_path or "Not generated"],
    ]
    _print_table(["Field", "Value"], matrix_rows)
    if result.test_matrix:
        preview_rows = [
            [t.test_id, t.category, t.test_name, t.target, t.scope_basis]
            for t in result.test_matrix[:50]
        ]
        _print_table(["ID", "Category", "Test", "Target", "Scope"], preview_rows)
    else:
        _print_table(["ID", "Category", "Test", "Target", "Scope"], [["-", "-", "No tests generated", "-", "-"]])

    _print_section("3) Downloaded Artifacts")
    if result.downloaded_artifact_reasons:
        artifact_rows = [[str(idx), item] for idx, item in enumerate(result.downloaded_artifact_reasons, start=1)]
        _print_table(["#", "Downloaded File and Reason"], artifact_rows)
    else:
        _print_table(["#", "Downloaded File and Reason"], [["1", "None downloaded in this run"]])

    _print_section("3) Checklist")
    checklist_rows: list[list[str]] = []
    for item in result.completed:
        checklist_rows.append([_color("DONE", GREEN, bold=True), item])
    for item in result.pending:
        checklist_rows.append([_color("TODO", YELLOW, bold=True), item])
    _print_table(["Status", "Task"], checklist_rows)

    _print_section("3) Next Actions")
    action_rows = [[str(idx), item] for idx, item in enumerate(result.suggestions, start=1)]
    _print_table(["#", "Action"], action_rows)

    _print_section("4) Compile Report: Sources Used")
    source_rows = [[str(idx), item] for idx, item in enumerate(result.sources, start=1)]
    if source_rows:
        _print_table(["#", "Source"], source_rows)
    else:
        _print_table(["#", "Source"], [["1", "No sources found in this run"]])

    _print_section("4) Compile Report: Notes")
    note_rows = [[str(idx), item] for idx, item in enumerate(result.notes, start=1)]
    if note_rows:
        _print_table(["#", "Note"], note_rows)
    else:
        _print_table(["#", "Note"], [["1", "No notes"]])

    if result.report_path:
        print(_color(f"\n[Report Saved] {result.report_path}", CYAN, bold=True))
    print(_color("[Quit] Press Ctrl+C or close terminal when finished.", RED, bold=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
