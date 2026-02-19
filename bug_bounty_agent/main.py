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
    parser.add_argument(
        "--non-interactive-output",
        action="store_true",
        help="Print all sections at once instead of interactive menu mode.",
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


def _show_workflow_menu() -> None:
    _print_section("Workflow Menu")
    _print_table(
        ["Input", "Action"],
        [
            ["1", "Intake Program Information"],
            ["2", "Scope Recommendation"],
            ["3", "Analyze Information and Generate Test Matrix"],
            ["4", "Compile Report (sources + notes + paths)"],
            ["a", "Show all sections"],
            ["q", "Quit"],
        ],
    )


def _render_step_1(result) -> None:
    _print_section("1) Intake Program Information")
    _print_table(
        ["Field", "Value"],
        [
            ["Status", result.status],
            ["Summary", result.summary],
            ["Report", result.report_path or "Not generated"],
        ],
    )


def _render_step_2(result) -> None:
    _print_section("2) Scope Recommendation")
    _print_table(
        ["Field", "Value"],
        [
            ["Domain", result.recommendation.domain or "None"],
            ["Scope Status", result.recommendation.status],
            ["Reason", result.recommendation.reason],
        ],
    )
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
    _print_table(
        ["#", "Evidence"],
        [[str(idx), item] for idx, item in enumerate(result.recommendation_rationale, start=1)] or [["1", "No evidence available"]],
    )


def _render_step_3(result) -> None:
    _print_section("3) Analyze Information and Build Test Matrix")
    _print_table(
        ["Field", "Value"],
        [
            ["Total Tests", str(len(result.test_matrix))],
            ["Matrix File", result.test_matrix_path or "Not generated"],
        ],
    )
    if result.test_matrix:
        _print_table(
            ["ID", "Category", "Test", "Target", "Scope"],
            [[t.test_id, t.category, t.test_name, t.target, t.scope_basis] for t in result.test_matrix[:50]],
        )
    else:
        _print_table(["ID", "Category", "Test", "Target", "Scope"], [["-", "-", "No tests generated", "-", "-"]])

    _print_section("3) Downloaded Artifacts")
    if result.downloaded_artifact_reasons:
        _print_table(
            ["#", "Downloaded File and Reason"],
            [[str(idx), item] for idx, item in enumerate(result.downloaded_artifact_reasons, start=1)],
        )
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
    _print_table(["#", "Action"], [[str(idx), item] for idx, item in enumerate(result.suggestions, start=1)])


def _render_step_4(result) -> None:
    _print_section("4) Compile Report: Sources Used")
    source_rows = [[str(idx), item] for idx, item in enumerate(result.sources, start=1)]
    _print_table(["#", "Source"], source_rows or [["1", "No sources found in this run"]])

    _print_section("4) Compile Report: Notes")
    note_rows = [[str(idx), item] for idx, item in enumerate(result.notes, start=1)]
    _print_table(["#", "Note"], note_rows or [["1", "No notes"]])

    if result.report_path:
        print(_color(f"\n[Report Saved] {result.report_path}", CYAN, bold=True))


def _render_all_steps(result) -> None:
    _render_step_1(result)
    _render_step_2(result)
    _render_step_3(result)
    _render_step_4(result)


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

    if args.non_interactive_output:
        _render_all_steps(result)
        print(_color("[Quit] Non-interactive run complete.", RED, bold=True))
        return 0

    while True:
        _show_workflow_menu()
        choice = input(_color("Select a step (1/2/3/4/a/q): ", CYAN, bold=True)).strip().lower()
        if choice == "1":
            _render_step_1(result)
        elif choice == "2":
            _render_step_2(result)
        elif choice == "3":
            _render_step_3(result)
        elif choice == "4":
            _render_step_4(result)
        elif choice == "a":
            _render_all_steps(result)
        elif choice == "q":
            print(_color("[Quit] Session ended.", RED, bold=True))
            break
        else:
            print(_color("Invalid choice. Use 1, 2, 3, 4, a, or q.", RED, bold=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
