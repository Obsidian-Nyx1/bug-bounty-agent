#!/usr/bin/env python3
"""CLI entrypoint for the bug bounty agent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from bug_bounty_agent.agent import AgentInput, BugBountyAgent
from bug_bounty_agent.banner import render_banner
from bug_bounty_agent.bootstrap import ensure_runtime_dependencies

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[38;5;51m"
GREEN = "\033[38;5;46m"
YELLOW = "\033[38;5;220m"
RED = "\033[38;5;196m"
WHITE = "\033[38;5;255m"
GRAY = "\033[38;5;245m"
DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


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
        "--run-automated",
        nargs="?",
        const="test",
        default=None,
        help="Run automated in-scope checks. Example: --run-automated test",
    )
    parser.add_argument(
        "--non-interactive-output",
        action="store_true",
        help="Print all sections at once instead of interactive menu mode.",
    )
    parser.add_argument(
        "--xss_unified.py",
        dest="run_xss_unified",
        action="store_true",
        help="Run scope-aware xss_unified.py scans using Step 1 in-scope targets.",
    )
    parser.add_argument(
        "--no-auto-install-deps",
        action="store_true",
        help="Disable automatic runtime dependency installation.",
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
            ["1", "RECON (Mandatory): URL intake + scope/download discovery"],
            ["2", "TESTS: choose which automated test to run"],
            ["3", "REPORTING: save downloaded-doc manifest or custom report"],
            ["q", "Quit"],
        ],
    )


def _show_test_mode_menu() -> None:
    _print_section("TESTS Module")
    _print_table(
        ["Input", "Mode"],
        [
            ["l", "List available tests"],
            ["x", "Run scope-aware XSS test (xss_unified.py)"],
            ["b", "Back to main menu"],
        ],
    )


def _show_reporting_menu() -> None:
    _print_section("REPORTING Module")
    _print_table(
        ["Input", "Action"],
        [
            ["d", "Save downloaded-documents manifest"],
            ["c", "Create a custom report note"],
            ["v", "View current compiled report details"],
            ["b", "Back to main menu"],
        ],
    )


def _show_start_instructions() -> None:
    _print_section("Quick Instructions")
    _print_table(
        ["Step", "Command / Action"],
        [
            ["1", "Start guided workflow: ./bug_bounty"],
            ["2", "Paste HackerOne program URL when prompted"],
            ["3", "Use menu: 1 RECON, 2 TESTS, 3 REPORTING, q quit"],
            ["4", "Run automated checks: ./bug_bounty --run-automated test"],
            ["5", "Run scope-aware XSS step: ./bug_bounty --xss_unified.py"],
        ],
    )
    _print_table(
        ["Notes", "Details"],
        [
            ["Scope Safety", "Only test verified in-scope assets."],
            ["Reports", "Results are saved under .bug_bounty_agent/reports/<operator>/"],
            ["Operator", "Use --operator-id to keep your learning/checkpoint profile stable."],
        ],
    )


class _ProgressBar:
    def __init__(self) -> None:
        self.current = 0
        self._last_len = 0

    def update(self, pct: int, message: str) -> None:
        pct = max(self.current, max(0, min(100, pct)))
        self.current = pct
        width = 34
        filled = int((pct / 100) * width)
        bar = ("#" * filled) + ("-" * (width - filled))
        text = message[:64]
        line = (
            _color("[Loading]", CYAN, bold=True)
            + f" [{bar}] {pct:3d}% "
            + _color(text, WHITE)
        )
        pad = " " * max(0, self._last_len - len(line))
        sys.stdout.write("\r" + line + pad)
        self._last_len = len(line)
        sys.stdout.flush()

    def finish(self, message: str = "Ready") -> None:
        self.update(100, message)
        sys.stdout.write("\n")
        sys.stdout.flush()


def _xss_targets_from_scope(result) -> tuple[list[str], list[str]]:
    candidates = list(result.scope_data.in_scope)
    valid: list[str] = []
    skipped: list[str] = []
    for item in candidates:
        token = item.strip().lower()
        if token.startswith("*."):
            token = token[2:]
        if DOMAIN_RE.match(token):
            if token not in valid:
                valid.append(token)
        else:
            skipped.append(item)
    return valid, skipped


def _run_xss_unified_scope_step(result, operator_id: str) -> int:
    script_path = Path("xss_unified.py")
    if not script_path.exists():
        print(_color("[Error] xss_unified.py not found in project root.", RED, bold=True))
        return 1

    targets, skipped = _xss_targets_from_scope(result)
    _print_section("Scope-Aware XSS Targets")
    if targets:
        _print_table(["#", "In-Scope Target", "XSS Step"], [[str(i), t, "eligible"] for i, t in enumerate(targets, start=1)])
    else:
        _print_table(["#", "In-Scope Target", "XSS Step"], [["1", "None", "No domain-like in-scope target found"]])
    if skipped:
        _print_table(["#", "Skipped (Non-domain Scope Item)"], [[str(i), s] for i, s in enumerate(skipped[:20], start=1)])

    if not targets:
        print(_color("[Note] No domain targets to run xss_unified.py against.", YELLOW, bold=True))
        return 0

    out_dir = Path(".bug_bounty_agent/reports") / operator_id / "xss_unified"
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    failures = 0
    max_targets = len(targets)

    _print_section("Running Scope-Aware XSS Step")
    print(_color(f"[Status] Running xss_unified.py for {max_targets} in-scope target(s).", CYAN, bold=True))
    for idx, target in enumerate(targets[:max_targets], start=1):
        out_file = out_dir / f"{target.replace('.', '_')}_{timestamp}.json"
        cmd = [
            sys.executable,
            str(script_path),
            "--target",
            f"https://{target}",
            "--depth",
            "1",
            "--output",
            str(out_file),
        ]
        print(_color(f"[XSS {idx}/{max_targets}] {target}", WHITE, bold=True))
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0:
            failures += 1
            print(_color(f"  -> failed (exit {proc.returncode})", RED, bold=True))
        else:
            print(_color(f"  -> report: {out_file}", GREEN, bold=True))

    if failures:
        print(_color(f"[Status] XSS step completed with {failures} failure(s).", YELLOW, bold=True))
        return 1
    print(_color("[Status] XSS step completed successfully.", GREEN, bold=True))
    return 0


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


def _render_recon(result) -> None:
    _render_step_1(result)
    _render_step_2(result)
    _print_section("RECON: Downloaded Artifacts")
    if result.downloaded_artifact_reasons:
        _print_table(
            ["#", "Downloaded File and Reason"],
            [[str(idx), item] for idx, item in enumerate(result.downloaded_artifact_reasons, start=1)],
        )
    else:
        _print_table(["#", "Downloaded File and Reason"], [["1", "None downloaded in this run"]])
    _print_section("RECON: Checklist")
    checklist_rows: list[list[str]] = []
    for item in result.completed:
        checklist_rows.append([_color("DONE", GREEN, bold=True), item])
    for item in result.pending:
        checklist_rows.append([_color("TODO", YELLOW, bold=True), item])
    _print_table(["Status", "Task"], checklist_rows)


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

    _print_section("3) Scope Labels Guide")
    _print_table(
        ["Label", "Meaning"],
        [
            ["verified_in_scope_from_policy_or_artifact", "Explicitly in scope from program policy/scope artifacts."],
            ["verified_out_of_scope_from_policy_or_artifact", "Explicitly out of scope from program policy/scope artifacts."],
            ["discovered_target_requires_scope_validation", "Found during discovery but not explicitly verified in scope yet."],
        ],
    )

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
    _print_section("4) Automated Check Reports")
    _print_table(
        ["Artifact", "Path / Value"],
        [
            ["Automated Markdown", result.automated_md_report or "Not generated"],
            ["Automated PDF", result.automated_pdf_report or "Not generated"],
            ["Automated Findings", str(len(result.automated_findings))],
        ],
    )


def _render_documentation(result) -> None:
    _print_section("Documentation Review")
    source_rows = [[str(idx), item] for idx, item in enumerate(result.sources, start=1)]
    _print_table(["#", "Source"], source_rows or [["1", "No sources found in this run"]])
    _print_table(
        ["Artifact", "Path / Value"],
        [
            ["Intake Report", result.report_path or "Not generated"],
            ["Matrix CSV", result.test_matrix_path or "Not generated"],
            ["Automated Markdown", result.automated_md_report or "Not generated"],
            ["Automated PDF", result.automated_pdf_report or "Not generated"],
        ],
    )
    note_rows = [[str(idx), item] for idx, item in enumerate(result.notes, start=1)]
    _print_table(["#", "Notes"], note_rows[:20] or [["1", "No notes"]])


def _save_download_manifest(result, operator_id: str) -> str:
    out_dir = Path(".bug_bounty_agent/reports") / operator_id
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_file = out_dir / f"download_manifest_{timestamp}.md"
    lines = [
        "# Downloaded Documents Manifest",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Downloaded Artifacts",
    ]
    if result.downloaded_artifact_reasons:
        lines.extend([f"- {item}" for item in result.downloaded_artifact_reasons])
    else:
        lines.append("- None downloaded in this run.")
    lines.extend(["", "## Source Links"])
    if result.sources:
        lines.extend([f"- {item}" for item in result.sources])
    else:
        lines.append("- No sources recorded.")
    out_file.write_text("\n".join(lines), encoding="utf-8")
    return str(out_file)


def _save_custom_report(operator_id: str) -> str | None:
    title = input(_color("Custom report title: ", CYAN, bold=True)).strip() or "Custom Report"
    note = input(_color("Custom report note: ", CYAN, bold=True)).strip()
    if not note:
        return None
    out_dir = Path(".bug_bounty_agent/reports") / operator_id
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_file = out_dir / f"custom_report_{timestamp}.md"
    lines = [
        f"# {title}",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Note",
        note,
    ]
    out_file.write_text("\n".join(lines), encoding="utf-8")
    return str(out_file)


def _render_all_steps(result) -> None:
    _render_step_1(result)
    _render_step_2(result)
    _render_step_3(result)
    _render_step_4(result)


def main() -> int:
    args = parse_args()
    print(render_banner())
    print("\n[Status] Starting ./bug_bounty\n")
    _show_start_instructions()

    deps = ensure_runtime_dependencies(
        include_optional=bool(args.run_xss_unified),
        auto_install=not args.no_auto_install_deps,
    )
    if deps.notes:
        _print_section("Runtime Dependencies")
        _print_table(["Status", "Details"], [[("OK" if deps.ok else "WARN"), note] for note in deps.notes])
    if not deps.ok:
        print(_color("[Error] Missing required runtime dependencies. Re-run with network access or install manually.", RED, bold=True))
        return 1

    agent = BugBountyAgent()
    def run_recon(program_url: str | None, program_hint: str | None):
        progress = _ProgressBar()
        progress.update(2, "Preparing intake")
        result_local = agent.run(
            AgentInput(
                program_url=program_url or None,
                program_hint=program_hint or None,
                scope_file=Path(args.scope_file) if args.scope_file else None,
                policy_file=Path(args.policy_file) if args.policy_file else None,
                mode=args.mode,
                operator_id=args.operator_id,
                run_automated=(args.run_automated or "").strip().lower() == "test",
                progress_callback=progress.update,
            )
        )
        progress.finish("Intake finished")
        return result_local

    program_url = args.program_url
    program_hint = args.program_hint

    # Non-interactive / direct-command modes run intake immediately.
    if args.non_interactive_output or args.run_xss_unified:
        if not program_url and not args.no_prompt:
            program_url = input("[Input] Paste project URL: ").strip()
        if (
            program_url
            and "hackerone.com/opportunities" in program_url
            and not program_hint
            and not args.no_prompt
        ):
            program_hint = input(
                "[Input] Paste project handle/title from upper-left program header: "
            ).strip()
        result = run_recon(program_url, program_hint)
        if args.run_xss_unified:
            return _run_xss_unified_scope_step(result, args.operator_id)
        _render_all_steps(result)
        print(_color("[Quit] Non-interactive run complete.", RED, bold=True))
        return 0

    result = None
    intake_viewed = False
    tests_done = False

    while True:
        _show_workflow_menu()
        choice = input(_color("Select a step (1/2/3/q): ", CYAN, bold=True)).strip().lower()
        if choice == "1":
            if not program_url and not args.no_prompt:
                program_url = input("[Input] Paste project URL: ").strip()
            if not program_url:
                print(_color("RECON needs a program URL. Provide URL and select 1 again.", RED, bold=True))
                continue
            if (
                "hackerone.com/opportunities" in program_url
                and not program_hint
                and not args.no_prompt
            ):
                program_hint = input(
                    "[Input] Paste project handle/title from upper-left program header: "
                ).strip()
            result = run_recon(program_url, program_hint)
            _render_recon(result)
            intake_viewed = True
        elif choice == "2":
            if not intake_viewed:
                print(_color("RECON is mandatory. Complete step 1 first.", RED, bold=True))
                continue
            while True:
                _show_test_mode_menu()
                mode_choice = input(_color("Choose mode (l/x/b): ", CYAN, bold=True)).strip().lower()
                if mode_choice == "l":
                    _print_section("Available Tests")
                    _print_table(
                        ["ID", "Test", "Status"],
                        [
                            ["XSS-01", "scope-aware xss_unified.py", "available"],
                            ["NEXT", "future tests you add later", "placeholder"],
                        ],
                    )
                elif mode_choice == "x":
                    _render_step_2(result)
                    rc = _run_xss_unified_scope_step(result, args.operator_id)
                    if rc == 0:
                        tests_done = True
                elif mode_choice == "b":
                    break
                else:
                    print(_color("Invalid mode. Use l, x, or b.", RED, bold=True))
        elif choice == "3":
            if not intake_viewed:
                print(_color("Run RECON first.", YELLOW, bold=True))
                continue
            while True:
                _show_reporting_menu()
                r_choice = input(_color("Choose action (d/c/v/b): ", CYAN, bold=True)).strip().lower()
                if r_choice == "d":
                    out = _save_download_manifest(result, args.operator_id)
                    print(_color(f"[Saved] Download manifest: {out}", GREEN, bold=True))
                elif r_choice == "c":
                    out = _save_custom_report(args.operator_id)
                    if out:
                        print(_color(f"[Saved] Custom report: {out}", GREEN, bold=True))
                    else:
                        print(_color("[Note] Custom report was not saved (empty note).", YELLOW, bold=True))
                elif r_choice == "v":
                    if not tests_done:
                        print(_color("[Note] No test execution recorded yet. Showing current compiled details.", YELLOW, bold=True))
                    _render_step_4(result)
                    _render_documentation(result)
                elif r_choice == "b":
                    break
                else:
                    print(_color("Invalid action. Use d, c, v, or b.", RED, bold=True))
        elif choice == "q":
            print(_color("[Quit] Session ended.", RED, bold=True))
            break
        else:
            print(_color("Invalid choice. Use 1, 2, 3, or q.", RED, bold=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
