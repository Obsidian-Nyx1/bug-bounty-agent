#!/usr/bin/env python3
"""CLI entrypoint for the bug bounty agent."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
from datetime import datetime, timezone
from typing import Optional

from bug_bounty_agent.agent import AgentInput, BugBountyAgent
from bug_bounty_agent.banner import render_banner
from bug_bounty_agent.bootstrap import ensure_runtime_dependencies
from bug_bounty_agent.modules.schemas import SessionLayout, build_session_layout
from bug_bounty_agent.modules.recon import persist_recon_profile
from bug_bounty_agent.modules.tests import (
    collect_approved_targets,
    collect_xss_targets,
    ensure_afrog_installed,
    run_afrog_scope,
    run_xss_scope,
)
from bug_bounty_agent.modules.reporting import compile_session_report

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[38;5;51m"
GREEN = "\033[38;5;46m"
YELLOW = "\033[38;5;220m"
RED = "\033[38;5;196m"
WHITE = "\033[38;5;255m"
GRAY = "\033[38;5;117m"
BLUE = "\033[38;5;39m"
MAGENTA = "\033[38;5;201m"
ORANGE = "\033[38;5;208m"
DIM = "\033[2m"

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
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("recon", help="Run RECON: URL intake + scope discovery.")
    test_parser = subparsers.add_parser("test", help="Run TESTS module.")
    test_parser.add_argument(
        "--tool",
        choices=["xss", "afrog"],
        required=True,
        help="Testing tool to run.",
    )
    subparsers.add_parser("report", help="Run REPORTING module and compile session report.")
    subparsers.add_parser("run-all", help="Run RECON, TESTS (xss+afrog), then REPORTING.")
    return parser.parse_args()


def _color(text: str, color: str, bold: bool = False) -> str:
    style = f"{BOLD}{color}" if bold else color
    return f"{style}{text}{RESET}"


def _terminal_width() -> int:
    return max(80, min(140, shutil.get_terminal_size((100, 20)).columns))


def _print_section(title: str) -> None:
    line = "=" * min(100, _terminal_width() - 2)
    print(_color(f"\n{line}", BLUE))
    print(_color(f"[ {title} ]", MAGENTA, bold=True))
    print(_color(line, BLUE))


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
    for idx, row in enumerate(string_rows):
        row_text = render_row(row)
        if idx % 2 == 0:
            print(_color(row_text, WHITE))
        else:
            print(_color(row_text, GRAY))
    print(_color(border, GRAY))


def _show_workflow_menu() -> None:
    _print_section("Workflow Menu")
    print(_color("Choose your module to continue:", ORANGE, bold=True))
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
    print(_color("Select which testing operation to perform:", ORANGE, bold=True))
    _print_table(
        ["Input", "Mode"],
        [
            ["l", "List available tests"],
            ["s", "Show suggested tests table"],
            ["x", "Run scope-aware XSS test (xss_unified.py)"],
            ["a", "Run safe in-scope Afrog baseline scan"],
            ["b", "Back to main menu"],
        ],
    )


def _show_reporting_menu() -> None:
    _print_section("REPORTING Module")
    print(_color("Save or view report artifacts:", ORANGE, bold=True))
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
    print(_color("Console mode is active. Type commands at the prompt.", ORANGE, bold=True))
    _print_table(
        ["Command", "Action"],
        [
            ["show options", "Display RECON / TESTS / REPORTING options"],
            ["recon", "Run URL intake + scope/download discovery"],
            ["tests", "Open testing console (xss, afrog, list, suggested)"],
            ["report", "Open reporting console"],
            ["help", "Show this instruction block again"],
            ["quit", "Exit console"],
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
        self._tick = 0

    def update(self, pct: int, message: str) -> None:
        pct = max(self.current, max(0, min(100, pct)))
        self.current = pct
        width = 40
        filled = int((pct / 100) * width)
        head = ">" if filled < width else "="
        body = ("=" * max(0, filled - 1)) + (head if filled > 0 else "")
        trail = "." * (width - len(body))
        bar = body + trail
        spinner = ["|", "/", "-", "\\"][self._tick % 4]
        self._tick += 1
        text = message[:64]
        line = (
            _color(f"[{spinner}]", ORANGE, bold=True)
            + " "
            + _color("Loading", CYAN, bold=True)
            + f" <{bar}> {pct:3d}% "
            + _color(text, WHITE, bold=True)
        )
        pad = " " * max(0, self._last_len - len(line))
        sys.stdout.write("\r" + line + pad)
        self._last_len = len(line)
        sys.stdout.flush()

    def finish(self, message: str = "Ready") -> None:
        self.update(100, message)
        sys.stdout.write("\n")
        sys.stdout.flush()


def _run_afrog_safe_step(
    result,
    operator_id: str,
    session_layout: SessionLayout | None,
    session_state: Optional[dict] = None,
) -> int:
    _print_section("Afrog Instructions")
    _print_table(
        ["Step", "What Happens"],
        [
            ["1", "Checks if afrog is already installed."],
            ["2", "If missing, tries auto-install using Go."],
            ["3", "Builds approved in-scope target list from RECON."],
            ["4", "Runs baseline scan: afrog -t <target>."],
            ["5", "Saves logs under .bug_bounty_agent/reports/<operator>/afrog/."],
        ],
    )
    _print_table(
        ["Command", "Purpose"],
        [
            ["afrog -t https://target", "Run baseline scan for a single target"],
            ["afrog -h", "Show afrog help/options"],
        ],
    )
    proceed = input(_color("Proceed with Afrog baseline scan? (y/n): ", MAGENTA, bold=True)).strip().lower()
    if proceed not in {"y", "yes"}:
        print(_color("[Info] Afrog scan canceled by user.", YELLOW, bold=True))
        return 0

    afrog_bin = ensure_afrog_installed()
    if not afrog_bin:
        print(_color("[Error] afrog is not installed and auto-install failed.", RED, bold=True))
        print(_color("Install manually: go install github.com/zan8in/afrog/v3/cmd/afrog@latest", YELLOW, bold=True))
        return 1

    targets, skipped, sources = collect_approved_targets(result)
    _print_section("In-Scope Targets For Afrog")
    if targets:
        _print_table(["#", "Approved Target", "Scan Mode"], [[str(i), t, "afrog_baseline"] for i, t in enumerate(targets, start=1)])
    else:
        _print_table(["#", "Approved Target", "Scan Mode"], [["1", "None", "No in-scope URL/domain target found"]])
    if skipped:
        _print_table(["#", "Skipped (Non-domain/URL Scope Item)"], [[str(i), s] for i, s in enumerate(skipped[:20], start=1)])
    if sources:
        _print_table(["#", "Target Source"], [[str(i), s] for i, s in enumerate(sources[:30], start=1)])

    if not targets:
        print(_color("[Note] No approved targets available for afrog.", YELLOW, bold=True))
        return 0

    if session_layout is None:
        fallback_url = (session_state or {}).get("program_url") or "https://hackerone.com/unknown"
        session_layout = build_session_layout(operator_id, fallback_url)

    progress = _ProgressBar()
    _print_section("Running Afrog Baseline")

    def _on_target(idx: int, total: int, target: str) -> None:
        progress.update(int((idx - 1) / max(1, total) * 100), f"afrog scan {idx}/{total}: {target}")

    tool_run = run_afrog_scope(result, session_layout, afrog_bin, on_target=_on_target)
    progress.finish("Afrog scans complete")

    for item in tool_run.targets:
        if session_state is not None:
            session_state.setdefault("tested_targets", []).append({"tool": "afrog", "target": item})
    for artifact in tool_run.artifacts:
        out_file = Path(artifact)
        if session_state is not None:
            session_state.setdefault("artifacts", []).append(str(out_file))
            target_guess = out_file.stem.split("_")[0]
            session_state.setdefault("findings", []).extend(_extract_afrog_findings(out_file, target_guess))
    if tool_run.artifacts:
        print(_color(f"[Report] {tool_run.artifacts[0]}", GREEN, bold=True))
    if tool_run.index_file:
        print(_color(f"[Index] {tool_run.index_file}", CYAN, bold=True))

    if tool_run.failures:
        print(_color(f"[Status] Afrog finished with {tool_run.failures} failure(s).", YELLOW, bold=True))
        return 1
    print(_color("[Status] Afrog baseline scan completed successfully.", GREEN, bold=True))
    return 0


def _run_xss_unified_scope_step(
    result,
    operator_id: str,
    session_layout: SessionLayout | None,
    session_state: Optional[dict] = None,
) -> int:
    script_path = Path("xss_unified.py")
    if not script_path.exists():
        print(_color("[Error] xss_unified.py not found in project root.", RED, bold=True))
        return 1

    targets, skipped, sources = collect_xss_targets(result)
    _print_section("Scope-Aware XSS Targets")
    if targets:
        _print_table(["#", "In-Scope Target", "XSS Step"], [[str(i), t, "eligible"] for i, t in enumerate(targets, start=1)])
    else:
        _print_table(["#", "In-Scope Target", "XSS Step"], [["1", "None", "No in-scope URL/domain target found"]])
    if skipped:
        _print_table(["#", "Skipped (Non-domain Scope Item)"], [[str(i), s] for i, s in enumerate(skipped[:20], start=1)])
    if sources:
        _print_table(["#", "Target Source"], [[str(i), s] for i, s in enumerate(sources[:30], start=1)])

    if not targets:
        print(_color("[Note] No domain targets to run xss_unified.py against.", YELLOW, bold=True))
        return 0

    if session_layout is None:
        fallback_url = (session_state or {}).get("program_url") or "https://hackerone.com/unknown"
        session_layout = build_session_layout(operator_id, fallback_url)

    max_targets = len(targets)
    _print_section("Running Scope-Aware XSS Step")
    print(_color(f"[Status] Running xss_unified.py for {max_targets} in-scope target(s).", CYAN, bold=True))
    progress = _ProgressBar()

    def _on_target(idx: int, total: int, target: str) -> None:
        progress.update(int((idx - 1) / max(1, total) * 100), f"xss scan {idx}/{total}: {target}")

    tool_run = run_xss_scope(result, session_layout, script_path, on_target=_on_target)
    progress.finish("XSS scan complete")
    for target in tool_run.targets:
        if session_state is not None:
            session_state.setdefault("tested_targets", []).append({"tool": "xss_unified", "target": target})
    for artifact in tool_run.artifacts:
        out_file = Path(artifact)
        target_guess = out_file.stem.split("_")[0]
        if session_state is not None:
            session_state.setdefault("artifacts", []).append(str(out_file))
            session_state.setdefault("findings", []).extend(_extract_xss_findings(out_file, target_guess))
    if tool_run.artifacts:
        print(_color(f"[Report] {tool_run.artifacts[0]}", GREEN, bold=True))
    if tool_run.index_file:
        print(_color(f"[Index] {tool_run.index_file}", CYAN, bold=True))

    if tool_run.failures:
        print(_color(f"[Status] XSS step completed with {tool_run.failures} failure(s).", YELLOW, bold=True))
        return 1
    print(_color("[Status] XSS step completed successfully.", GREEN, bold=True))
    return 0


def _extract_xss_findings(report_file: Path, target: str) -> list[dict]:
    findings: list[dict] = []
    if not report_file.exists():
        return findings
    try:
        data = json.loads(report_file.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return findings

    mapping = {
        "reflected": "medium",
        "stored": "high",
        "dom": "high",
        "wordpress_admin_notices": "medium",
    }

    # New consolidated format: one file containing per-target results.
    if isinstance(data.get("targets"), list):
        for target_entry in data.get("targets", [])[:500]:
            target_name = str(target_entry.get("target") or target)
            findings_obj = target_entry.get("findings", {})
            if not isinstance(findings_obj, dict):
                continue
            for key, severity in mapping.items():
                values = findings_obj.get(key, [])
                if not values:
                    continue
                for item in values[:20]:
                    if isinstance(item, dict):
                        evidence = item.get("url") or item.get("found_at") or str(item)
                    else:
                        evidence = str(item)
                    findings.append(
                        {
                            "tool": "xss_unified",
                            "target": target_name,
                            "category": key,
                            "severity": severity,
                            "evidence": evidence,
                            "line_of_code": "N/A (black-box web test evidence)",
                            "artifact": str(report_file),
                        }
                    )
        return findings

    # Backward-compatible per-target report format.
    for key, severity in mapping.items():
        values = data.get(key, [])
        if not values:
            continue
        for item in values[:20]:
            if isinstance(item, dict):
                evidence = item.get("url") or item.get("found_at") or str(item)
            else:
                evidence = str(item)
            findings.append(
                {
                    "tool": "xss_unified",
                    "target": target,
                    "category": key,
                    "severity": severity,
                    "evidence": evidence,
                    "line_of_code": "N/A (black-box web test evidence)",
                    "artifact": str(report_file),
                }
            )
    return findings


def _extract_afrog_findings(report_file: Path, target: str) -> list[dict]:
    findings: list[dict] = []
    if not report_file.exists():
        return findings
    text = report_file.read_text(encoding="utf-8", errors="ignore")
    lowered = text.lower()
    if any(token in lowered for token in ("critical", " high ", "vulnerable", "[+]", "cve-")):
        sample = []
        for line in text.splitlines():
            low = line.lower()
            if any(token in low for token in ("critical", " high ", "vulnerable", "cve-")):
                sample.append(line.strip())
            if len(sample) >= 5:
                break
        findings.append(
            {
                "tool": "afrog",
                "target": target,
                "category": "baseline_scan_signal",
                "severity": "medium",
                "evidence": "; ".join(sample) if sample else "Potential vulnerability indicators in afrog output.",
                "line_of_code": "N/A (scanner output evidence)",
                "artifact": str(report_file),
            }
        )
    return findings


def _generate_automatic_report(
    result,
    operator_id: str,
    session_state: dict,
    session_layout: SessionLayout | None = None,
) -> str:
    if session_layout is not None:
        return compile_session_report(session_layout, session_state)

    out_dir = Path(".bug_bounty_agent/reports") / operator_id
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_file = out_dir / f"auto_session_report_{timestamp}.md"

    tested = session_state.get("tested_targets", [])
    artifacts = session_state.get("artifacts", [])
    steps = session_state.get("steps", [])
    findings = session_state.get("findings", [])

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings_sorted = sorted(findings, key=lambda x: severity_rank.get(str(x.get("severity", "info")).lower(), 1), reverse=True)

    lines = [
        "# Automatic Testing Session Report",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Program URL: {session_state.get('program_url') or 'N/A'}",
        f"- RECON completed: {'yes' if session_state.get('recon_done') else 'no'}",
        f"- Tests executed: {len(tested)}",
        f"- Findings highlighted: {len(findings_sorted)}",
        "",
        "## Steps Completed",
    ]
    if steps:
        lines.extend([f"- {s}" for s in steps])
    else:
        lines.append("- No recorded step history.")

    lines.extend(["", "## Tested Targets"])
    if tested:
        for item in tested:
            lines.append(f"- `{item.get('tool')}` -> `{item.get('target')}`")
    else:
        lines.append("- No tests executed yet.")

    lines.extend(["", "## Highlighted Findings"])
    if findings_sorted:
        lines.append("| Severity | Tool | Category | Target | Evidence | Line/Code |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings_sorted[:200]:
            sev = str(f.get("severity", "info")).upper()
            lines.append(
                f"| **{sev}** | {f.get('tool','n/a')} | {f.get('category','n/a')} | {f.get('target','n/a')} | "
                f"{str(f.get('evidence','n/a'))[:120]} | {f.get('line_of_code','N/A')} |"
            )
    else:
        lines.append("- No vulnerability signals recorded in this session.")

    lines.extend(["", "## Evidence Artifacts"])
    if artifacts:
        for a in artifacts:
            lines.append(f"- {a}")
    else:
        lines.append("- No artifacts recorded.")

    lines.extend(["", "## RECON Context"])
    lines.append(f"- Intake report: {result.report_path or 'N/A'}")
    lines.append(f"- Matrix file: {result.test_matrix_path or 'N/A'}")
    if result.downloaded_artifact_reasons:
        lines.append("- Downloaded scope/policy artifacts:")
        for item in result.downloaded_artifact_reasons:
            lines.append(f"  - {item}")

    out_file.write_text("\n".join(lines), encoding="utf-8")
    return str(out_file)


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
            [[t.test_id, t.category, t.test_name, t.target, t.scope_basis] for t in result.test_matrix[:100]],
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


def _render_suggested_tests_table(result) -> None:
    _print_section("Suggested Tests")
    if result.test_matrix:
        _print_table(
            ["ID", "Category", "Test", "Target", "Scope"],
            [[t.test_id, t.category, t.test_name, t.target, t.scope_basis] for t in result.test_matrix[:100]],
        )
        _print_table(
            ["Field", "Value"],
            [
                ["Total Suggested Tests", str(len(result.test_matrix))],
                ["Matrix File", result.test_matrix_path or "Not generated"],
            ],
        )
    else:
        _print_table(["ID", "Category", "Test", "Target", "Scope"], [["-", "-", "No suggested tests generated", "-", "-"]])


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


def _resolve_program_inputs(args: argparse.Namespace) -> tuple[str | None, str | None]:
    program_url = args.program_url
    program_hint = args.program_hint
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
    return program_url, program_hint


def _run_recon_with_session(
    args: argparse.Namespace,
    run_recon_fn,
    session_state: dict,
) -> tuple[object | None, int]:
    program_url, program_hint = _resolve_program_inputs(args)
    if not program_url:
        print(_color("RECON needs a program URL.", RED, bold=True))
        return None, 1

    result = run_recon_fn(program_url, program_hint)
    layout = build_session_layout(args.operator_id, program_url)
    profile_path = persist_recon_profile(layout, result, program_url, program_hint)
    session_state["program_url"] = program_url
    session_state["recon_done"] = True
    session_state["session_layout"] = layout
    session_state.setdefault("artifacts", []).append(profile_path)
    session_state.setdefault("steps", []).append(f"Session initialized: {layout.session_id}")
    session_state.setdefault("steps", []).append(f"RECON profile saved: {profile_path}")
    return result, 0


def main() -> int:
    args = parse_args()
    print(render_banner())
    print(_color("\n[Status] Starting ./bug_bounty", GREEN, bold=True))
    print(_color("Ready.", ORANGE, bold=True))
    _show_start_instructions()

    deps = ensure_runtime_dependencies(
        include_optional=False,
        auto_install=not args.no_auto_install_deps,
    )
    if deps.notes:
        _print_section("Runtime Dependencies")
        _print_table(["Status", "Details"], [[("OK" if deps.ok else "WARN"), note] for note in deps.notes])
    if not deps.ok:
        print(_color("[Error] Missing required runtime dependencies. Re-run with network access or install manually.", RED, bold=True))
        return 1

    # Optional dependencies (like selenium) should not block execution.
    if args.run_xss_unified:
        opt_deps = ensure_runtime_dependencies(
            include_optional=True,
            auto_install=not args.no_auto_install_deps,
        )
        optional_notes = [note for note in opt_deps.notes if "selenium" in note.lower()]
        if optional_notes:
            _print_section("Optional XSS Dependencies")
            _print_table(
                ["Status", "Details"],
                [[("OK" if opt_deps.ok else "WARN"), note] for note in optional_notes],
            )

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
    session_state: dict = {
        "program_url": program_url,
        "recon_done": False,
        "steps": [],
        "tested_targets": [],
        "artifacts": [],
        "findings": [],
        "session_layout": None,
    }

    if args.command:
        result, rc = _run_recon_with_session(args, run_recon, session_state)
        if rc != 0 or result is None:
            return 1

        if args.command == "recon":
            _render_recon(result)
            return 0

        if args.command == "test":
            if args.tool == "xss":
                core_deps = ensure_runtime_dependencies(
                    include_optional=False,
                    auto_install=not args.no_auto_install_deps,
                )
                if not core_deps.ok:
                    print(_color("[Error] XSS core dependencies unavailable.", RED, bold=True))
                    return 1
                rc = _run_xss_unified_scope_step(
                    result,
                    args.operator_id,
                    session_layout=session_state.get("session_layout"),
                    session_state=session_state,
                )
                return 0 if rc == 0 else 1
            rc = _run_afrog_safe_step(
                result,
                args.operator_id,
                session_layout=session_state.get("session_layout"),
                session_state=session_state,
            )
            return 0 if rc == 0 else 1

        if args.command == "report":
            out = _generate_automatic_report(
                result,
                args.operator_id,
                session_state,
                session_layout=session_state.get("session_layout"),
            )
            print(_color(f"[Auto Report] {out}", GREEN, bold=True))
            return 0

        if args.command == "run-all":
            _render_recon(result)
            xss_rc = _run_xss_unified_scope_step(
                result,
                args.operator_id,
                session_layout=session_state.get("session_layout"),
                session_state=session_state,
            )
            afrog_rc = _run_afrog_safe_step(
                result,
                args.operator_id,
                session_layout=session_state.get("session_layout"),
                session_state=session_state,
            )
            out = _generate_automatic_report(
                result,
                args.operator_id,
                session_state,
                session_layout=session_state.get("session_layout"),
            )
            print(_color(f"[Auto Report] {out}", GREEN, bold=True))
            return 0 if (xss_rc == 0 and afrog_rc == 0) else 1

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
        session_state["program_url"] = program_url
        session_state["recon_done"] = True
        if program_url:
            layout = build_session_layout(args.operator_id, program_url)
            session_state["session_layout"] = layout
            profile_path = persist_recon_profile(layout, result, program_url, program_hint)
            session_state.setdefault("artifacts", []).append(profile_path)
            session_state.setdefault("steps", []).append(f"Session initialized: {layout.session_id}")
            session_state.setdefault("steps", []).append(f"RECON profile saved: {profile_path}")
        session_state.setdefault("steps", []).append("RECON completed (non-interactive/direct mode).")
        if args.run_xss_unified:
            return _run_xss_unified_scope_step(
                result,
                args.operator_id,
                session_layout=session_state.get("session_layout"),
                session_state=session_state,
            )
        _render_all_steps(result)
        print(_color("[Quit] Non-interactive run complete.", RED, bold=True))
        return 0

    result = None
    intake_viewed = False
    tests_done = False

    while True:
        command = input(_color("bug_bounty>> ", ORANGE, bold=True)).strip().lower()
        if not command:
            continue

        if command in {"show options", "options", "menu"}:
            _show_workflow_menu()
            continue
        if command in {"help", "show help"}:
            _show_start_instructions()
            continue
        if command in {"q", "quit", "exit"}:
            print(_color("[Quit] Session ended.", RED, bold=True))
            break

        if command in {"1", "recon"}:
            if not program_url and not args.no_prompt:
                program_url = input("[Input] Paste project URL: ").strip()
            if not program_url:
                print(_color("RECON needs a program URL. Provide one and retry.", RED, bold=True))
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
            session_state["program_url"] = program_url
            session_state["recon_done"] = True
            layout = build_session_layout(args.operator_id, program_url)
            session_state["session_layout"] = layout
            profile_path = persist_recon_profile(layout, result, program_url, program_hint)
            session_state.setdefault("artifacts", []).append(profile_path)
            session_state.setdefault("steps", []).append(f"Session initialized: {layout.session_id}")
            session_state.setdefault("steps", []).append(f"RECON profile saved: {profile_path}")
            session_state.setdefault("steps", []).append(f"RECON completed for {program_url}.")
            continue

        if command in {"2", "tests", "test"}:
            if not intake_viewed:
                print(_color("RECON is mandatory. Run `recon` first.", RED, bold=True))
                continue
            _show_test_mode_menu()
            while True:
                mode_choice = input(_color("bug_bounty/tests>> ", ORANGE, bold=True)).strip().lower()
                if mode_choice in {"b", "back"}:
                    break
                if mode_choice in {"show options", "options", "menu"}:
                    _show_test_mode_menu()
                    continue
                if mode_choice in {"l", "list"}:
                    _print_section("Available Tests")
                    _print_table(
                        ["ID", "Test", "Status"],
                        [
                            ["XSS-01", "scope-aware xss_unified.py", "available"],
                            ["AFROG-01", "afrog baseline in-scope scan", "available"],
                            ["NEXT", "future tests you add later", "placeholder"],
                        ],
                    )
                elif mode_choice in {"s", "suggested"}:
                    _render_suggested_tests_table(result)
                elif mode_choice in {"x", "xss"}:
                    core_deps = ensure_runtime_dependencies(
                        include_optional=False,
                        auto_install=not args.no_auto_install_deps,
                    )
                    if core_deps.notes:
                        _print_section("XSS Runtime Dependencies")
                        _print_table(
                            ["Status", "Details"],
                            [[("OK" if core_deps.ok else "WARN"), note] for note in core_deps.notes],
                        )
                    if not core_deps.ok:
                        print(_color("[Error] XSS core dependencies unavailable.", RED, bold=True))
                        continue
                    optional_deps = ensure_runtime_dependencies(
                        include_optional=True,
                        auto_install=not args.no_auto_install_deps,
                    )
                    optional_notes = [note for note in optional_deps.notes if "selenium" in note.lower()]
                    if optional_notes:
                        _print_section("Optional XSS Dependencies")
                        _print_table(
                            ["Status", "Details"],
                            [[("OK" if optional_deps.ok else "WARN"), note] for note in optional_notes],
                        )
                    if not optional_deps.ok:
                        print(_color("[Note] Continuing XSS scan without optional DOM browser checks if selenium is unavailable.", YELLOW, bold=True))
                    _render_step_2(result)
                    rc = _run_xss_unified_scope_step(
                        result,
                        args.operator_id,
                        session_layout=session_state.get("session_layout"),
                        session_state=session_state,
                    )
                    if rc == 0:
                        tests_done = True
                        session_state.setdefault("steps", []).append("TESTS completed: XSS unified scan executed.")
                elif mode_choice in {"a", "afrog"}:
                    _render_step_2(result)
                    rc = _run_afrog_safe_step(
                        result,
                        args.operator_id,
                        session_layout=session_state.get("session_layout"),
                        session_state=session_state,
                    )
                    if rc == 0:
                        tests_done = True
                        session_state.setdefault("steps", []).append("TESTS completed: Afrog baseline scan executed.")
                else:
                    print(_color("Invalid test command. Use: show options | list | suggested | xss | afrog | back", RED, bold=True))
            continue

        if command in {"3", "report", "reporting"}:
            if not intake_viewed:
                print(_color("Run RECON first.", YELLOW, bold=True))
                continue
            auto_report_path = _generate_automatic_report(
                result,
                args.operator_id,
                session_state,
                session_layout=session_state.get("session_layout"),
            )
            session_state.setdefault("artifacts", []).append(auto_report_path)
            session_state.setdefault("steps", []).append("REPORTING invoked: automatic session report generated.")
            print(_color(f"[Auto Report] {auto_report_path}", GREEN, bold=True))
            _show_reporting_menu()
            while True:
                r_choice = input(_color("bug_bounty/report>> ", ORANGE, bold=True)).strip().lower()
                if r_choice in {"b", "back"}:
                    break
                if r_choice in {"show options", "options", "menu"}:
                    _show_reporting_menu()
                    continue
                if r_choice in {"d", "download"}:
                    out = _save_download_manifest(result, args.operator_id)
                    print(_color(f"[Saved] Download manifest: {out}", GREEN, bold=True))
                elif r_choice in {"c", "custom"}:
                    out = _save_custom_report(args.operator_id)
                    if out:
                        print(_color(f"[Saved] Custom report: {out}", GREEN, bold=True))
                    else:
                        print(_color("[Note] Custom report was not saved (empty note).", YELLOW, bold=True))
                elif r_choice in {"v", "view"}:
                    if not tests_done:
                        print(_color("[Note] No test execution recorded yet. Showing current compiled details.", YELLOW, bold=True))
                    _render_step_4(result)
                    _render_documentation(result)
                else:
                    print(_color("Invalid reporting command. Use: show options | download | custom | view | back", RED, bold=True))
            continue

        print(_color("Unknown command. Type `show options` or `help`.", RED, bold=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
