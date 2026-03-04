"""TESTS module: execute tool runs and persist structured test artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Optional
from urllib.parse import urlparse

from bug_bounty_agent.modules.schemas import SessionLayout, ensure_layout
from bug_bounty_agent.scope import classify_domain

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
URL_RE = re.compile(r"https?://[^\s\])>]+", re.IGNORECASE)


@dataclass
class ToolRunResult:
    failures: int
    artifacts: list[str]
    targets: list[str]
    index_file: str | None
    findings: list[dict] | None = None


def collect_xss_targets(result) -> tuple[list[str], list[str], list[str]]:
    candidates: list[tuple[str, str]] = []
    for item in result.scope_data.in_scope:
        candidates.append((item, "recon_scope"))
    for item in getattr(result, "discovery", []).in_scope_domains if hasattr(result, "discovery") else []:
        candidates.append((item, "recon_discovery_scope"))
    for test in result.test_matrix:
        if test.category.strip().lower() != "xss":
            continue
        if "verified_in_scope" not in (test.scope_basis or ""):
            continue
        candidates.append((test.target, f"suggested_test_{test.test_id}"))
    if result.recommendation and result.recommendation.domain and result.recommendation.status == "in-scope":
        candidates.append((result.recommendation.domain, "recommendation"))
    return _normalize_candidates(candidates, result=result)


def collect_approved_targets(result) -> tuple[list[str], list[str], list[str]]:
    candidates: list[tuple[str, str]] = []
    for item in result.scope_data.in_scope:
        candidates.append((item, "recon_scope"))
    for test in result.test_matrix:
        if "verified_in_scope" not in (test.scope_basis or ""):
            continue
        candidates.append((test.target, f"suggested_test_{test.test_id}"))
    if result.recommendation and result.recommendation.domain and result.recommendation.status == "in-scope":
        candidates.append((result.recommendation.domain, "recommendation"))
    return _normalize_candidates(candidates, result=result)


def _normalize_candidates(candidates: list[tuple[str, str]], result=None) -> tuple[list[str], list[str], list[str]]:
    valid: list[str] = []
    skipped: list[str] = []
    used_sources: list[str] = []
    for item, source in candidates:
        normalized = _normalize_target(item)
        if not normalized:
            skipped.append(item)
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if host in {"hackerone.com", "www.hackerone.com"}:
            skipped.append(item)
            continue
        if result is not None and hasattr(result, "scope_data"):
            scope_status = classify_domain(host, result.scope_data)
            if scope_status != "in-scope":
                skipped.append(item)
                continue
        if normalized not in valid:
            valid.append(normalized)
            used_sources.append(f"{normalized} <- {source}")
    return valid, skipped, used_sources


def _normalize_target(item: str) -> str | None:
    raw = (item or "").strip()
    if not raw:
        return None
    if raw.startswith("*."):
        raw = raw[2:]
    low = raw.lower()
    if low.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return raw.rstrip("/")
        return None
    if DOMAIN_RE.match(low):
        return f"https://{low}"
    return None


def run_xss_scope(
    result,
    layout: SessionLayout,
    script_path: Path,
    use_async_mode: bool = True,
    use_headless: bool = True,
    use_waf_evasion: bool = False,
    html_report: bool = True,
    on_target: Optional[Callable[[int, int, str], None]] = None,
) -> ToolRunResult:
    ensure_layout(layout)
    targets, _, _ = collect_xss_targets(result)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_dir = layout.tests_dir / "xss_unified"
    out_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    run_index: list[dict] = []
    txt_report = out_dir / f"xss_unified_{timestamp}.txt"
    html_summary = out_dir / f"xss_unified_{timestamp}.html"
    combined: dict = {
        "tool": "xss_unified",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_count": len(targets),
        "summary": {
            "failed_targets": 0,
            "reflected": 0,
            "stored": 0,
            "dom": 0,
            "wordpress_admin_notices": 0,
            "triage_by_verdict": {},
        },
        "targets": [],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        for idx, target in enumerate(targets, start=1):
            if on_target:
                on_target(idx, len(targets), target)
            tmp_output = Path(tmpdir) / f"target_{idx}.json"
            cmd = [
                sys.executable,
                str(script_path),
                target,
                "--non-interactive",
                "--depth",
                "1",
                "--output",
                str(tmp_output),
            ]
            if use_async_mode:
                cmd.append("--async-mode")
            if use_headless:
                cmd.append("--headless")
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            target_data: dict = {}
            if tmp_output.exists():
                try:
                    target_data = json.loads(tmp_output.read_text(encoding="utf-8"))
                except Exception:
                    target_data = {}

            reflected = len(target_data.get("reflected", []))
            stored = len(target_data.get("stored", []))
            dom = len(target_data.get("dom", []))
            wp_notice = len(target_data.get("wordpress_admin_notices", []))
            triage_summary = target_data.get("triage_summary", {})

            combined["summary"]["reflected"] += reflected
            combined["summary"]["stored"] += stored
            combined["summary"]["dom"] += dom
            combined["summary"]["wordpress_admin_notices"] += wp_notice
            for verdict, count in triage_summary.get("by_verdict", {}).items():
                current = combined["summary"]["triage_by_verdict"].get(verdict, 0)
                combined["summary"]["triage_by_verdict"][verdict] = current + int(count)

            entry = {
                "target": target,
                "exit_code": proc.returncode,
                "tests": {
                    "reflected": reflected,
                    "stored": stored,
                    "dom": dom,
                    "wordpress_admin_notices": wp_notice,
                },
                "triage_summary": triage_summary,
                "findings": {
                    "reflected": target_data.get("reflected", []),
                    "stored": target_data.get("stored", []),
                    "dom": target_data.get("dom", []),
                    "wordpress_admin_notices": target_data.get("wordpress_admin_notices", []),
                },
            }
            if proc.returncode != 0:
                failures += 1
                combined["summary"]["failed_targets"] += 1
                entry["error"] = (proc.stderr or proc.stdout or "").strip()[:500]

            combined["targets"].append(entry)

    if html_report:
        _write_xss_consolidated_html(html_summary, combined)
        selected_report = html_summary
    else:
        _write_xss_consolidated_txt(txt_report, combined)
        selected_report = txt_report
    run_index.append(
        {
            "tool": "xss_unified",
            "targets": len(targets),
            "output": str(selected_report),
            "exit_code": 1 if failures else 0,
        }
    )

    index_file = _append_test_index(layout, "xss_unified", run_index, timestamp)
    artifacts = [str(selected_report)]
    findings = _collect_xss_findings(combined)
    return ToolRunResult(
        failures=failures,
        artifacts=artifacts,
        targets=targets,
        index_file=index_file,
        findings=findings,
    )


def find_afrog_binary() -> Optional[str]:
    found = shutil.which("afrog")
    if found:
        return found
    go_bin = Path.home() / "go" / "bin" / "afrog"
    if go_bin.exists():
        return str(go_bin)
    return None


def ensure_afrog_installed() -> Optional[str]:
    existing = find_afrog_binary()
    if existing:
        return existing
    install_cmds = [
        ["go", "install", "github.com/zan8in/afrog/v3/cmd/afrog@latest"],
        ["go", "install", "github.com/zan8in/afrog/cmd/afrog@latest"],
    ]
    for cmd in install_cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception:
            continue
        if proc.returncode == 0:
            installed = find_afrog_binary()
            if installed:
                return installed
    return find_afrog_binary()


def run_afrog_scope(
    result,
    layout: SessionLayout,
    afrog_bin: str,
    extra_args: list[str] | None = None,
    on_target: Optional[Callable[[int, int, str], None]] = None,
) -> ToolRunResult:
    ensure_layout(layout)
    targets, _, _ = collect_approved_targets(result)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_dir = layout.tests_dir / "afrog"
    out_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    html_report = out_dir / f"afrog_{timestamp}.html"
    run_index: list[dict] = []
    runs: list[dict] = []
    extra = list(extra_args or [])
    for idx, target in enumerate(targets, start=1):
        if on_target:
            on_target(idx, len(targets), target)
        cmd = [afrog_bin, *extra, "-t", target]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        finding_lines = _extract_key_lines(stdout + "\n" + stderr)
        runs.append(
            {
                "target": target,
                "exit_code": proc.returncode,
                "command": cmd,
                "stdout": stdout,
                "stderr": stderr,
                "finding_lines": finding_lines,
            }
        )
        run_index.append(
            {
                "tool": "afrog",
                "target": target,
                "command": cmd,
                "output": str(html_report),
                "exit_code": proc.returncode,
            }
        )
        if proc.returncode != 0:
            failures += 1

    _write_afrog_consolidated_html(html_report, runs)
    index_file = _append_test_index(layout, "afrog", run_index, timestamp)
    return ToolRunResult(
        failures=failures,
        artifacts=[str(html_report)],
        targets=targets,
        index_file=index_file,
        findings=[],
    )


def _append_test_index(layout: SessionLayout, tool: str, entries: list[dict], timestamp: str) -> str:
    payload = {"last_updated": datetime.now(timezone.utc).isoformat(), "runs": []}
    if layout.tests_index_file.exists():
        try:
            payload = json.loads(layout.tests_index_file.read_text(encoding="utf-8"))
        except Exception:
            payload = {"last_updated": datetime.now(timezone.utc).isoformat(), "runs": []}

    payload.setdefault("runs", []).append({"tool": tool, "timestamp": timestamp, "entries": entries})
    payload["last_updated"] = datetime.now(timezone.utc).isoformat()
    layout.tests_index_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(layout.tests_index_file)


def _extract_key_lines(text: str, limit: int = 30) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if any(
            token in low
            for token in (
                "critical",
                "high",
                "medium",
                "low",
                "vulnerable",
                "cve-",
                "matched",
                "found",
                "issue",
            )
        ):
            lines.append(line[:240])
        if len(lines) >= limit:
            break
    return lines


def _collect_xss_findings(combined: dict) -> list[dict]:
    findings: list[dict] = []
    mapping = {
        "reflected": "medium",
        "stored": "high",
        "dom": "high",
        "wordpress_admin_notices": "medium",
    }
    for target_entry in combined.get("targets", [])[:500]:
        target_name = str(target_entry.get("target") or "unknown")
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
                    }
                )
    return findings


def _write_xss_consolidated_txt(path: Path, combined: dict) -> None:
    lines = [
        "XSS Unified Consolidated Report",
        f"Generated: {combined.get('generated_at', 'n/a')}",
        f"Targets tested: {combined.get('target_count', 0)}",
        "",
        "Summary",
        f"- Failed targets: {combined.get('summary', {}).get('failed_targets', 0)}",
        f"- Reflected findings: {combined.get('summary', {}).get('reflected', 0)}",
        f"- Reflected triage: {combined.get('summary', {}).get('triage_by_verdict', {})}",
        f"- Stored findings: {combined.get('summary', {}).get('stored', 0)}",
        f"- DOM findings: {combined.get('summary', {}).get('dom', 0)}",
        f"- WordPress notice findings: {combined.get('summary', {}).get('wordpress_admin_notices', 0)}",
        "",
        "Per Target Details",
    ]
    for idx, item in enumerate(combined.get("targets", []), start=1):
        tests = item.get("tests", {})
        lines.extend(
            [
                f"{idx}. Target: {item.get('target', 'n/a')}",
                f"   Exit code: {item.get('exit_code', 'n/a')}",
                (
                    "   Counts: "
                    f"reflected={tests.get('reflected', 0)}, "
                    f"stored={tests.get('stored', 0)}, "
                    f"dom={tests.get('dom', 0)}, "
                    f"wp_notice={tests.get('wordpress_admin_notices', 0)}"
                ),
                f"   Reflected triage: {item.get('triage_summary', {}).get('by_verdict', {})}",
            ]
        )
        if item.get("error"):
            lines.append(f"   Error: {str(item.get('error', ''))[:300]}")
        findings = item.get("findings", {})
        for key in ("reflected", "stored", "dom", "wordpress_admin_notices"):
            vals = findings.get(key, [])
            if not vals:
                continue
            lines.append(f"   {key}:")
            for v in vals[:6]:
                lines.append(f"     - {str(v)[:220]}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_xss_consolidated_html(path: Path, combined: dict) -> None:
    rows = []
    for item in combined.get("targets", []):
        tests = item.get("tests", {})
        detail = []
        findings = item.get("findings", {})
        for key in ("reflected", "stored", "dom", "wordpress_admin_notices"):
            vals = findings.get(key, [])
            if not vals:
                continue
            detail.append(f"<div><strong>{html.escape(key)}:</strong><ul>")
            for v in vals[:6]:
                detail.append(f"<li>{html.escape(str(v)[:260])}</li>")
            detail.append("</ul></div>")
        if item.get("error"):
            detail.append(f"<div><strong>Error:</strong> {html.escape(str(item.get('error'))[:300])}</div>")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('target', 'n/a')))}</td>"
            f"<td>{item.get('exit_code', 'n/a')}</td>"
            f"<td>ref={tests.get('reflected', 0)} / stored={tests.get('stored', 0)} / "
            f"dom={tests.get('dom', 0)} / wp={tests.get('wordpress_admin_notices', 0)}"
            f"<br>triage={html.escape(str(item.get('triage_summary', {}).get('by_verdict', {})))}</td>"
            f"<td>{''.join(detail) or 'None'}</td>"
            "</tr>"
        )
    html_text = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>XSS Consolidated Report</title>"
        "<style>body{font-family:Arial,sans-serif;margin:20px;}table{width:100%;border-collapse:collapse;}"
        "th,td{border:1px solid #ccc;padding:8px;vertical-align:top;}th{background:#f1f5f9;text-align:left;}</style>"
        "</head><body>"
        "<h1>XSS Unified Consolidated Report</h1>"
        f"<p><strong>Generated:</strong> {html.escape(str(combined.get('generated_at', 'n/a')))}</p>"
        f"<p><strong>Targets tested:</strong> {combined.get('target_count', 0)}</p>"
        "<h2>Summary</h2>"
        "<ul>"
        f"<li>Failed targets: {combined.get('summary', {}).get('failed_targets', 0)}</li>"
        f"<li>Reflected findings: {combined.get('summary', {}).get('reflected', 0)}</li>"
        f"<li>Reflected triage: {html.escape(str(combined.get('summary', {}).get('triage_by_verdict', {})))}</li>"
        f"<li>Stored findings: {combined.get('summary', {}).get('stored', 0)}</li>"
        f"<li>DOM findings: {combined.get('summary', {}).get('dom', 0)}</li>"
        f"<li>WordPress notice findings: {combined.get('summary', {}).get('wordpress_admin_notices', 0)}</li>"
        "</ul>"
        "<h2>Per Target Details</h2>"
        "<table><thead><tr><th>Target</th><th>Exit</th><th>Counts</th><th>Findings</th></tr></thead><tbody>"
        f"{''.join(rows)}"
        "</tbody></table></body></html>"
    )
    path.write_text(html_text, encoding="utf-8")


def _write_afrog_consolidated_txt(path: Path, runs: list[dict]) -> None:
    failed = sum(1 for r in runs if int(r.get("exit_code", 1)) != 0)
    lines = [
        "Afrog Consolidated Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Targets tested: {len(runs)}",
        f"Failed targets: {failed}",
        "",
        "Per Target Details",
    ]
    for idx, run in enumerate(runs, start=1):
        lines.extend(
            [
                f"{idx}. Target: {run.get('target', 'n/a')}",
                f"   Command: {' '.join(run.get('command', []))}",
                f"   Exit code: {run.get('exit_code', 'n/a')}",
            ]
        )
        flines = run.get("finding_lines", [])
        if flines:
            lines.append("   Findings/Signals:")
            for line in flines:
                lines.append(f"     - {line}")
        else:
            lines.append("   Findings/Signals: none detected in output")
        if run.get("stderr", "").strip():
            lines.append(f"   stderr (preview): {run.get('stderr', '').strip()[:300]}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_afrog_consolidated_html(path: Path, runs: list[dict]) -> None:
    rows = []
    for run in runs:
        flines = run.get("finding_lines", [])
        findings = "<br>".join(html.escape(line) for line in flines) if flines else "None"
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(run.get('target', 'n/a')))}</td>"
            f"<td>{run.get('exit_code', 'n/a')}</td>"
            f"<td>{html.escape(' '.join(run.get('command', [])))}</td>"
            f"<td>{findings}</td>"
            "</tr>"
        )
    html_text = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Afrog Consolidated Report</title>"
        "<style>body{font-family:Arial,sans-serif;margin:20px;}table{width:100%;border-collapse:collapse;}"
        "th,td{border:1px solid #ccc;padding:8px;vertical-align:top;}th{background:#f1f5f9;text-align:left;}</style>"
        "</head><body>"
        "<h1>Afrog Consolidated Report</h1>"
        f"<p><strong>Generated:</strong> {html.escape(datetime.now(timezone.utc).isoformat())}</p>"
        f"<p><strong>Targets tested:</strong> {len(runs)}</p>"
        "<table><thead><tr><th>Target</th><th>Exit</th><th>Command</th><th>Findings/Signals</th></tr></thead><tbody>"
        f"{''.join(rows)}"
        "</tbody></table></body></html>"
    )
    path.write_text(html_text, encoding="utf-8")
