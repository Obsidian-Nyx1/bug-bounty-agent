"""TESTS module: execute tool runs and persist structured test artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
    combined_file = out_dir / f"xss_unified_{timestamp}.json"
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
        },
        "targets": [],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        html_artifacts: list[str] = []
        for idx, target in enumerate(targets, start=1):
            if on_target:
                on_target(idx, len(targets), target)
            tmp_output = Path(tmpdir) / f"target_{idx}.json"
            slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", target)
            html_output = out_dir / f"{slug}_{timestamp}.html"
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
            if html_report:
                cmd.extend(["--html-report", str(html_output)])
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

            combined["summary"]["reflected"] += reflected
            combined["summary"]["stored"] += stored
            combined["summary"]["dom"] += dom
            combined["summary"]["wordpress_admin_notices"] += wp_notice

            entry = {
                "target": target,
                "exit_code": proc.returncode,
                "tests": {
                    "reflected": reflected,
                    "stored": stored,
                    "dom": dom,
                    "wordpress_admin_notices": wp_notice,
                },
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

            # Keep HTML report only when it exists and is not empty.
            if html_report and html_output.exists():
                if html_output.stat().st_size > 0:
                    html_artifacts.append(str(html_output))
                    entry["html_report"] = str(html_output)
                else:
                    try:
                        html_output.unlink()
                    except Exception:
                        pass
            combined["targets"].append(entry)

    combined_file.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    run_index.append(
        {
            "tool": "xss_unified",
            "targets": len(targets),
            "output": str(combined_file),
            "exit_code": 1 if failures else 0,
        }
    )

    index_file = _append_test_index(layout, "xss_unified", run_index, timestamp)
    return ToolRunResult(
        failures=failures,
        artifacts=[str(combined_file), *html_artifacts],
        targets=targets,
        index_file=index_file,
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
    on_target: Optional[Callable[[int, int, str], None]] = None,
) -> ToolRunResult:
    ensure_layout(layout)
    targets, _, _ = collect_approved_targets(result)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_dir = layout.tests_dir / "afrog"
    out_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    artifacts: list[str] = []
    run_index: list[dict] = []
    for idx, target in enumerate(targets, start=1):
        if on_target:
            on_target(idx, len(targets), target)
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", target)
        out_file = out_dir / f"{slug}_{timestamp}.txt"
        cmd = [afrog_bin, "-t", target]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = [f"$ {' '.join(cmd)}", "", proc.stdout or "", proc.stderr or ""]
        out_file.write_text("\n".join(output), encoding="utf-8")
        artifacts.append(str(out_file))
        run_index.append(
            {
                "tool": "afrog",
                "target": target,
                "command": cmd,
                "output": str(out_file),
                "exit_code": proc.returncode,
            }
        )
        if proc.returncode != 0:
            failures += 1

    index_file = _append_test_index(layout, "afrog", run_index, timestamp)
    return ToolRunResult(failures=failures, artifacts=artifacts, targets=targets, index_file=index_file)


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
