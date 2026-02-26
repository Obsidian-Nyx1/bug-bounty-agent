"""Shared session schema for recon/tests/reporting artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import re


@dataclass
class SessionLayout:
    session_id: str
    root: Path
    recon_dir: Path
    tests_dir: Path
    reports_dir: Path
    recon_profile_file: Path
    tests_index_file: Path


def build_session_layout(operator_id: str, program_url: str) -> SessionLayout:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    host = urlparse(program_url).hostname or "unknown-program"
    safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", host.lower())
    session_id = f"{safe_host}_{timestamp}"
    root = Path(".bug_bounty_agent/sessions") / operator_id / session_id
    recon_dir = root / "recon"
    tests_dir = root / "tests"
    reports_dir = root / "reports"
    recon_profile_file = recon_dir / "project.json"
    tests_index_file = tests_dir / "index.json"
    return SessionLayout(
        session_id=session_id,
        root=root,
        recon_dir=recon_dir,
        tests_dir=tests_dir,
        reports_dir=reports_dir,
        recon_profile_file=recon_profile_file,
        tests_index_file=tests_index_file,
    )


def ensure_layout(layout: SessionLayout) -> None:
    layout.root.mkdir(parents=True, exist_ok=True)
    layout.recon_dir.mkdir(parents=True, exist_ok=True)
    layout.tests_dir.mkdir(parents=True, exist_ok=True)
    layout.reports_dir.mkdir(parents=True, exist_ok=True)

