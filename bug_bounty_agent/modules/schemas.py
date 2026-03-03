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
    parsed = urlparse(program_url)
    host = parsed.hostname or "unknown-program"
    path_parts = [part for part in parsed.path.split("/") if part]

    session_key = host.lower()
    if host.lower() == "hackerone.com" and path_parts:
        session_key = path_parts[0].lower()
    elif path_parts and path_parts[0] not in {"", "/"}:
        session_key = f"{host.lower()}_{path_parts[0].lower()}"

    safe_key = re.sub(r"[^a-zA-Z0-9._-]+", "_", session_key)
    session_id = f"{safe_key}_{timestamp}"
    # Keep session artifacts in a simple top-level path for easy access.
    root = Path("reports") / operator_id / session_id
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
