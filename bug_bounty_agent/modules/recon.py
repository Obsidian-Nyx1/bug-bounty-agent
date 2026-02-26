"""RECON module: persist normalized intake artifacts for downstream steps."""

from __future__ import annotations

from dataclasses import asdict
import json

from bug_bounty_agent.modules.schemas import SessionLayout, ensure_layout


def persist_recon_profile(layout: SessionLayout, result, program_url: str, program_hint: str | None) -> str:
    ensure_layout(layout)
    payload = {
        "session_id": layout.session_id,
        "program_url": program_url,
        "program_hint": program_hint,
        "status": result.status,
        "summary": result.summary,
        "project_key": result.report_path or "",
        "recommendation": asdict(result.recommendation),
        "scope_data": asdict(result.scope_data),
        "downloaded_artifact_reasons": list(result.downloaded_artifact_reasons),
        "sources": list(result.sources),
        "notes": list(result.notes),
        "test_matrix": [asdict(t) for t in result.test_matrix],
        "test_matrix_path": result.test_matrix_path,
        "report_path": result.report_path,
    }
    layout.recon_profile_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(layout.recon_profile_file)

