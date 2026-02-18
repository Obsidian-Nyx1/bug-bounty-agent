"""Lightweight run memory so the agent can adapt over time."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re


class LearningStore:
    def __init__(self, memory_file: Path) -> None:
        self.memory_file = memory_file
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)
        self.base_dir = self.memory_file.parent

    def record_run(
        self,
        operator_id: str,
        project_key: str,
        mode: str,
        program_url: str,
        completed: list[str],
        pending: list[str],
    ) -> int:
        history = self._read_all()
        run_count = sum(1 for row in history if row.get("project_key") == project_key) + 1
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator_id": operator_id,
            "project_key": project_key,
            "program_url": program_url,
            "mode": mode,
            "completed_count": len(completed),
            "pending_count": len(pending),
            "run_count_for_project": run_count,
        }
        with self.memory_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        return run_count

    def load_checkpoint(self, operator_id: str, project_key: str) -> dict | None:
        path = self._checkpoint_path(operator_id, project_key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def save_checkpoint(
        self,
        operator_id: str,
        project_key: str,
        payload: dict,
    ) -> Path:
        path = self._checkpoint_path(operator_id, project_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def get_last_program_url(self, operator_id: str) -> str | None:
        rows = self._read_all()
        filtered = [row for row in rows if row.get("operator_id") == operator_id]
        if not filtered:
            return None
        filtered.sort(key=lambda x: x.get("timestamp", ""))
        return filtered[-1].get("program_url")

    def _read_all(self) -> list[dict]:
        if not self.memory_file.exists():
            return []
        rows: list[dict] = []
        with self.memory_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    def _checkpoint_path(self, operator_id: str, project_key: str) -> Path:
        safe_operator = self._safe_slug(operator_id)
        safe_project = self._safe_slug(project_key)
        return self.base_dir / "checkpoints" / safe_operator / f"{safe_project}.json"

    @staticmethod
    def _safe_slug(text: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", text.strip())
        return slug.strip("-").lower() or "default"
