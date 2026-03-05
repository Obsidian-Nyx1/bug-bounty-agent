"""L-point learning loop: persistent run memory + online model updates."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

DB_PATH = Path(".bug_bounty_agent/lpoint_learning.db")
MODEL_KEY_GLOBAL = "__global__"

DEFAULT_MODEL_WEIGHTS: dict[str, float] = {
    "ml_bias": 0.0,
    "ml_in_scope": 1.2,
    "ml_high_value": 0.8,
    "ml_docs": 0.4,
    "ml_allowed": 0.6,
    "ml_prev_bug": 0.4,
    "ml_related_assets": 0.3,
    "ml_out_scope": -2.0,
}


def model_db_path() -> str:
    return str(DB_PATH)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sigmoid(value: float) -> float:
    if value < -60:
        return 0.0
    if value > 60:
        return 1.0
    return 1.0 / (1.0 + pow(2.718281828, -value))


def _normalize_target(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower().strip(".")
    return raw.strip(".")


def _safe_project_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", (value or "").strip().lower()) or "default-project"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS recon_runs (
            run_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            operator_id TEXT NOT NULL,
            project_key TEXT NOT NULL,
            program_url TEXT NOT NULL,
            mode TEXT NOT NULL,
            tests_generated INTEGER NOT NULL,
            automated_findings_total INTEGER NOT NULL,
            automated_review_findings INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recon_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            target TEXT NOT NULL,
            in_scope INTEGER NOT NULL,
            out_scope INTEGER NOT NULL,
            high_value INTEGER NOT NULL,
            docs_ref INTEGER NOT NULL,
            allowed_ref INTEGER NOT NULL,
            prev_bug_ref INTEGER NOT NULL,
            related_assets REAL NOT NULL,
            confidence REAL NOT NULL,
            exposure REAL NOT NULL,
            priority REAL NOT NULL,
            ml_probability REAL NOT NULL,
            FOREIGN KEY(run_id) REFERENCES recon_runs(run_id)
        );

        CREATE TABLE IF NOT EXISTS recon_outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            target TEXT NOT NULL,
            label REAL NOT NULL,
            review_count INTEGER NOT NULL,
            ok_count INTEGER NOT NULL,
            FOREIGN KEY(run_id) REFERENCES recon_runs(run_id)
        );

        CREATE TABLE IF NOT EXISTS model_state (
            project_key TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            sample_count INTEGER NOT NULL,
            weights_json TEXT NOT NULL
        );
        """
    )
    conn.commit()


def _load_state(conn: sqlite3.Connection, project_key: str) -> tuple[dict[str, float], dict[str, Any]]:
    key = _safe_project_key(project_key)
    row = conn.execute("SELECT * FROM model_state WHERE project_key = ?", (key,)).fetchone()
    source = "project"
    if row is None:
        row = conn.execute("SELECT * FROM model_state WHERE project_key = ?", (MODEL_KEY_GLOBAL,)).fetchone()
        source = "global"
    if row is None:
        return dict(DEFAULT_MODEL_WEIGHTS), {"version": 0, "updated_at": None, "sample_count": 0, "source": "default"}
    try:
        parsed = json.loads(str(row["weights_json"]))
    except Exception:
        parsed = {}
    merged = dict(DEFAULT_MODEL_WEIGHTS)
    for key_name, value in parsed.items():
        try:
            merged[key_name] = float(value)
        except Exception:
            continue
    meta = {
        "version": int(row["version"]),
        "updated_at": str(row["updated_at"]),
        "sample_count": int(row["sample_count"]),
        "source": source,
    }
    return merged, meta


def load_model_weights(project_key: str) -> dict[str, Any]:
    with _connect() as conn:
        weights, meta = _load_state(conn, project_key)
    return {"weights": weights, "meta": meta, "db_path": model_db_path()}


def _save_state(
    conn: sqlite3.Connection,
    project_key: str,
    *,
    weights: dict[str, float],
    version: int,
    sample_count: int,
) -> None:
    conn.execute(
        """
        INSERT INTO model_state(project_key, version, updated_at, sample_count, weights_json)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(project_key) DO UPDATE SET
            version=excluded.version,
            updated_at=excluded.updated_at,
            sample_count=excluded.sample_count,
            weights_json=excluded.weights_json
        """,
        (
            _safe_project_key(project_key),
            int(version),
            _utc_now(),
            int(sample_count),
            json.dumps(weights, sort_keys=True),
        ),
    )
    conn.commit()


def _features_from_scored_item(item: dict[str, Any]) -> dict[str, float]:
    features = item.get("features", {}) if isinstance(item, dict) else {}
    return {
        "in_scope": float(features.get("in_scope", 0.0)),
        "high_value": float(features.get("high_value", 0.0)),
        "docs_ref": float(features.get("docs_reference", 0.0)),
        "allowed_ref": float(features.get("allowed_scope_signal", 0.0)),
        "prev_bug_ref": float(features.get("previous_bug_context", 0.0)),
        "related_assets": float(features.get("related_assets", 0.0)),
        "out_scope": float(features.get("out_of_scope", 0.0)),
    }


def _predict(weights: dict[str, float], features: dict[str, float]) -> float:
    logit = float(weights.get("ml_bias", 0.0))
    logit += float(weights.get("ml_in_scope", 0.0)) * float(features.get("in_scope", 0.0))
    logit += float(weights.get("ml_high_value", 0.0)) * float(features.get("high_value", 0.0))
    logit += float(weights.get("ml_docs", 0.0)) * float(features.get("docs_ref", 0.0))
    logit += float(weights.get("ml_allowed", 0.0)) * float(features.get("allowed_ref", 0.0))
    logit += float(weights.get("ml_prev_bug", 0.0)) * float(features.get("prev_bug_ref", 0.0))
    logit += float(weights.get("ml_related_assets", 0.0)) * float(features.get("related_assets", 0.0))
    logit += float(weights.get("ml_out_scope", 0.0)) * float(features.get("out_scope", 0.0))
    return _sigmoid(logit)


def _collect_automated_outcomes(automated_findings: list[Any]) -> dict[str, dict[str, int]]:
    outcomes: dict[str, dict[str, int]] = {}
    for finding in automated_findings:
        target_raw = str(getattr(finding, "target", "") or "")
        target = _normalize_target(target_raw)
        if not target:
            continue
        status = str(getattr(finding, "status", "") or "").strip().lower()
        bucket = outcomes.setdefault(target, {"review": 0, "ok": 0})
        if status == "review":
            bucket["review"] += 1
        else:
            bucket["ok"] += 1
    return outcomes


def record_lpoint_cycle(
    *,
    operator_id: str,
    project_key: str,
    program_url: str,
    mode: str,
    recon_flow: dict[str, Any],
    tests_generated: int,
    automated_findings: list[Any] | None,
) -> dict[str, Any]:
    run_id = f"run_{uuid4().hex[:16]}"
    scored_targets = list(recon_flow.get("scored_targets", []) or [])
    outcomes = _collect_automated_outcomes(automated_findings or [])
    review_total = sum(item["review"] for item in outcomes.values())
    finding_total = sum((item["review"] + item["ok"]) for item in outcomes.values())

    with _connect() as conn:
        weights, meta = _load_state(conn, project_key)
        conn.execute(
            """
            INSERT INTO recon_runs(
                run_id, created_at, operator_id, project_key, program_url, mode,
                tests_generated, automated_findings_total, automated_review_findings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                _utc_now(),
                operator_id,
                _safe_project_key(project_key),
                program_url,
                mode,
                int(tests_generated),
                int(finding_total),
                int(review_total),
            ),
        )

        labeled_samples = 0
        learning_rate = 0.08
        for item in scored_targets:
            target = _normalize_target(str(item.get("target", "") or ""))
            if not target:
                continue
            features = _features_from_scored_item(item)
            scores = item.get("scores", {}) if isinstance(item, dict) else {}
            conn.execute(
                """
                INSERT INTO recon_targets(
                    run_id, target, in_scope, out_scope, high_value, docs_ref, allowed_ref, prev_bug_ref,
                    related_assets, confidence, exposure, priority, ml_probability
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target,
                    int(features["in_scope"]),
                    int(features["out_scope"]),
                    int(features["high_value"]),
                    int(features["docs_ref"]),
                    int(features["allowed_ref"]),
                    int(features["prev_bug_ref"]),
                    float(features["related_assets"]),
                    float(scores.get("confidence", 0.0)),
                    float(scores.get("exposure", 0.0)),
                    float(scores.get("priority", 0.0)),
                    float(scores.get("ml_probability", 0.5)),
                ),
            )

            if target not in outcomes:
                continue
            review_count = int(outcomes[target]["review"])
            ok_count = int(outcomes[target]["ok"])
            label = 1.0 if review_count > 0 else 0.0
            conn.execute(
                """
                INSERT INTO recon_outcomes(run_id, target, label, review_count, ok_count)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, target, label, review_count, ok_count),
            )
            prediction = _predict(weights, features)
            error = label - prediction
            weights["ml_bias"] = float(weights.get("ml_bias", 0.0)) + learning_rate * error
            weights["ml_in_scope"] = float(weights.get("ml_in_scope", 0.0)) + learning_rate * error * features["in_scope"]
            weights["ml_high_value"] = float(weights.get("ml_high_value", 0.0)) + learning_rate * error * features["high_value"]
            weights["ml_docs"] = float(weights.get("ml_docs", 0.0)) + learning_rate * error * features["docs_ref"]
            weights["ml_allowed"] = float(weights.get("ml_allowed", 0.0)) + learning_rate * error * features["allowed_ref"]
            weights["ml_prev_bug"] = float(weights.get("ml_prev_bug", 0.0)) + learning_rate * error * features["prev_bug_ref"]
            weights["ml_related_assets"] = float(weights.get("ml_related_assets", 0.0)) + learning_rate * error * features["related_assets"]
            weights["ml_out_scope"] = float(weights.get("ml_out_scope", 0.0)) + learning_rate * error * features["out_scope"]
            labeled_samples += 1

        next_version = int(meta.get("version", 0))
        total_samples = int(meta.get("sample_count", 0))
        if labeled_samples > 0:
            next_version += 1
            total_samples += labeled_samples
            _save_state(
                conn,
                project_key,
                weights=weights,
                version=next_version,
                sample_count=total_samples,
            )
            _save_state(
                conn,
                MODEL_KEY_GLOBAL,
                weights=weights,
                version=next_version,
                sample_count=total_samples,
            )
        conn.commit()

    return {
        "run_id": run_id,
        "db_path": model_db_path(),
        "project_key": _safe_project_key(project_key),
        "scored_targets_logged": len(scored_targets),
        "labeled_samples": labeled_samples,
        "model_version_before": int(meta.get("version", 0)),
        "model_version_after": next_version,
        "sample_count_after": int(meta.get("sample_count", 0)) + labeled_samples,
        "auto_findings_seen": finding_total,
        "review_findings_seen": review_total,
    }
