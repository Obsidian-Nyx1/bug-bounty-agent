"""GitHub Models integration with security checks and multi-model consensus."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.request import Request, urlopen


CATALOG_ENDPOINT = "https://models.github.ai/catalog/models"
INFERENCE_ENDPOINT = "https://models.github.ai/inference/chat/completions"
ALLOWED_HOSTS = {"models.github.ai", "api.github.com"}


@dataclass
class ModelRun:
    model: str
    ok: bool
    content: str


@dataclass
class MultiModelResult:
    summary: str | None
    runs: list[ModelRun]
    notes: list[str]


def _is_safe_endpoint(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme == "https" and (parsed.hostname or "") in ALLOWED_HOSTS
    except Exception:
        return False


def _sanitize_prompt(prompt: str) -> str:
    clean = "".join(ch for ch in prompt if ch.isprintable() or ch in "\n\t ")
    return clean[:6000]


def _is_free_model(item: dict) -> tuple[bool, str]:
    pricing = item.get("pricing")
    if isinstance(pricing, dict):
        numeric = []
        for value in pricing.values():
            if isinstance(value, (int, float)):
                numeric.append(float(value))
        if numeric:
            return (all(v == 0.0 for v in numeric), "priced")
    free_flags = (
        item.get("isFree"),
        item.get("free"),
        item.get("free_tier"),
    )
    for flag in free_flags:
        if isinstance(flag, bool):
            return (flag, "flagged")
    return (True, "unknown")


def _get_catalog_models(token: str) -> tuple[list[str], list[str]]:
    req = Request(
        CATALOG_ENDPOINT,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    notes: list[str] = []
    with urlopen(req, timeout=20) as response:
        data = json.loads(response.read().decode("utf-8"))

    models: list[str] = []
    unknown_pricing = 0
    excluded_priced = 0
    for item in data if isinstance(data, list) else []:
        model_id = item.get("id")
        if not (isinstance(model_id, str) and model_id):
            continue
        allowed, reason = _is_free_model(item)
        if reason == "unknown":
            unknown_pricing += 1
        if not allowed:
            excluded_priced += 1
            continue
        models.append(model_id)
    if not models:
        notes.append("No models returned from GitHub catalog.")
    if excluded_priced:
        notes.append(f"Excluded {excluded_priced} priced model(s).")
    if unknown_pricing:
        notes.append(
            f"{unknown_pricing} model(s) had unknown pricing metadata and were treated as free-tier eligible."
        )
    return models, notes


def _infer_one(token: str, model: str, prompt: str) -> ModelRun:
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a bug bounty planning assistant. Return max 70 words with: "
                    "(1) what is done, (2) what is missing, (3) next best action."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    req = Request(
        INFERENCE_ENDPOINT,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urlopen(req, timeout=25) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        if not content:
            return ModelRun(model=model, ok=False, content="Empty model response.")
        return ModelRun(model=model, ok=True, content=content)
    except Exception as exc:
        return ModelRun(model=model, ok=False, content=f"{type(exc).__name__}: {exc}")


def summarize_with_github_models(prompt: str) -> MultiModelResult:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return MultiModelResult(
            summary=None,
            runs=[],
            notes=["GITHUB_TOKEN missing. Skipped GitHub Models inference."],
        )

    notes: list[str] = []
    if not (_is_safe_endpoint(CATALOG_ENDPOINT) and _is_safe_endpoint(INFERENCE_ENDPOINT)):
        return MultiModelResult(
            summary=None,
            runs=[],
            notes=["Security check failed for model endpoint host allowlist."],
        )

    models, catalog_notes = _get_catalog_models(token)
    notes.extend(catalog_notes)
    clean_prompt = _sanitize_prompt(prompt)
    if clean_prompt != prompt:
        notes.append("Prompt sanitized before model inference.")

    max_models_str = os.getenv("GITHUB_MODELS_MAX_MODELS", "0").strip()
    max_models = int(max_models_str) if max_models_str.isdigit() else 0
    selected = models if max_models <= 0 else models[:max_models]
    if not selected:
        return MultiModelResult(summary=None, runs=[], notes=notes)

    runs: list[ModelRun] = []
    for model in selected:
        runs.append(_infer_one(token, model, clean_prompt))

    good = [run for run in runs if run.ok and run.content]
    if not good:
        notes.append("No successful model responses.")
        return MultiModelResult(summary=None, runs=runs, notes=notes)

    # Simple consensus: take shortest successful answer for concise actionability.
    consensus = sorted(good, key=lambda r: len(r.content))[0].content
    notes.append(f"Ran {len(selected)} model(s) from GitHub catalog.")
    return MultiModelResult(summary=consensus, runs=runs, notes=notes)
