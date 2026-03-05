"""Program intake and internet context discovery."""

from __future__ import annotations

from dataclasses import dataclass
import csv
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import re
import hashlib
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Any, Callable
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen

from bug_bounty_agent.lpoint import load_model_weights

TAB_SUFFIXES = [
    "",  # Program guidelines
    "policy_scopes",  # Scope
    "hacktivity",
    "thanks",
    "updates",
    "collaborators",
    "safe_harbor",
]

ProgressHook = Callable[[int, str], None]


def _progress(hook: ProgressHook | None, pct: int, message: str) -> None:
    if not hook:
        return
    try:
        hook(max(0, min(100, pct)), message)
    except Exception:
        return


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.text_parts: list[str] = []
        self._capture_text = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value:
                    self.links.append(value)
        if tag in {"script", "style"}:
            self._capture_text = False

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._capture_text = True

    def handle_data(self, data: str) -> None:
        if self._capture_text:
            text = " ".join(data.split())
            if text:
                self.text_parts.append(text)


@dataclass
class DiscoveryData:
    project_url: str
    project_key: str
    platform: str
    program_handle: str | None
    candidate_policy_links: list[str]
    candidate_scope_links: list[str]
    candidate_doc_links: list[str]
    previous_bug_links: list[str]
    social_discussion_links: list[str]
    domain_candidates: list[str]
    in_scope_domains: list[str]
    out_scope_domains: list[str]
    downloaded_files: list[str]
    downloaded_artifact_reasons: list[str]
    tab_links: list[str]
    allowed_scope_signals: list[str]
    out_scope_signals: list[str]
    non_web_in_scope_assets: list[str]
    non_web_out_scope_assets: list[str]
    normalized_scope_assets: list[dict]
    recon_flow: dict[str, Any]
    sources: list[str]

    def as_prompt(self) -> str:
        return (
            f"Project URL: {self.project_url}\n"
            f"Policy links: {self.candidate_policy_links}\n"
            f"Scope links: {self.candidate_scope_links}\n"
            f"Documentation links: {self.candidate_doc_links}\n"
            f"Domains in scope (candidates): {self.domain_candidates}\n"
            f"Domains in scope (parsed): {self.in_scope_domains}\n"
            f"Domains out of scope (parsed): {self.out_scope_domains}\n"
            f"Downloaded files: {self.downloaded_files}\n"
            f"Downloaded artifact reasons: {self.downloaded_artifact_reasons}\n"
            f"Allowed scope signals: {self.allowed_scope_signals}\n"
            f"Out-of-scope signals: {self.out_scope_signals}\n"
            f"Non-web in-scope assets: {self.non_web_in_scope_assets}\n"
            f"Non-web out-of-scope assets: {self.non_web_out_scope_assets}\n"
            f"Normalized scope assets: {self.normalized_scope_assets[:20]}\n"
            f"Recon flow: {self.recon_flow}\n"
            f"Previous bug links: {self.previous_bug_links}\n"
            f"Social/public discussions: {self.social_discussion_links}\n"
            "Create an actionable bug bounty plan with completed vs pending phases."
        )


def _is_high_value_target(target: str) -> bool:
    low = target.lower()
    return any(token in low for token in ("api", "auth", "admin", "account", "billing", "pay", "upload"))


def _score_target(
    target: str,
    in_scope_domains: list[str],
    out_scope_domains: list[str],
    candidate_doc_links: list[str],
    allowed_scope_signals: list[str],
    previous_bug_links: list[str],
    normalized_scope_assets: list[dict],
    model_weights: dict[str, float],
) -> dict[str, Any]:
    evidence: list[str] = []
    confidence = 10
    exposure = 15
    priority = 20
    out = target in out_scope_domains
    in_scope = target in in_scope_domains

    if in_scope:
        evidence.append("in_scope_artifact")
        confidence += 40
        priority += 20
    if out:
        evidence.append("out_of_scope_artifact")
        confidence = max(0, confidence - 50)
        priority = 0
    if _is_high_value_target(target):
        evidence.append("high_value_token_match")
        exposure += 35
        priority += 30
    if any(target in link.lower() for link in candidate_doc_links):
        evidence.append("docs_reference")
        confidence += 8
        priority += 6
    if any(target in signal.lower() for signal in allowed_scope_signals):
        evidence.append("allowed_scope_signal")
        confidence += 12
        priority += 8
    if any(target in link.lower() for link in previous_bug_links):
        evidence.append("previous_bug_context")
        exposure += 10
        priority += 6

    related_assets = 0
    for asset in normalized_scope_assets:
        domains = [str(item).lower() for item in asset.get("normalized_domains", [])]
        if target.lower() in domains:
            related_assets += 1
    if related_assets:
        evidence.append("normalized_scope_assets")
        confidence += min(18, related_assets * 3)
        priority += min(15, related_assets * 2)

    features = {
        "in_scope": 1.0 if in_scope else 0.0,
        "out_of_scope": 1.0 if out else 0.0,
        "high_value": 1.0 if _is_high_value_target(target) else 0.0,
        "docs_reference": 1.0 if "docs_reference" in evidence else 0.0,
        "allowed_scope_signal": 1.0 if "allowed_scope_signal" in evidence else 0.0,
        "previous_bug_context": 1.0 if "previous_bug_context" in evidence else 0.0,
        "related_assets": min(1.0, related_assets / 5.0) if related_assets else 0.0,
    }
    ml_logit = float(model_weights.get("ml_bias", 0.0))
    ml_logit += float(model_weights.get("ml_in_scope", 0.0)) * features["in_scope"]
    ml_logit += float(model_weights.get("ml_high_value", 0.0)) * features["high_value"]
    ml_logit += float(model_weights.get("ml_docs", 0.0)) * features["docs_reference"]
    ml_logit += float(model_weights.get("ml_allowed", 0.0)) * features["allowed_scope_signal"]
    ml_logit += float(model_weights.get("ml_prev_bug", 0.0)) * features["previous_bug_context"]
    ml_logit += float(model_weights.get("ml_related_assets", 0.0)) * features["related_assets"]
    ml_logit += float(model_weights.get("ml_out_scope", 0.0)) * features["out_of_scope"]
    ml_prob = 1.0 / (1.0 + pow(2.718281828, -ml_logit))
    ml_adjust = int(round((ml_prob - 0.5) * 24))
    priority += ml_adjust
    confidence += int(round(ml_adjust * 0.5))
    if ml_adjust >= 4:
        evidence.append("ml_rank_boost")
    elif ml_adjust <= -4:
        evidence.append("ml_rank_penalty")

    confidence = min(100, max(0, confidence))
    exposure = min(100, max(0, exposure))
    priority = min(100, max(0, priority))
    if out:
        exposure = 0

    return {
        "target": target,
        "in_scope": in_scope,
        "out_of_scope": out,
        "high_value": _is_high_value_target(target),
        "scores": {
            "confidence": confidence,
            "exposure": exposure,
            "priority": priority,
            "ml_probability": round(ml_prob, 4),
        },
        "features": features,
        "evidence": evidence,
    }


def _build_recon_flow(
    *,
    project_key: str,
    project_url: str,
    candidate_policy_links: list[str],
    candidate_scope_links: list[str],
    candidate_doc_links: list[str],
    downloaded_files: list[str],
    tab_links: list[str],
    in_scope_domains: list[str],
    out_scope_domains: list[str],
    domain_candidates: list[str],
    allowed_scope_signals: list[str],
    out_scope_signals: list[str],
    previous_bug_links: list[str],
    social_discussion_links: list[str],
    normalized_scope_assets: list[dict],
) -> dict[str, Any]:
    model = load_model_weights(project_key)
    model_weights = dict(model.get("weights", {}))
    model_meta = dict(model.get("meta", {}))
    policy_pass = bool(candidate_policy_links or candidate_scope_links or downloaded_files)
    scope_pass = bool(in_scope_domains or normalized_scope_assets)
    policy_gate = {
        "status": "pass" if (policy_pass and scope_pass) else "partial",
        "checks": [
            {"name": "policy_links_present", "ok": bool(candidate_policy_links)},
            {"name": "scope_links_present", "ok": bool(candidate_scope_links)},
            {"name": "scope_artifacts_present", "ok": bool(downloaded_files)},
            {"name": "in_scope_assets_present", "ok": bool(in_scope_domains or normalized_scope_assets)},
        ],
    }

    collection = {
        "searching_platform": {
            "policy_links": len(candidate_policy_links),
            "scope_links": len(candidate_scope_links),
            "tab_links": len(tab_links),
        },
        "files_on_platform": {"downloaded_artifacts": len(downloaded_files)},
        "available_internet_info": {
            "docs_links": len(candidate_doc_links),
            "previous_bug_links": len(previous_bug_links),
        },
        "social_platform_discussions": {
            "social_links": len(social_discussion_links),
        },
    }

    unique_candidates: list[str] = []
    for item in domain_candidates + in_scope_domains:
        if item and item not in unique_candidates and item not in {"hackerone.com", "www.hackerone.com"}:
            unique_candidates.append(item)
    in_scope_unique = [d for d in unique_candidates if d in in_scope_domains and d not in out_scope_domains]
    normalization = {
        "candidate_domains_raw": len(domain_candidates),
        "candidate_domains_deduplicated": len(unique_candidates),
        "normalized_scope_assets": len(normalized_scope_assets),
        "in_scope_domains_deduplicated": len(in_scope_unique),
        "out_scope_domains_deduplicated": len(set(out_scope_domains)),
        "allowed_scope_signals": len(allowed_scope_signals),
        "out_scope_signals": len(out_scope_signals),
    }

    scored = [
        _score_target(
            target=target,
            in_scope_domains=in_scope_domains,
            out_scope_domains=out_scope_domains,
            candidate_doc_links=candidate_doc_links,
            allowed_scope_signals=allowed_scope_signals,
            previous_bug_links=previous_bug_links,
            normalized_scope_assets=normalized_scope_assets,
            model_weights=model_weights,
        )
        for target in unique_candidates
    ]
    scored.sort(
        key=lambda item: (
            item["out_of_scope"],
            -int(item["scores"]["priority"]),
            -int(item["scores"]["confidence"]),
            item["target"],
        )
    )
    prioritized_targets = [item for item in scored if not item["out_of_scope"]][:20]
    prioritization = {
        "total_candidates_scored": len(scored),
        "high_value_candidates": sum(1 for item in scored if item["high_value"] and not item["out_of_scope"]),
        "top_targets": prioritized_targets[:10],
    }

    safe_validation = {
        "mode": "non_destructive_only",
        "guardrails": [
            "in_scope_only",
            "respect_program_rate_limits",
            "no_auth_bypass_or_dos",
            "evidence_capture_required",
        ],
        "target_count": len(prioritized_targets[:10]),
    }
    test_queue = [
        {
            "target": item["target"],
            "priority": item["scores"]["priority"],
            "confidence": item["scores"]["confidence"],
            "reason": ", ".join(item["evidence"][:3]) or "scored_candidate",
        }
        for item in prioritized_targets[:10]
    ]
    deliverables = {
        "prioritized_target_list": len(prioritized_targets),
        "test_queue_items": len(test_queue),
        "report_ready_evidence": {
            "policy_sources": len(candidate_policy_links) + len(candidate_scope_links),
            "scope_artifacts": len(downloaded_files),
            "internet_context_links": len(candidate_doc_links) + len(previous_bug_links),
            "social_context_links": len(social_discussion_links),
        },
    }

    return {
        "pipeline_version": "bugbounty-recon-v2",
        "project_url": project_url,
        "model": {
            "source": model_meta.get("source"),
            "version": model_meta.get("version"),
            "sample_count": model_meta.get("sample_count"),
            "updated_at": model_meta.get("updated_at"),
            "db_path": model.get("db_path"),
        },
        "stages": {
            "scope_policy_check": policy_gate,
            "recon_collection": collection,
            "normalize_correlate": normalization,
            "prioritize": prioritization,
            "safe_validation": safe_validation,
            "deliverables": deliverables,
            "learning_point": {
                "enabled": True,
                "mode": "online_learning",
                "training_source": "automated_findings_status",
            },
        },
        "prioritized_targets": prioritized_targets,
        "scored_targets": scored[:100],
        "test_queue": test_queue,
    }


def _fetch(url: str, timeout: int = 12) -> str:
    last_error: Exception | None = None
    for _ in range(4):
        req = Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/123.0 Safari/537.36"
                )
            },
        )
        try:
            with urlopen(req, timeout=timeout) as response:
                raw = response.read(350_000)
            return raw.decode("utf-8", errors="ignore")
        except Exception as exc:
            last_error = exc
            time.sleep(1.0)
    if last_error:
        raise last_error
    return ""


def _download_file(url: str, target_dir: Path, timeout: int = 20) -> str | None:
    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0 Safari/537.36"
            )
        },
    )
    content_disposition = ""
    content_type = ""
    payload = b""
    success = False
    for _ in range(4):
        try:
            with urlopen(req, timeout=timeout) as response:
                content_disposition = response.headers.get("Content-Disposition", "")
                content_type = (response.headers.get("Content-Type", "") or "").lower()
                payload = response.read(8_000_000)
            success = True
            break
        except Exception:
            time.sleep(1.0)

    if not success:
        fallback = _download_file_with_curl(url, target_dir)
        if fallback:
            return fallback
        return None

    if not payload:
        fallback = _download_file_with_curl(url, target_dir)
        if fallback:
            return fallback
        return None
    if "attachment" not in content_disposition.lower() and "text/csv" not in content_type and "json" not in content_type:
        fallback = _download_file_with_curl(url, target_dir)
        if fallback:
            return fallback
        return None

    filename = None
    match = re.search(r'filename="([^"]+)"', content_disposition)
    if match:
        filename = match.group(1)
    if not filename:
        filename = Path(urlparse(url).path).name or "download.bin"

    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / filename
    out_file.write_bytes(payload)
    return str(out_file)


def _download_file_with_curl(url: str, target_dir: Path) -> str | None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        result = None
        header_path = Path(tmpdir) / "headers.txt"
        body_path = Path(tmpdir) / "body.bin"
        for _ in range(4):
            cmd = [
                "curl",
                "-sL",
                "--retry",
                "4",
                "--retry-all-errors",
                "--retry-delay",
                "1",
                "-D",
                str(header_path),
                "-o",
                str(body_path),
                url,
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            except Exception:
                return None
            if result.returncode == 0 and body_path.exists() and body_path.stat().st_size > 0:
                break
            time.sleep(1.0)
        if result is None or result.returncode != 0 or not body_path.exists() or body_path.stat().st_size == 0:
            return None

        headers_text = header_path.read_text(encoding="utf-8", errors="ignore")
        lower_headers = headers_text.lower()
        if (
            "content-disposition: attachment" not in lower_headers
            and "content-type: text/csv" not in lower_headers
            and "content-type: application/json" not in lower_headers
        ):
            return None

        filename = None
        for line in headers_text.splitlines():
            if line.lower().startswith("content-disposition:"):
                match = re.search(r'filename="([^"]+)"', line)
                if match:
                    filename = match.group(1)
                    break
        if not filename:
            filename = Path(urlparse(url).path).name or "download.bin"

        out_file = target_dir / filename
        out_file.write_bytes(body_path.read_bytes())
        return str(out_file)


def _artifact_meta_file(download_dir: Path) -> Path:
    return download_dir / "artifact_meta.json"


def _load_artifact_meta(download_dir: Path) -> dict[str, dict]:
    path = _artifact_meta_file(download_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_artifact_meta(download_dir: Path, data: dict[str, dict]) -> None:
    path = _artifact_meta_file(download_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1_048_576)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _head_headers(url: str, timeout: int = 10) -> dict[str, str]:
    req = Request(
        url=url,
        method="HEAD",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0 Safari/537.36"
            )
        },
    )
    try:
        with urlopen(req, timeout=timeout) as response:
            return {
                "etag": str(response.headers.get("ETag", "") or "").strip(),
                "last_modified": str(response.headers.get("Last-Modified", "") or "").strip(),
                "content_length": str(response.headers.get("Content-Length", "") or "").strip(),
                "content_type": str(response.headers.get("Content-Type", "") or "").strip(),
            }
    except Exception:
        return {}


def _resolve_artifact(
    *,
    url: str,
    download_dir: Path,
    cache_pattern: str,
    reason_label: str,
) -> tuple[str | None, str | None]:
    meta_all = _load_artifact_meta(download_dir)
    meta = meta_all.get(url, {}) if isinstance(meta_all.get(url, {}), dict) else {}
    cached = _find_cached_artifact(download_dir, cache_pattern)
    head = _head_headers(url)

    if cached and head:
        same_etag = bool(meta.get("etag")) and str(meta.get("etag")) == str(head.get("etag"))
        same_last = bool(meta.get("last_modified")) and str(meta.get("last_modified")) == str(head.get("last_modified"))
        same_len = bool(head.get("content_length")) and str(head.get("content_length")) == str(Path(cached).stat().st_size)
        if same_etag or same_last or same_len:
            return cached, f"{cached} <- {url} ({reason_label}; cached not modified)"

    downloaded = _download_file(url, download_dir)
    if downloaded:
        path = Path(downloaded)
        meta_all[url] = {
            "path": downloaded,
            "etag": str(head.get("etag", "") or ""),
            "last_modified": str(head.get("last_modified", "") or ""),
            "content_length": str(path.stat().st_size),
            "content_type": str(head.get("content_type", "") or ""),
            "sha256": _sha256_file(path),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_artifact_meta(download_dir, meta_all)
        source_hint = "updated download" if cached else "fresh download"
        return downloaded, f"{downloaded} <- {url} ({reason_label}; {source_hint})"

    if cached:
        return cached, f"{cached} <- {url} ({reason_label}; cached fallback)"
    return None, None


def _classify_links(links: list[str]) -> tuple[list[str], list[str], list[str]]:
    policy: list[str] = []
    scope: list[str] = []
    docs: list[str] = []
    seen: set[str] = set()

    for link in links:
        if not link.startswith("http"):
            continue
        if link in seen:
            continue
        seen.add(link)

        low = link.lower()
        if any(k in low for k in ("policy", "guideline", "safe-harbor", "rules", "legal")):
            policy.append(link)
        if any(k in low for k in ("scope", "asset", "target", "in-scope", "out-of-scope")):
            scope.append(link)
        if any(k in low for k in ("docs", "documentation", "api", "developer", "graphql")):
            docs.append(link)

    return policy[:8], scope[:8], docs[:8]


def _extract_domains_from_text(text: str) -> list[str]:
    pattern = re.compile(r"\b(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    domains: list[str] = []
    for found in pattern.findall(text):
        item = found.lower().strip(".")
        if item.startswith("www."):
            item = item[4:]
        if item not in domains:
            domains.append(item)
    return domains[:30]


def _search_generic(queries: list[str], limit: int = 12) -> list[str]:
    found: list[str] = []
    for query in queries:
        try:
            html = _fetch(f"https://duckduckgo.com/html/?q={quote_plus(query)}")
            parser = _LinkParser()
            parser.feed(html)
            for link in parser.links:
                if link.startswith("http") and link not in found:
                    found.append(link)
                if len(found) >= limit:
                    break
        except Exception:
            continue
        if len(found) >= limit:
            break
    return found[:limit]


def _search_previous_bugs(project_url: str) -> list[str]:
    domain = urlparse(project_url).netloc or project_url
    queries = [
        f"site:hackerone.com {domain} report",
        f"{domain} bug bounty writeup",
        f"{domain} vulnerability disclosure bug bounty",
    ]
    return _search_generic(queries, limit=15)


def _search_social_discussions(project_url: str) -> list[str]:
    domain = urlparse(project_url).netloc or project_url
    queries = [
        f"site:reddit.com {domain} bug bounty",
        f"site:x.com {domain} bug bounty",
        f"site:twitter.com {domain} bug bounty",
        f"discord {domain} bug bounty",
    ]
    return _search_generic(queries, limit=15)


def _extract_h1_handle(project_url: str) -> str | None:
    parsed = urlparse(project_url)
    if parsed.netloc.lower() != "hackerone.com":
        return None
    segments = [seg for seg in parsed.path.split("/") if seg]
    if not segments:
        return None
    handle = segments[0].strip().lower()
    # Ignore non-program common routes.
    if handle in {
        "hackers",
        "teams",
        "users",
        "reports",
        "notifications",
        "settings",
        "directory",
        "programs",
        "opportunities",
    }:
        return None
    return handle


def _normalize_handle_hint(hint: str | None) -> str | None:
    if not hint:
        return None
    raw = hint.strip().lower()
    if not raw:
        return None
    # Accept full HackerOne URL as hint.
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        parts = [seg for seg in parsed.path.split("/") if seg]
        if parts:
            raw = parts[0].lower()
    # Normalize spaces/symbols to handle-like token.
    raw = re.sub(r"[^a-z0-9_-]+", "-", raw).strip("-")
    return raw or None


def _extract_domains_from_csv(path: Path) -> tuple[list[str], list[str], list[str], list[str]]:
    in_scope: list[str] = []
    out_scope: list[str] = []
    allowed_signals: list[str] = []
    blocked_signals: list[str] = []
    if not path.exists():
        return in_scope, out_scope, allowed_signals, blocked_signals
    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                ident = (row.get("identifier") or "").strip()
                asset_type = (row.get("asset_type") or "").strip().upper()
                instruction = (row.get("instruction") or "").strip().lower()
                eligible_sub = (row.get("eligible_for_submission") or "").strip().lower()
                eligible_bounty = (row.get("eligible_for_bounty") or "").strip().lower()

                domains = _extract_domains_from_identifier(
                    ident,
                    asset_type=asset_type,
                    allow_host_widening=not _is_path_specific_identifier(ident),
                )
                is_out = (
                    eligible_sub == "false"
                    or eligible_bounty == "false"
                    or "out of scope" in instruction
                    or "excluded" in instruction
                )
                if domains:
                    signal_value = ", ".join(domains[:3])
                else:
                    signal_value = ident[:120] if ident else "unlabeled asset"
                if asset_type:
                    signal_value = f"{signal_value} [{asset_type}]"
                if is_out:
                    blocked = f"{signal_value} (submission={eligible_sub or 'n/a'}, bounty={eligible_bounty or 'n/a'})"
                    if blocked not in blocked_signals:
                        blocked_signals.append(blocked)
                else:
                    allowed = f"{signal_value} (submission={eligible_sub or 'n/a'}, bounty={eligible_bounty or 'n/a'})"
                    if allowed not in allowed_signals:
                        allowed_signals.append(allowed)

                if not domains:
                    continue
                target = out_scope if is_out else in_scope
                for domain in domains:
                    if domain not in target:
                        target.append(domain)
    except Exception:
        return in_scope, out_scope, allowed_signals, blocked_signals
    return in_scope[:100], out_scope[:100], allowed_signals[:50], blocked_signals[:50]


def _normalize_scope_status(*, eligible_submission: str, eligible_bounty: str, instruction: str, source_state: str | None = None) -> str:
    if source_state in {"include", "exclude"}:
        return "in-scope" if source_state == "include" else "out-of-scope"
    if eligible_submission == "false" or eligible_bounty == "false":
        return "out-of-scope"
    low_instruction = (instruction or "").lower()
    if "out of scope" in low_instruction or "excluded" in low_instruction:
        return "out-of-scope"
    return "in-scope"


def _normalize_asset_category(asset_type: str, identifier: str) -> str:
    normalized = (asset_type or "").strip().upper()
    raw = (identifier or "").strip().lower()
    if normalized in {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"}:
        return "mobile_app"
    if raw.startswith(("http://", "https://")) or normalized in {"URL", "BURP_SCOPE"}:
        return "web"
    if normalized:
        return normalized.lower()
    return "unknown"


def _normalize_scope_asset(
    *,
    identifier: str,
    asset_type: str,
    source: str,
    scope_status: str,
    instruction: str = "",
    eligible_submission: str = "",
    eligible_bounty: str = "",
    host: str = "",
    protocol: str = "",
    port: str = "",
    file_pattern: str = "",
    max_severity: str = "",
) -> dict:
    raw_identifier = (identifier or "").strip()
    category = _normalize_asset_category(asset_type, raw_identifier)
    normalized_domains = _extract_domains_from_identifier(
        raw_identifier if raw_identifier else host,
        asset_type=asset_type,
        allow_host_widening=not _is_path_specific_identifier(raw_identifier or host),
    )

    normalized_hosts: list[str] = []
    candidate_hosts = [host, raw_identifier]
    for candidate in candidate_hosts:
        value = (candidate or "").strip()
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            value = (parsed.hostname or "").lower().strip(".")
        value = value.replace("\\.", ".").replace("^", "").replace("$", "").strip(".")
        if value.startswith("*."):
            value = value[2:]
        if value and re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", value) and value not in normalized_hosts:
            normalized_hosts.append(value)

    path = ""
    if raw_identifier.startswith(("http://", "https://")):
        parsed = urlparse(raw_identifier)
        path = parsed.path or "/"
    elif file_pattern:
        path = file_pattern

    return {
        "value": raw_identifier or host,
        "asset_type": (asset_type or "").strip().upper() or "UNKNOWN",
        "asset_category": category,
        "scope_status": scope_status,
        "source": source,
        "normalized_hosts": normalized_hosts,
        "normalized_domains": normalized_domains,
        "host": normalized_hosts[0] if normalized_hosts else "",
        "protocol": (protocol or "").strip().lower(),
        "port": (port or "").strip(),
        "path": path,
        "eligible_for_submission": eligible_submission,
        "eligible_for_bounty": eligible_bounty,
        "max_severity": (max_severity or "").strip().lower(),
        "instruction": " ".join((instruction or "").split())[:300],
    }


def _merge_scope_assets(assets: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str, str, str, str], dict] = {}
    for asset in assets:
        key = (
            str(asset.get("value") or ""),
            str(asset.get("asset_type") or ""),
            str(asset.get("scope_status") or ""),
            str(asset.get("host") or ""),
            str(asset.get("path") or ""),
        )
        if key not in merged:
            item = dict(asset)
            item["sources"] = [asset.get("source")] if asset.get("source") else []
            merged[key] = item
            continue
        existing = merged[key]
        for field in ("normalized_hosts", "normalized_domains", "sources"):
            combined = list(existing.get(field, []))
            for value in asset.get(field, []) if isinstance(asset.get(field), list) else []:
                if value not in combined:
                    combined.append(value)
            source_value = asset.get("source")
            if field == "sources" and source_value and source_value not in combined:
                combined.append(source_value)
            existing[field] = combined
        for field in ("instruction", "protocol", "port", "max_severity", "eligible_for_submission", "eligible_for_bounty"):
            if not existing.get(field) and asset.get(field):
                existing[field] = asset.get(field)
    out = list(merged.values())
    out.sort(key=lambda item: (
        str(item.get("scope_status") or ""),
        str(item.get("asset_category") or ""),
        str(item.get("value") or ""),
    ))
    return out


def _extract_scope_assets_from_csv(path: Path) -> list[dict]:
    assets: list[dict] = []
    if not path.exists():
        return assets
    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                identifier = (row.get("identifier") or "").strip()
                asset_type = (row.get("asset_type") or "").strip().upper()
                instruction = (row.get("instruction") or "").strip()
                eligible_sub = (row.get("eligible_for_submission") or "").strip().lower()
                eligible_bounty = (row.get("eligible_for_bounty") or "").strip().lower()
                max_severity = (row.get("max_severity") or "").strip()
                if not identifier:
                    continue
                assets.append(
                    _normalize_scope_asset(
                        identifier=identifier,
                        asset_type=asset_type,
                        source="hackerone_csv",
                        scope_status=_normalize_scope_status(
                            eligible_submission=eligible_sub,
                            eligible_bounty=eligible_bounty,
                            instruction=instruction,
                        ),
                        instruction=instruction,
                        eligible_submission=eligible_sub,
                        eligible_bounty=eligible_bounty,
                        max_severity=max_severity,
                    )
                )
    except Exception:
        return assets
    return assets


def _extract_scope_assets_from_burp_json(path: Path) -> list[dict]:
    assets: list[dict] = []
    if not path.exists():
        return assets
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return assets
    target = data.get("target", {}).get("scope", {})
    include = target.get("include", []) if isinstance(target, dict) else []
    exclude = target.get("exclude", []) if isinstance(target, dict) else []
    for state, items in (("include", include), ("exclude", exclude)):
        for item in items if isinstance(items, list) else []:
            host = str(item.get("host", "")).replace("\\.", ".").replace("^", "").replace("$", "")
            protocol = str(item.get("protocol", ""))
            port = str(item.get("port", ""))
            file_pattern = str(item.get("file", "") or "")
            if not host:
                continue
            assets.append(
                _normalize_scope_asset(
                    identifier=host,
                    asset_type="BURP_SCOPE",
                    source="burp_scope_json",
                    scope_status=_normalize_scope_status(
                        eligible_submission="",
                        eligible_bounty="",
                        instruction="",
                        source_state=state,
                    ),
                    host=host,
                    protocol=protocol,
                    port=port,
                    file_pattern=file_pattern,
                )
            )
    return assets


def _extract_domains_from_burp_json(path: Path) -> tuple[list[str], list[str], list[str], list[str]]:
    in_scope: list[str] = []
    out_scope: list[str] = []
    allowed_signals: list[str] = []
    blocked_signals: list[str] = []
    if not path.exists():
        return in_scope, out_scope, allowed_signals, blocked_signals
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return in_scope, out_scope, allowed_signals, blocked_signals
    target = data.get("target", {}).get("scope", {})
    include = target.get("include", []) if isinstance(target, dict) else []
    exclude = target.get("exclude", []) if isinstance(target, dict) else []

    for item in include if isinstance(include, list) else []:
        host = str(item.get("host", ""))
        file_pattern = str(item.get("file", "") or "")
        domains = _extract_domains_from_identifier(
            host.replace("\\.", ".").replace("^", "").replace("$", ""),
            asset_type="BURP_SCOPE",
            allow_host_widening=_is_global_burp_file_scope(file_pattern),
        )
        if domains:
            signal = f"{', '.join(domains[:3])} (Burp include)"
            if signal not in allowed_signals:
                allowed_signals.append(signal)
        for domain in domains:
            if domain not in in_scope:
                in_scope.append(domain)
    for item in exclude if isinstance(exclude, list) else []:
        host = str(item.get("host", ""))
        file_pattern = str(item.get("file", "") or "")
        domains = _extract_domains_from_identifier(
            host.replace("\\.", ".").replace("^", "").replace("$", ""),
            asset_type="BURP_SCOPE",
            allow_host_widening=_is_global_burp_file_scope(file_pattern),
        )
        if domains:
            signal = f"{', '.join(domains[:3])} (Burp exclude)"
            if signal not in blocked_signals:
                blocked_signals.append(signal)
        for domain in domains:
            if domain not in out_scope:
                out_scope.append(domain)
    return in_scope[:100], out_scope[:100], allowed_signals[:50], blocked_signals[:50]


def _extract_non_web_assets_from_csv(path: Path) -> tuple[list[str], list[str]]:
    in_scope: list[str] = []
    out_scope: list[str] = []
    if not path.exists():
        return in_scope, out_scope
    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                ident = (row.get("identifier") or "").strip()
                asset_type = (row.get("asset_type") or "").strip().upper()
                if not ident or _asset_type_supports_web_targets(asset_type):
                    continue
                eligible_sub = (row.get("eligible_for_submission") or "").strip().lower()
                eligible_bounty = (row.get("eligible_for_bounty") or "").strip().lower()
                instruction = (row.get("instruction") or "").strip().lower()
                is_out = (
                    eligible_sub == "false"
                    or eligible_bounty == "false"
                    or "out of scope" in instruction
                    or "excluded" in instruction
                )
                label = f"{ident} [{asset_type}]"
                target = out_scope if is_out else in_scope
                if label not in target:
                    target.append(label)
    except Exception:
        return in_scope, out_scope
    return in_scope[:50], out_scope[:50]


def _extract_scope_signals_from_text(text: str) -> tuple[list[str], list[str]]:
    allowed: list[str] = []
    blocked: list[str] = []
    chunks = re.split(r"[\n\r\.]", text)
    for chunk in chunks:
        line = " ".join(chunk.strip().split())
        if not line:
            continue
        low = line.lower()
        if any(k in low for k in ("allowed", "in scope", "eligible", "permitted")):
            if line not in allowed:
                allowed.append(line[:180])
        if any(k in low for k in ("out of scope", "not allowed", "excluded", "disallowed", "prohibited")):
            if line not in blocked:
                blocked.append(line[:180])
    return allowed[:40], blocked[:40]


def _asset_type_supports_web_targets(asset_type: str) -> bool:
    normalized = (asset_type or "").strip().upper()
    if not normalized:
        return True
    return normalized not in {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"}


def _extract_domains_from_identifier(identifier: str, asset_type: str, allow_host_widening: bool) -> list[str]:
    if not identifier or not _asset_type_supports_web_targets(asset_type):
        return []
    if not allow_host_widening:
        return []

    raw = identifier.strip()
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        return [host] if host else []

    return _extract_domains_from_text(raw)


def _is_path_specific_identifier(identifier: str) -> bool:
    raw = (identifier or "").strip()
    if not raw.startswith(("http://", "https://")):
        return False
    parsed = urlparse(raw)
    path = (parsed.path or "").strip()
    return bool(path and path not in {"", "/"})


def _is_global_burp_file_scope(file_pattern: str) -> bool:
    normalized = (file_pattern or "").strip()
    if not normalized:
        return True
    return normalized in {"^/.*", "^/.*$", "^.*$", ".*", "/.*", "^/$"}


def _find_cached_artifact(download_dir: Path, pattern: str) -> str | None:
    matches = sorted(
        download_dir.glob(pattern),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )
    for match in matches:
        if match.is_file() and match.stat().st_size > 0:
            return str(match)
    return None


def discover_project_context(
    project_url: str,
    program_hint: str | None = None,
    progress_hook: ProgressHook | None = None,
) -> DiscoveryData:
    _progress(progress_hook, 12, "Resolving project handle and fetching main page")
    parsed = urlparse(project_url)
    handle = _extract_h1_handle(project_url) or _normalize_handle_hint(program_hint)
    project_key = handle or (parsed.netloc or project_url).replace("www.", "").strip("/")
    platform = "hackerone" if parsed.netloc.lower() == "hackerone.com" else parsed.netloc.lower()

    links: list[str] = []
    page_text = ""
    try:
        html = _fetch(project_url)
        parser = _LinkParser()
        parser.feed(html)
        links.extend(parser.links)
        page_text = " ".join(parser.text_parts)
    except Exception:
        pass

    _progress(progress_hook, 20, "Classifying policy/scope/document links")
    policy, scope, docs = _classify_links(links)

    tab_links: list[str] = []
    downloaded_files: list[str] = []
    downloaded_artifact_reasons: list[str] = []
    in_scope_domains: list[str] = []
    out_scope_domains: list[str] = []
    allowed_scope_signals: list[str] = []
    out_scope_signals: list[str] = []
    non_web_in_scope_assets: list[str] = []
    non_web_out_scope_assets: list[str] = []
    normalized_scope_assets: list[dict] = []

    if handle:
        _progress(progress_hook, 28, f"Program handle detected: {handle}")
        base = f"https://hackerone.com/{handle}"
        tab_links = [base if not suf else f"{base}/{suf}" for suf in TAB_SUFFIXES]
        download_dir = Path(".bug_bounty_agent/downloads") / project_key
        _progress(progress_hook, 34, "Downloading scope CSV artifact")
        csv_url = f"https://hackerone.com/teams/{handle}/assets/download_csv.csv"
        csv_file, csv_reason = _resolve_artifact(
            url=csv_url,
            download_dir=download_dir,
            cache_pattern=f"scopes_for_{handle}_*.csv",
            reason_label="scope inventory",
        )
        _progress(progress_hook, 40, "Downloading Burp scope JSON artifact")
        burp_url = f"https://hackerone.com/teams/{handle}/assets/download_burp_project_file.json"
        burp_file, burp_reason = _resolve_artifact(
            url=burp_url,
            download_dir=download_dir,
            cache_pattern=f"{handle}-*.json",
            reason_label="include/exclude scope rules",
        )
        for path in [csv_file, burp_file]:
            if path:
                downloaded_files.append(path)
                if path == csv_file and csv_reason:
                    downloaded_artifact_reasons.append(csv_reason)
                if path == burp_file and burp_reason:
                    downloaded_artifact_reasons.append(burp_reason)

        if csv_file:
            _progress(progress_hook, 48, "Parsing CSV scope artifact")
            csv_in, csv_out, csv_allow, csv_block = _extract_domains_from_csv(Path(csv_file))
            csv_non_web_in, csv_non_web_out = _extract_non_web_assets_from_csv(Path(csv_file))
            normalized_scope_assets.extend(_extract_scope_assets_from_csv(Path(csv_file)))
            for d in csv_in:
                if d not in in_scope_domains:
                    in_scope_domains.append(d)
            for d in csv_out:
                if d not in out_scope_domains:
                    out_scope_domains.append(d)
            for s in csv_allow:
                if s not in allowed_scope_signals:
                    allowed_scope_signals.append(s)
            for s in csv_block:
                if s not in out_scope_signals:
                    out_scope_signals.append(s)
            for item in csv_non_web_in:
                if item not in non_web_in_scope_assets:
                    non_web_in_scope_assets.append(item)
            for item in csv_non_web_out:
                if item not in non_web_out_scope_assets:
                    non_web_out_scope_assets.append(item)

        if burp_file:
            _progress(progress_hook, 54, "Parsing Burp JSON scope artifact")
            b_in, b_out, b_allow, b_block = _extract_domains_from_burp_json(Path(burp_file))
            normalized_scope_assets.extend(_extract_scope_assets_from_burp_json(Path(burp_file)))
            for d in b_in:
                if d not in in_scope_domains:
                    in_scope_domains.append(d)
            for d in b_out:
                if d not in out_scope_domains:
                    out_scope_domains.append(d)
            for s in b_allow:
                if s not in allowed_scope_signals:
                    allowed_scope_signals.append(s)
            for s in b_block:
                if s not in out_scope_signals:
                    out_scope_signals.append(s)

        tab_text: list[str] = []
        total_tabs = len(tab_links) if tab_links else 1
        for tab in tab_links:
            try:
                tab_html = _fetch(tab)
                parser = _LinkParser()
                parser.feed(tab_html)
                links.extend(parser.links)
                tab_text.append(" ".join(parser.text_parts))
                tab_done = len(tab_text)
                pct = 58 + int((tab_done / total_tabs) * 16)
                _progress(progress_hook, pct, f"Processed program tab {tab_done}/{total_tabs}")
            except Exception:
                continue
        for text in tab_text:
            allow_txt, block_txt = _extract_scope_signals_from_text(text)
            for item in allow_txt:
                if item not in allowed_scope_signals:
                    allowed_scope_signals.append(item)
            for item in block_txt:
                if item not in out_scope_signals:
                    out_scope_signals.append(item)
        # Ensure policy/scope tab links are in candidates even when SPA hides link markup.
        for candidate in [base, f"{base}/policy_scopes"]:
            if candidate not in policy:
                policy.append(candidate)
            if candidate not in scope:
                scope.append(candidate)
    else:
        _progress(progress_hook, 30, "No program handle detected; using base page signals only")

    _progress(progress_hook, 80, "Searching prior bug reports and social context")
    previous_bugs = _search_previous_bugs(project_url)
    social_links = _search_social_discussions(project_url)
    _progress(progress_hook, 90, "Merging sources, normalizing data, and ranking targets")
    domain_candidates = _extract_domains_from_text(page_text + " " + " ".join(links))
    for d in in_scope_domains:
        if d not in domain_candidates:
            domain_candidates.append(d)
    domain_candidates = [d for d in domain_candidates if d not in {"hackerone.com", "www.hackerone.com"}]

    sources = [
        project_url,
        *tab_links,
        *policy,
        *scope,
        *docs,
        *downloaded_files,
        *previous_bugs,
        *social_links,
    ]
    uniq_sources: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if source and source not in seen:
            seen.add(source)
            uniq_sources.append(source)
    merged_scope_assets = _merge_scope_assets(normalized_scope_assets)[:250]
    recon_flow = _build_recon_flow(
        project_key=project_key,
        project_url=project_url,
        candidate_policy_links=policy,
        candidate_scope_links=scope,
        candidate_doc_links=docs,
        downloaded_files=downloaded_files,
        tab_links=tab_links,
        in_scope_domains=in_scope_domains,
        out_scope_domains=out_scope_domains,
        domain_candidates=domain_candidates,
        allowed_scope_signals=allowed_scope_signals,
        out_scope_signals=out_scope_signals,
        previous_bug_links=previous_bugs,
        social_discussion_links=social_links,
        normalized_scope_assets=merged_scope_assets,
    )
    _progress(progress_hook, 95, "Discovery complete")

    return DiscoveryData(
        project_url=project_url,
        project_key=project_key,
        platform=platform,
        program_handle=handle,
        candidate_policy_links=policy,
        candidate_scope_links=scope,
        candidate_doc_links=docs,
        previous_bug_links=previous_bugs,
        social_discussion_links=social_links,
        domain_candidates=domain_candidates,
        in_scope_domains=in_scope_domains,
        out_scope_domains=out_scope_domains,
        downloaded_files=downloaded_files,
        downloaded_artifact_reasons=downloaded_artifact_reasons,
        tab_links=tab_links,
        allowed_scope_signals=allowed_scope_signals[:60],
        out_scope_signals=out_scope_signals[:60],
        non_web_in_scope_assets=non_web_in_scope_assets[:60],
        non_web_out_scope_assets=non_web_out_scope_assets[:60],
        normalized_scope_assets=merged_scope_assets,
        recon_flow=recon_flow,
        sources=uniq_sources[:20],
    )
