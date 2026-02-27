"""Scope parsing and domain recommendation logic."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"\b(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
NON_TARGET_DOMAINS = {
    "hackerone.com",
    "www.hackerone.com",
    "github.com",
    "www.github.com",
    "docs.github.com",
    "x.com",
    "www.x.com",
    "twitter.com",
    "www.twitter.com",
    "reddit.com",
    "www.reddit.com",
    "discord.com",
    "www.discord.com",
    "nextjs.org",
    "www.nextjs.org",
    "npmjs.com",
    "www.npmjs.com",
}


@dataclass
class ScopeData:
    in_scope: list[str]
    out_scope: list[str]
    raw_lines: list[str]


@dataclass
class DomainRecommendation:
    domain: str | None
    status: str
    reason: str
    allowed_tests: list[str]
    blocked_tests: list[str]


def parse_scope_file(scope_file: Path | None) -> ScopeData:
    if not scope_file or not scope_file.exists():
        return ScopeData(in_scope=[], out_scope=[], raw_lines=[])

    lines = scope_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    in_scope: list[str] = []
    out_scope: list[str] = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        found = DOMAIN_RE.findall(line)
        if not found:
            continue
        is_out = _line_is_out_scope(line)
        target = out_scope if is_out else in_scope
        for item in found:
            cleaned = item.lower().strip(".")
            if cleaned not in target:
                target.append(cleaned)

    return ScopeData(in_scope=in_scope, out_scope=out_scope, raw_lines=lines)


def merge_scope_sources(file_scope: ScopeData, discovered_in: list[str], discovered_out: list[str]) -> ScopeData:
    in_scope = list(file_scope.in_scope)
    out_scope = list(file_scope.out_scope)
    for item in discovered_in:
        low = item.lower()
        if low not in in_scope:
            in_scope.append(low)
    for item in discovered_out:
        low = item.lower()
        if low not in out_scope:
            out_scope.append(low)
    raw = list(file_scope.raw_lines)
    if discovered_in or discovered_out:
        raw.append("# discovered_from_program_downloads")
    return ScopeData(in_scope=in_scope, out_scope=out_scope, raw_lines=raw)


def recommend_domain(
    project_url: str,
    candidates: list[str],
    scope: ScopeData,
) -> DomainRecommendation:
    project_host = _normalize_domain(urlparse(project_url).hostname or "")
    project_root = _root_domain(project_host) if project_host else ""
    ordered: list[str] = []
    if project_host:
        ordered.append(project_host)
    for item in candidates:
        normalized = _normalize_domain(item)
        if normalized and normalized not in ordered:
            ordered.append(normalized)
    for item in scope.in_scope:
        normalized = _normalize_domain(item)
        if normalized and normalized not in ordered:
            ordered.append(normalized)

    filtered = [
        d for d in ordered
        if _is_recommendable_domain(d, project_host=project_host, project_root=project_root)
    ]

    if not filtered:
        return DomainRecommendation(
            domain=None,
            status="unknown",
            reason="No actionable target domain was found from intake/scope artifacts.",
            allowed_tests=[],
            blocked_tests=[],
        )

    best_domain = None
    best_score = -10_000
    best_status = "unknown"
    for domain in filtered:
        status = classify_domain(domain, scope)
        score = 0
        if status == "in-scope":
            score += 100
        elif status == "unknown":
            score += 20
        else:
            score -= 200
        if project_host and (domain == project_host or domain.endswith("." + project_host)):
            score += 45
        if project_root and (domain == project_root or domain.endswith("." + project_root)):
            score += 25
        if any(k in domain for k in ("api", "auth", "admin", "account")):
            score += 15
        if score > best_score:
            best_score = score
            best_domain = domain
            best_status = status

    if best_domain is None:
        return DomainRecommendation(
            domain=None,
            status="unknown",
            reason="No suitable domain candidate could be selected.",
            allowed_tests=[],
            blocked_tests=[],
        )

    if best_status == "out-of-scope":
        return DomainRecommendation(
            domain=best_domain,
            status=best_status,
            reason=f"{best_domain} matches an out-of-scope pattern from provided scope data.",
            allowed_tests=[
                "Only collect passive metadata and move to another domain candidate."
            ],
            blocked_tests=[
                "Do not send active scans/fuzzing payloads",
                "Do not attempt auth bypass or exploit testing",
            ],
        )

    if best_status == "in-scope":
        return DomainRecommendation(
            domain=best_domain,
            status=best_status,
            reason=f"{best_domain} matches provided in-scope domain patterns.",
            allowed_tests=[
                "Start with passive recon and endpoint inventory",
                "Map auth/session flows and access control",
                "Test IDOR, rate-limit, business-logic, and injection safely",
            ],
            blocked_tests=[
                "No DoS or traffic flooding unless explicitly allowed",
                "No social engineering or physical attacks",
                "No testing third-party assets not listed in scope",
            ],
        )

    return DomainRecommendation(
        domain=best_domain,
        status=best_status,
        reason="Domain does not match explicit in-scope/out-of-scope patterns; manual validation required.",
        allowed_tests=[
            "Limit to passive recon until scope is confirmed",
            "Confirm scope entry before active testing",
        ],
        blocked_tests=[
            "Avoid active exploitation until scope confirmation",
        ],
    )


def classify_domain(domain: str, scope: ScopeData) -> str:
    d = domain.lower()
    for pattern in scope.out_scope:
        if _matches(d, pattern):
            return "out-of-scope"
    for pattern in scope.in_scope:
        if _matches(d, pattern):
            return "in-scope"
    return "unknown"


def _line_is_out_scope(line: str) -> bool:
    low = line.lower()
    if low.startswith(("!", "-", "exclude:", "excluded:", "out:")):
        return True
    return any(token in low for token in ("out-of-scope", "oos", "excluded", "not allowed"))


def _matches(domain: str, pattern: str) -> bool:
    p = pattern.lower().strip()
    if p.startswith("*."):
        root = p[2:]
        return domain == root or domain.endswith("." + root)
    return domain == p


def _normalize_domain(value: str) -> str:
    v = (value or "").strip().lower().strip(".")
    if not v:
        return ""
    if v.startswith(("http://", "https://")):
        v = (urlparse(v).hostname or "").lower().strip(".")
    if v.startswith("*."):
        v = v[2:]
    return v


def _root_domain(domain: str) -> str:
    if not domain:
        return ""
    labels = [item for item in domain.split(".") if item]
    if len(labels) < 2:
        return domain
    return ".".join(labels[-2:])


def _is_recommendable_domain(domain: str, project_host: str, project_root: str) -> bool:
    if not domain:
        return False
    if domain in {"hackerone.com", "www.hackerone.com"}:
        return False
    if domain in NON_TARGET_DOMAINS:
        if project_host and (domain == project_host or domain.endswith("." + project_host)):
            return True
        if project_root and (domain == project_root or domain.endswith("." + project_root)):
            return True
        return False
    if project_host and (domain == project_host or project_host.endswith("." + domain)):
        return True
    if project_root and (domain == project_root or domain.endswith("." + project_root)):
        return True
    return True
