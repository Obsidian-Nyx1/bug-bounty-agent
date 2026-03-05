"""High-level passive intel pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from bug_bounty_agent.intel_collectors import IntelItem, collect_duckduckgo_results


@dataclass
class IntelPipelineResult:
    items: list[dict]
    links: list[str]
    notes: list[str]


def _uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def _build_queries(
    *,
    project_url: str,
    project_key: str,
    domains: list[str],
    program_hint: str | None,
) -> list[tuple[str, str]]:
    parsed = urlparse(project_url)
    root_host = (parsed.hostname or "").lower().strip(".")
    key_terms = [project_key, root_host, program_hint or ""]
    for domain in domains[:5]:
        key_terms.append(domain)
    uniq_terms = _uniq([term for term in key_terms if term])

    queries: list[tuple[str, str]] = []
    for term in uniq_terms[:6]:
        queries.extend(
            [
                (f"{term} bug bounty writeup", "web"),
                (f"{term} vulnerability disclosure", "web"),
                (f"{term} api auth admin", "docs"),
                (f"site:reddit.com {term} bug bounty", "reddit"),
                (f"site:x.com {term} bug bounty", "x_twitter"),
                (f"site:twitter.com {term} bug bounty", "x_twitter"),
                (f"site:github.com {term} security issue", "github"),
                (f"site:hackerone.com {term} report", "hackerone"),
            ]
        )
    return queries[:36]


def run_intel_pipeline(
    *,
    project_url: str,
    project_key: str,
    domains: list[str],
    program_hint: str | None = None,
    max_items: int = 50,
) -> IntelPipelineResult:
    queries = _build_queries(
        project_url=project_url,
        project_key=project_key,
        domains=domains,
        program_hint=program_hint,
    )
    scope_domains = _uniq(domains)

    gathered: list[IntelItem] = []
    for query, source_type in queries:
        items = collect_duckduckgo_results(
            query=query,
            source_type=source_type,
            scope_domains=scope_domains,
            limit=5,
        )
        gathered.extend(items)
        if len(gathered) >= max_items * 2:
            break

    # Deduplicate by URL and keep highest-scoring.
    best_by_url: dict[str, IntelItem] = {}
    for item in gathered:
        current = best_by_url.get(item.url)
        if current is None or item.combined_score > current.combined_score:
            best_by_url[item.url] = item

    ranked = sorted(best_by_url.values(), key=lambda i: (-i.combined_score, i.url))
    top = ranked[:max_items]
    links = [item.url for item in top]
    notes = [
        f"Intel pipeline queries executed: {len(queries)}",
        f"Intel items collected: {len(gathered)}",
        f"Intel items retained after dedupe/ranking: {len(top)}",
    ]
    return IntelPipelineResult(items=[item.to_dict() for item in top], links=links, notes=notes)
