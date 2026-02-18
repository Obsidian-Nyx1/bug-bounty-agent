"""Program intake and internet context discovery."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen


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
    candidate_policy_links: list[str]
    candidate_scope_links: list[str]
    candidate_doc_links: list[str]
    previous_bug_links: list[str]
    social_discussion_links: list[str]
    domain_candidates: list[str]
    sources: list[str]

    def as_prompt(self) -> str:
        return (
            f"Project URL: {self.project_url}\n"
            f"Policy links: {self.candidate_policy_links}\n"
            f"Scope links: {self.candidate_scope_links}\n"
            f"Documentation links: {self.candidate_doc_links}\n"
            f"Domains in scope (candidates): {self.domain_candidates}\n"
            f"Previous bug links: {self.previous_bug_links}\n"
            f"Social/public discussions: {self.social_discussion_links}\n"
            "Create an actionable bug bounty plan with completed vs pending phases."
        )


def _fetch(url: str, timeout: int = 12) -> str:
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
    with urlopen(req, timeout=timeout) as response:
        raw = response.read(350_000)
    return raw.decode("utf-8", errors="ignore")


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


def discover_project_context(project_url: str) -> DiscoveryData:
    parsed = urlparse(project_url)
    project_key = (parsed.netloc or project_url).replace("www.", "").strip("/")

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

    policy, scope, docs = _classify_links(links)
    previous_bugs = _search_previous_bugs(project_url)
    social_links = _search_social_discussions(project_url)
    domain_candidates = _extract_domains_from_text(page_text + " " + " ".join(links))

    sources = [
        project_url,
        *policy,
        *scope,
        *docs,
        *previous_bugs,
        *social_links,
    ]
    uniq_sources: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if source and source not in seen:
            seen.add(source)
            uniq_sources.append(source)

    return DiscoveryData(
        project_url=project_url,
        project_key=project_key,
        candidate_policy_links=policy,
        candidate_scope_links=scope,
        candidate_doc_links=docs,
        previous_bug_links=previous_bugs,
        social_discussion_links=social_links,
        domain_candidates=domain_candidates,
        sources=uniq_sources[:20],
    )
