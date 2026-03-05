"""Passive internet/social collectors for bug bounty recon."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
import re
from typing import Callable
from urllib.parse import quote_plus
from urllib.request import Request, urlopen


DOMAIN_RE = re.compile(r"\b(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")


@dataclass
class IntelItem:
    source_type: str
    query: str
    url: str
    title: str
    snippet: str
    extracted_domains: list[str]
    extracted_urls: list[str]
    collected_at: str
    confidence_score: int
    relevance_score: int
    recency_score: int
    combined_score: int

    def to_dict(self) -> dict:
        return asdict(self)


class _SearchParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._capture_link = False
        self._current_href = ""
        self._current_text: list[str] = []
        self._capture_text = True
        self.page_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = ""
            for key, value in attrs:
                if key == "href" and value:
                    href = value
                    break
            if href.startswith("http"):
                self._capture_link = True
                self._current_href = href
                self._current_text = []
        if tag in {"script", "style"}:
            self._capture_text = False

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._capture_link and self._current_href:
            title = " ".join(" ".join(self._current_text).split())[:160]
            self.links.append((self._current_href, title))
            self._capture_link = False
            self._current_href = ""
            self._current_text = []
        if tag in {"script", "style"}:
            self._capture_text = True

    def handle_data(self, data: str) -> None:
        if not data:
            return
        if self._capture_link:
            self._current_text.append(data)
        if self._capture_text:
            text = " ".join(data.split())
            if text:
                self.page_text.append(text)


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
        payload = response.read(350_000)
    return payload.decode("utf-8", errors="ignore")


def _extract_domains(text: str) -> list[str]:
    out: list[str] = []
    for found in DOMAIN_RE.findall(text or ""):
        value = found.lower().strip(".")
        if value.startswith("www."):
            value = value[4:]
        if value and value not in out:
            out.append(value)
    return out[:20]


def _extract_urls(text: str) -> list[str]:
    out: list[str] = []
    for found in URL_RE.findall(text or ""):
        cleaned = found.strip().rstrip(").,")
        if cleaned not in out:
            out.append(cleaned)
    return out[:20]


def _score_item(
    *,
    source_type: str,
    query: str,
    title: str,
    url: str,
    scope_domains: list[str],
) -> tuple[int, int, int, int]:
    low_blob = f"{query} {title} {url}".lower()
    confidence = 45
    relevance = 30
    recency = 20

    if source_type in {"hackerone", "github", "docs"}:
        confidence += 25
    if source_type in {"reddit", "x_twitter"}:
        confidence += 10
    if any(token in low_blob for token in ("2026", "2025", "today", "recent", "update", "incident")):
        recency += 20
    if any(token in low_blob for token in ("bug bounty", "vulnerability", "writeup", "hacktivity")):
        relevance += 25
    if any(token in low_blob for token in ("api", "auth", "admin", "upload", "payment")):
        relevance += 15
    if any(domain in low_blob for domain in scope_domains):
        relevance += 20
        confidence += 10

    confidence = max(0, min(100, confidence))
    relevance = max(0, min(100, relevance))
    recency = max(0, min(100, recency))
    combined = int(round((confidence * 0.4) + (relevance * 0.4) + (recency * 0.2)))
    return confidence, relevance, recency, combined


def collect_duckduckgo_results(
    *,
    query: str,
    source_type: str,
    scope_domains: list[str],
    limit: int = 10,
    fetcher: Callable[[str], str] | None = None,
) -> list[IntelItem]:
    fetch = fetcher or _fetch
    search_url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
    try:
        html = fetch(search_url)
    except Exception:
        return []

    parser = _SearchParser()
    parser.feed(html)
    page_snippet = " ".join(parser.page_text[:100])[:300]
    out: list[IntelItem] = []
    seen: set[str] = set()
    for href, title in parser.links:
        if href in seen:
            continue
        seen.add(href)
        conf, rel, rec, combined = _score_item(
            source_type=source_type,
            query=query,
            title=title,
            url=href,
            scope_domains=scope_domains,
        )
        item = IntelItem(
            source_type=source_type,
            query=query,
            url=href,
            title=title or href,
            snippet=page_snippet,
            extracted_domains=_extract_domains(f"{title} {href}"),
            extracted_urls=_extract_urls(href),
            collected_at=datetime.now(timezone.utc).isoformat(),
            confidence_score=conf,
            relevance_score=rel,
            recency_score=rec,
            combined_score=combined,
        )
        out.append(item)
        if len(out) >= limit:
            break
    return out
