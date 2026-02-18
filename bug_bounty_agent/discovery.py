"""Program intake and internet context discovery."""

from __future__ import annotations

from dataclasses import dataclass
import csv
from html.parser import HTMLParser
import json
import re
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen

TAB_SUFFIXES = [
    "",  # Program guidelines
    "policy_scopes",  # Scope
    "hacktivity",
    "thanks",
    "updates",
    "collaborators",
    "safe_harbor",
]


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
    tab_links: list[str]
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
            f"Previous bug links: {self.previous_bug_links}\n"
            f"Social/public discussions: {self.social_discussion_links}\n"
            "Create an actionable bug bounty plan with completed vs pending phases."
        )


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


def _extract_domains_from_csv(path: Path) -> tuple[list[str], list[str]]:
    in_scope: list[str] = []
    out_scope: list[str] = []
    if not path.exists():
        return in_scope, out_scope
    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                ident = (row.get("identifier") or "").strip()
                instruction = (row.get("instruction") or "").strip().lower()
                eligible_sub = (row.get("eligible_for_submission") or "").strip().lower()
                eligible_bounty = (row.get("eligible_for_bounty") or "").strip().lower()

                domains = _extract_domains_from_text(ident)
                if not domains:
                    continue
                is_out = (
                    eligible_sub == "false"
                    or eligible_bounty == "false"
                    or "out of scope" in instruction
                    or "excluded" in instruction
                )
                target = out_scope if is_out else in_scope
                for domain in domains:
                    if domain not in target:
                        target.append(domain)
    except Exception:
        return in_scope, out_scope
    return in_scope[:100], out_scope[:100]


def _extract_domains_from_burp_json(path: Path) -> tuple[list[str], list[str]]:
    in_scope: list[str] = []
    out_scope: list[str] = []
    if not path.exists():
        return in_scope, out_scope
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return in_scope, out_scope
    target = data.get("target", {}).get("scope", {})
    include = target.get("include", []) if isinstance(target, dict) else []
    exclude = target.get("exclude", []) if isinstance(target, dict) else []

    for item in include if isinstance(include, list) else []:
        host = str(item.get("host", ""))
        domains = _extract_domains_from_text(host.replace("\\.", ".").replace("^", "").replace("$", ""))
        for domain in domains:
            if domain not in in_scope:
                in_scope.append(domain)
    for item in exclude if isinstance(exclude, list) else []:
        host = str(item.get("host", ""))
        domains = _extract_domains_from_text(host.replace("\\.", ".").replace("^", "").replace("$", ""))
        for domain in domains:
            if domain not in out_scope:
                out_scope.append(domain)
    return in_scope[:100], out_scope[:100]


def discover_project_context(project_url: str, program_hint: str | None = None) -> DiscoveryData:
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

    policy, scope, docs = _classify_links(links)

    tab_links: list[str] = []
    downloaded_files: list[str] = []
    in_scope_domains: list[str] = []
    out_scope_domains: list[str] = []

    if handle:
        base = f"https://hackerone.com/{handle}"
        tab_links = [base if not suf else f"{base}/{suf}" for suf in TAB_SUFFIXES]
        # Ensure policy/scope tab links are in candidates even when SPA hides link markup.
        for candidate in [base, f"{base}/policy_scopes"]:
            if candidate not in policy:
                policy.append(candidate)
            if candidate not in scope:
                scope.append(candidate)

        download_dir = Path(".bug_bounty_agent/downloads") / project_key
        csv_file = _download_file(
            f"https://hackerone.com/teams/{handle}/assets/download_csv.csv",
            download_dir,
        )
        burp_file = _download_file(
            f"https://hackerone.com/teams/{handle}/assets/download_burp_project_file.json",
            download_dir,
        )
        for path in [csv_file, burp_file]:
            if path:
                downloaded_files.append(path)

        if csv_file:
            csv_in, csv_out = _extract_domains_from_csv(Path(csv_file))
            for d in csv_in:
                if d not in in_scope_domains:
                    in_scope_domains.append(d)
            for d in csv_out:
                if d not in out_scope_domains:
                    out_scope_domains.append(d)

        if burp_file:
            b_in, b_out = _extract_domains_from_burp_json(Path(burp_file))
            for d in b_in:
                if d not in in_scope_domains:
                    in_scope_domains.append(d)
            for d in b_out:
                if d not in out_scope_domains:
                    out_scope_domains.append(d)

    previous_bugs = _search_previous_bugs(project_url)
    social_links = _search_social_discussions(project_url)
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
        tab_links=tab_links,
        sources=uniq_sources[:20],
    )
