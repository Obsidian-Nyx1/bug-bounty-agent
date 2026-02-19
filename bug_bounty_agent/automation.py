"""Authorized in-scope automation checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import subprocess
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from bug_bounty_agent.discovery import DiscoveryData
from bug_bounty_agent.scope import ScopeData


DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


@dataclass
class AutomatedFinding:
    test_id: str
    test_name: str
    target: str
    status: str
    evidence: str


@dataclass
class AutomatedResult:
    findings: list[AutomatedFinding]
    markdown_report: str | None
    pdf_report: str | None
    notes: list[str]


def run_automated_tests(
    discovery: DiscoveryData,
    scope_data: ScopeData,
    operator_id: str,
) -> AutomatedResult:
    targets = _build_in_scope_targets(discovery, scope_data)
    if not targets:
        return AutomatedResult(
            findings=[],
            markdown_report=None,
            pdf_report=None,
            notes=["No domain-like in-scope targets available for automated checks."],
        )

    findings: list[AutomatedFinding] = []
    for target in targets[:12]:
        base = f"https://{target}"
        findings.extend(
            [
                _check_forced_browsing(base),
                _check_method_confusion(base),
                _check_graphql_introspection(base),
                _check_cors(base),
                _check_debug_and_error_disclosure(base),
                _check_open_redirect(base),
                _check_host_header_reflection(base),
                _check_path_traversal_signature(base),
                _check_reflected_xss_signature(base),
                _check_sensitive_bundle_exposure(base),
            ]
        )

    md_path, pdf_path, notes = _write_reports(discovery.project_key, operator_id, findings)
    return AutomatedResult(
        findings=findings,
        markdown_report=md_path,
        pdf_report=pdf_path,
        notes=notes,
    )


def _request(url: str, method: str = "GET", headers: dict | None = None, timeout: int = 12) -> tuple[int | None, dict, str]:
    req = Request(url=url, method=method, headers=headers or {"User-Agent": "bug-bounty-agent/1.0"})
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read(60_000).decode("utf-8", errors="ignore")
            return response.status, dict(response.headers), body
    except Exception as exc:
        return None, {}, f"error:{type(exc).__name__}:{exc}"


def _post_json(url: str, payload: dict, timeout: int = 12) -> tuple[int | None, dict, str]:
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url=url,
        method="POST",
        data=data,
        headers={
            "User-Agent": "bug-bounty-agent/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read(100_000).decode("utf-8", errors="ignore")
            return response.status, dict(response.headers), body
    except Exception as exc:
        return None, {}, f"error:{type(exc).__name__}:{exc}"


def _build_in_scope_targets(discovery: DiscoveryData, scope_data: ScopeData) -> list[str]:
    raw = []
    raw.extend(scope_data.in_scope)
    raw.extend(discovery.in_scope_domains)
    raw.extend(discovery.domain_candidates)

    targets: list[str] = []
    for item in raw:
        low = item.lower().strip()
        if not low:
            continue
        if low.startswith("*."):
            low = low[2:]
        if not DOMAIN_RE.match(low):
            continue
        if low.endswith(".program"):
            continue
        if low in discovery.out_scope_domains or low in scope_data.out_scope:
            continue
        if low not in targets:
            targets.append(low)
    return targets


def _finding(test_id: str, test_name: str, target: str, status: str, evidence: str) -> AutomatedFinding:
    return AutomatedFinding(test_id=test_id, test_name=test_name, target=target, status=status, evidence=evidence[:300])


def _check_forced_browsing(base: str) -> AutomatedFinding:
    for path in ["/admin", "/dashboard/admin", "/internal"]:
        code, _, _ = _request(base + path)
        if code and code < 300:
            return _finding("A001", "Forced browsing probe", base, "review", f"{path} returned {code}")
    return _finding("A001", "Forced browsing probe", base, "ok", "No direct admin path returned success.")


def _check_method_confusion(base: str) -> AutomatedFinding:
    code, headers, _ = _request(base, method="OPTIONS")
    allow = headers.get("Allow", "")
    if allow and ("PUT" in allow or "DELETE" in allow):
        return _finding("A002", "HTTP method confusion probe", base, "review", f"Allow header: {allow}")
    return _finding("A002", "HTTP method confusion probe", base, "ok", f"OPTIONS status={code}, allow={allow or 'n/a'}")


def _check_graphql_introspection(base: str) -> AutomatedFinding:
    payload = {"query": "{__schema{types{name}}}"}
    code, _, body = _post_json(base + "/graphql", payload)
    if code and code < 300 and "__schema" in body:
        return _finding("A003", "GraphQL introspection exposure", base, "review", f"/graphql returned schema data (status={code})")
    return _finding("A003", "GraphQL introspection exposure", base, "ok", f"/graphql introspection not exposed (status={code})")


def _check_cors(base: str) -> AutomatedFinding:
    code, headers, _ = _request(base, headers={"Origin": "https://evil.example", "User-Agent": "bug-bounty-agent/1.0"})
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*" or "evil.example" in acao:
        return _finding("A004", "CORS misconfiguration probe", base, "review", f"ACAO={acao} status={code}")
    return _finding("A004", "CORS misconfiguration probe", base, "ok", f"ACAO={acao or 'none'} status={code}")


def _check_debug_and_error_disclosure(base: str) -> AutomatedFinding:
    for path in ["/debug", "/.env", "/server-status", "/actuator"]:
        code, _, body = _request(base + path)
        if code and code < 300 and any(k in body.lower() for k in ("password", "secret", "exception", "traceback")):
            return _finding("A005", "Debug/error disclosure probe", base, "review", f"{path} returned {code} with potential sensitive keywords")
    return _finding("A005", "Debug/error disclosure probe", base, "ok", "No obvious debug exposure in common paths.")


def _check_open_redirect(base: str) -> AutomatedFinding:
    url = base + "/redirect?next=https://example.org"
    code, headers, _ = _request(url)
    loc = headers.get("Location", "")
    if code and 300 <= code < 400 and "example.org" in loc:
        return _finding("A006", "Open redirect probe", base, "review", f"Location={loc} status={code}")
    return _finding("A006", "Open redirect probe", base, "ok", f"Redirect not confirmed (status={code}, location={loc or 'none'})")


def _check_host_header_reflection(base: str) -> AutomatedFinding:
    code, _, body = _request(base, headers={"Host": "evil.example", "User-Agent": "bug-bounty-agent/1.0"})
    if "evil.example" in body:
        return _finding("A007", "Host header reflection probe", base, "review", f"Reflected custom Host in response (status={code})")
    return _finding("A007", "Host header reflection probe", base, "ok", f"No host reflection observed (status={code})")


def _check_path_traversal_signature(base: str) -> AutomatedFinding:
    url = base + "/?file=../../../../etc/passwd"
    code, _, body = _request(url)
    if "root:x:" in body:
        return _finding("A008", "Path traversal signature probe", base, "review", "Potential traversal signature root:x detected.")
    return _finding("A008", "Path traversal signature probe", base, "ok", f"No traversal signature detected (status={code})")


def _check_reflected_xss_signature(base: str) -> AutomatedFinding:
    marker = "bbxss123"
    parsed = urlparse(base + "/?q=" + marker)
    query = dict(parse_qsl(parsed.query))
    query["q"] = marker
    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(query), ""))
    code, _, body = _request(url)
    if marker in body:
        return _finding("A009", "Reflected XSS signature probe", base, "review", f"Marker reflected in response (status={code})")
    return _finding("A009", "Reflected XSS signature probe", base, "ok", f"Marker not reflected (status={code})")


def _check_sensitive_bundle_exposure(base: str) -> AutomatedFinding:
    for path in ["/.env", "/config.js", "/app.js", "/main.js", "/.git/config"]:
        code, _, body = _request(base + path)
        if code and code < 300 and any(k in body.lower() for k in ("apikey", "secret", "token", "authorization")):
            return _finding("A010", "Sensitive bundle/config exposure", base, "review", f"{path} status={code} with sensitive keywords")
    return _finding("A010", "Sensitive bundle/config exposure", base, "ok", "No obvious sensitive bundle/config leakage in common paths.")


def _write_reports(project_key: str, operator_id: str, findings: list[AutomatedFinding]) -> tuple[str | None, str | None, list[str]]:
    out_dir = Path(".bug_bounty_agent/reports") / operator_id
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    md_file = out_dir / f"{project_key}_{timestamp}_automated_checks.md"
    lines = [
        f"# Automated Checks Report: {project_key}",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Total checks: {len(findings)}",
        "",
        "| Test ID | Name | Target | Status | Evidence |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.test_id} | {f.test_name} | {f.target} | {f.status} | {f.evidence} |")
    md_file.write_text("\n".join(lines), encoding="utf-8")

    notes = [f"Automated check report saved: {md_file}"]
    pdf_file: str | None = None
    pandoc = shutil_which("pandoc")
    if pandoc:
        out_pdf = out_dir / f"{project_key}_{timestamp}_automated_checks.pdf"
        cmd = [pandoc, str(md_file), "-o", str(out_pdf)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0 and out_pdf.exists():
            pdf_file = str(out_pdf)
            notes.append(f"PDF report saved: {out_pdf}")
        else:
            notes.append("PDF conversion failed; markdown report remains available.")
    else:
        notes.append("pandoc not found; generated markdown report only.")
    return str(md_file), pdf_file, notes


def shutil_which(cmd: str) -> str | None:
    from shutil import which
    return which(cmd)
