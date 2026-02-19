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
    for path in ["/admin", "/dashboard/admin", "/internal", "/admin/login", "/manage", "/console", "/backend", "/staff"]:
        code, _, _ = _request(base + path)
        if code and code < 300:
            return _finding("A001", "Forced browsing probe", base, "review", f"{path} returned {code}")
    # HEAD verb variant for low-noise endpoint existence checks.
    for path in ["/admin", "/api/admin", "/manage"]:
        h_code, _, _ = _request(base + path, method="HEAD")
        if h_code and h_code < 300:
            return _finding("A001", "Forced browsing probe", base, "review", f"{path} returned {h_code} on HEAD")
    # robots.txt hint extraction variant.
    r_code, _, r_body = _request(base + "/robots.txt")
    if r_code and r_code < 300 and any(k in r_body.lower() for k in ("disallow: /admin", "disallow: /internal", "disallow: /manage")):
        return _finding("A001", "Forced browsing probe", base, "review", "robots.txt exposes sensitive admin/internal paths")
    return _finding("A001", "Forced browsing probe", base, "ok", "No direct admin path returned success.")


def _check_method_confusion(base: str) -> AutomatedFinding:
    code, headers, _ = _request(base, method="OPTIONS")
    allow = headers.get("Allow", "")
    if allow and ("PUT" in allow or "DELETE" in allow):
        return _finding("A002", "HTTP method confusion probe", base, "review", f"Allow header: {allow}")
    # Method override header variant.
    o_code, _, _ = _request(
        base,
        method="POST",
        headers={
            "User-Agent": "bug-bounty-agent/1.0",
            "X-HTTP-Method-Override": "DELETE",
        },
    )
    if o_code and o_code < 300:
        return _finding("A002", "HTTP method confusion probe", base, "review", f"Method-override request accepted (status={o_code})")
    # Override parameter variant seen in some frameworks.
    m_code, _, _ = _request(base + "/?_method=DELETE", method="POST", headers={"User-Agent": "bug-bounty-agent/1.0"})
    if m_code and m_code < 300:
        return _finding("A002", "HTTP method confusion probe", base, "review", f"_method override accepted (status={m_code})")
    # OPTIONS on API root variant.
    api_code, api_headers, _ = _request(base + "/api", method="OPTIONS")
    api_allow = api_headers.get("Allow", "")
    if api_allow and ("PUT" in api_allow or "DELETE" in api_allow or "PATCH" in api_allow):
        return _finding("A002", "HTTP method confusion probe", base, "review", f"/api allow header: {api_allow}")
    return _finding("A002", "HTTP method confusion probe", base, "ok", f"OPTIONS status={code}, allow={allow or 'n/a'}")


def _check_graphql_introspection(base: str) -> AutomatedFinding:
    payload = {"query": "{__schema{types{name}}}"}
    code, _, body = _post_json(base + "/graphql", payload)
    if code and code < 300 and "__schema" in body:
        return _finding("A003", "GraphQL introspection exposure", base, "review", f"/graphql returned schema data (status={code})")
    # Alternative GraphQL endpoint variant.
    alt_code, _, alt_body = _post_json(base + "/api/graphql", payload)
    if alt_code and alt_code < 300 and "__schema" in alt_body:
        return _finding("A003", "GraphQL introspection exposure", base, "review", f"/api/graphql returned schema data (status={alt_code})")
    # GET query variant (common for permissive GraphQL setups).
    get_code, _, get_body = _request(base + "/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D")
    if get_code and get_code < 300 and "__schema" in get_body:
        return _finding("A003", "GraphQL introspection exposure", base, "review", f"/graphql GET returned schema data (status={get_code})")
    # GraphiQL UI exposure variant.
    g_code, _, g_body = _request(base + "/graphiql")
    if g_code and g_code < 300 and any(k in g_body.lower() for k in ("graphiql", "graphql playground", "apollo sandbox")):
        return _finding("A003", "GraphQL introspection exposure", base, "review", f"/graphiql UI exposed (status={g_code})")
    return _finding("A003", "GraphQL introspection exposure", base, "ok", f"/graphql introspection not exposed (status={code})")


def _check_cors(base: str) -> AutomatedFinding:
    code, headers, _ = _request(base, headers={"Origin": "https://evil.example", "User-Agent": "bug-bounty-agent/1.0"})
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*" or "evil.example" in acao:
        return _finding("A004", "CORS misconfiguration probe", base, "review", f"ACAO={acao} status={code}")
    # Null origin variant.
    n_code, n_headers, _ = _request(base, headers={"Origin": "null", "User-Agent": "bug-bounty-agent/1.0"})
    n_acao = n_headers.get("Access-Control-Allow-Origin", "")
    if n_acao == "null" or n_acao == "*":
        return _finding("A004", "CORS misconfiguration probe", base, "review", f"ACAO={n_acao} for null origin status={n_code}")
    # Preflight variant.
    p_code, p_headers, _ = _request(
        base,
        method="OPTIONS",
        headers={
            "User-Agent": "bug-bounty-agent/1.0",
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        },
    )
    p_acao = p_headers.get("Access-Control-Allow-Origin", "")
    p_acac = p_headers.get("Access-Control-Allow-Credentials", "")
    if (p_acao == "*" and p_acac.lower() == "true") or "evil.example" in p_acao:
        return _finding("A004", "CORS misconfiguration probe", base, "review", f"Preflight ACAO={p_acao} ACAC={p_acac} status={p_code}")
    # API endpoint variant.
    a_code, a_headers, _ = _request(base + "/api", headers={"Origin": "https://evil.example", "User-Agent": "bug-bounty-agent/1.0"})
    a_acao = a_headers.get("Access-Control-Allow-Origin", "")
    if a_acao == "*" or "evil.example" in a_acao:
        return _finding("A004", "CORS misconfiguration probe", base, "review", f"/api ACAO={a_acao} status={a_code}")
    return _finding("A004", "CORS misconfiguration probe", base, "ok", f"ACAO={acao or 'none'} status={code}")


def _check_debug_and_error_disclosure(base: str) -> AutomatedFinding:
    for path in ["/debug", "/.env", "/server-status", "/actuator", "/_debug", "/api/debug", "/phpinfo.php", "/actuator/env", "/actuator/health"]:
        code, _, body = _request(base + path)
        if code and code < 300 and any(k in body.lower() for k in ("password", "secret", "exception", "traceback")):
            return _finding("A005", "Debug/error disclosure probe", base, "review", f"{path} returned {code} with potential sensitive keywords")
    # Forced error signature variant.
    e_code, _, e_body = _request(base + "/?__bb_test__=%")
    if any(k in e_body.lower() for k in ("stack trace", "exception", "traceback", "sql syntax")):
        return _finding("A005", "Debug/error disclosure probe", base, "review", f"Error signature leaked via invalid query (status={e_code})")
    # Not-found error variant.
    nf_code, _, nf_body = _request(base + "/this-path-should-not-exist-bb-agent")
    if any(k in nf_body.lower() for k in ("stack trace", "exception", "traceback", "runtimeerror", "nullreferenceexception")):
        return _finding("A005", "Debug/error disclosure probe", base, "review", f"Verbose error leaked on 404 path (status={nf_code})")
    return _finding("A005", "Debug/error disclosure probe", base, "ok", "No obvious debug exposure in common paths.")


def _check_open_redirect(base: str) -> AutomatedFinding:
    candidates = [
        base + "/redirect?next=https://example.org",
        base + "/login?redirect=https://example.org",
        base + "/?url=https://example.org",
        base + "/oauth/authorize?redirect_uri=https://example.org",
        base + "/logout?returnTo=https://example.org",
        base + "/continue?return=https://example.org",
    ]
    for url in candidates:
        code, headers, _ = _request(url)
        loc = headers.get("Location", "")
        if code and 300 <= code < 400 and "example.org" in loc:
            return _finding("A006", "Open redirect probe", base, "review", f"{urlparse(url).path} location={loc} status={code}")
    return _finding("A006", "Open redirect probe", base, "ok", f"Redirect not confirmed (status={code}, location={loc or 'none'})")


def _check_host_header_reflection(base: str) -> AutomatedFinding:
    code, _, body = _request(base, headers={"Host": "evil.example", "User-Agent": "bug-bounty-agent/1.0"})
    if "evil.example" in body:
        return _finding("A007", "Host header reflection probe", base, "review", f"Reflected custom Host in response (status={code})")
    # X-Forwarded-Host variant.
    xf_code, _, xf_body = _request(
        base,
        headers={"User-Agent": "bug-bounty-agent/1.0", "X-Forwarded-Host": "evil.example"},
    )
    if "evil.example" in xf_body:
        return _finding("A007", "Host header reflection probe", base, "review", f"Reflected X-Forwarded-Host in response (status={xf_code})")
    # Additional reverse-proxy header variants.
    xo_code, _, xo_body = _request(
        base,
        headers={"User-Agent": "bug-bounty-agent/1.0", "X-Original-Host": "evil.example"},
    )
    if "evil.example" in xo_body:
        return _finding("A007", "Host header reflection probe", base, "review", f"Reflected X-Original-Host in response (status={xo_code})")
    xh_code, _, xh_body = _request(
        base,
        headers={"User-Agent": "bug-bounty-agent/1.0", "X-Host": "evil.example"},
    )
    if "evil.example" in xh_body:
        return _finding("A007", "Host header reflection probe", base, "review", f"Reflected X-Host in response (status={xh_code})")
    return _finding("A007", "Host header reflection probe", base, "ok", f"No host reflection observed (status={code})")


def _check_path_traversal_signature(base: str) -> AutomatedFinding:
    candidates = [
        base + "/?file=../../../../etc/passwd",
        base + "/download?path=..%2f..%2f..%2f..%2fetc%2fpasswd",
        base + "/?template=../../../../windows/win.ini",
        base + "/?file=..%252f..%252f..%252f..%252fetc%252fpasswd",
        base + "/download/../../../../etc/passwd",
        base + "/?path=..\\..\\..\\..\\windows\\win.ini",
    ]
    for url in candidates:
        code, _, body = _request(url)
        if "root:x:" in body or "[extensions]" in body.lower():
            return _finding("A008", "Path traversal signature probe", base, "review", f"Traversal signature detected via {urlparse(url).path} (status={code})")
    return _finding("A008", "Path traversal signature probe", base, "ok", f"No traversal signature detected (status={code})")


def _check_reflected_xss_signature(base: str) -> AutomatedFinding:
    markers = [
        ("bbxss123", "q"),
        ("bbxss_name", "search"),
        ("bbxss_test", "query"),
        ("bbxss_msg", "message"),
        ("bbxss_redirect", "next"),
    ]
    for marker, param in markers:
        parsed = urlparse(base + f"/?{param}=" + marker)
        query = dict(parse_qsl(parsed.query))
        query[param] = marker
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(query), ""))
        code, _, body = _request(url)
        if marker in body:
            return _finding("A009", "Reflected XSS signature probe", base, "review", f"Marker {marker} reflected via param {param} (status={code})")
    # Path-based reflection variant.
    p_code, _, p_body = _request(base + "/search/" + "bbxss_path")
    if "bbxss_path" in p_body:
        return _finding("A009", "Reflected XSS signature probe", base, "review", f"Path marker reflected (status={p_code})")
    return _finding("A009", "Reflected XSS signature probe", base, "ok", f"Marker not reflected (status={code})")


def _check_sensitive_bundle_exposure(base: str) -> AutomatedFinding:
    for path in ["/.env", "/config.js", "/app.js", "/main.js", "/.git/config", "/assets/main.js", "/static/js/main.js", "/config.json", "/env.js", "/config.production.json", "/webpack-stats.json"]:
        code, _, body = _request(base + path)
        if code and code < 300 and any(k in body.lower() for k in ("apikey", "secret", "token", "authorization")):
            return _finding("A010", "Sensitive bundle/config exposure", base, "review", f"{path} status={code} with sensitive keywords")
    # JS source map variant.
    code, _, body = _request(base + "/main.js.map")
    if code and code < 300 and ("sourcesContent" in body or "\"mappings\"" in body):
        return _finding("A010", "Sensitive bundle/config exposure", base, "review", f"/main.js.map exposed (status={code})")
    # sourceMappingURL hint variant.
    js_code, _, js_body = _request(base + "/main.js")
    if js_code and js_code < 300 and "sourceMappingURL=" in js_body:
        return _finding("A010", "Sensitive bundle/config exposure", base, "review", f"/main.js exposes sourceMappingURL hint (status={js_code})")
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
