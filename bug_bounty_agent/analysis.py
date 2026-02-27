"""Step 3: Analyze collected scope data and generate test matrix."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re

from bug_bounty_agent.discovery import DiscoveryData
from bug_bounty_agent.scope import ScopeData

SCOPE_VERIFIED_IN = "verified_in_scope_from_policy_or_artifact"
SCOPE_VERIFIED_OUT = "verified_out_of_scope_from_policy_or_artifact"
SCOPE_DISCOVERED_UNVERIFIED = "discovered_target_requires_scope_validation"


@dataclass
class TestCase:
    test_id: str
    category: str
    test_name: str
    target: str
    scope_basis: str
    why: str


@dataclass
class AnalysisResult:
    tests: list[TestCase]
    matrix_path: str | None
    notes: list[str]


@dataclass(frozen=True)
class TestTemplate:
    category: str
    name: str
    why: str
    keywords: tuple[str, ...]
    target_hints: tuple[str, ...]


def analyze_information(
    discovery: DiscoveryData,
    scope_data: ScopeData,
    ai_ideas: list[str] | None = None,
    target_count: int = 50,
    operator_id: str = "default-operator",
) -> AnalysisResult:
    targets = _pick_targets(discovery, scope_data)
    if not targets:
        return AnalysisResult(
            tests=[],
            matrix_path=None,
            notes=["No in-scope targets available to build Step 3 test matrix."],
        )

    templates = _rank_templates(_base_templates(), discovery, scope_data, targets)
    tests: list[TestCase] = []
    idx = 1
    usage_counts = {target: 0 for target in targets}

    for template in templates:
        if len(tests) >= target_count:
            break
        target = _pick_best_target(template, targets, usage_counts)
        usage_counts[target] += 1
        scope_basis = _scope_basis_for_target(target, scope_data, discovery)
        tests.append(
            TestCase(
                test_id=f"T{idx:03d}",
                category=template.category,
                test_name=template.name,
                target=target,
                scope_basis=scope_basis,
                why=template.why,
            )
        )
        idx += 1

    if ai_ideas:
        target_cursor = 0
        for idea in ai_ideas:
            if len(tests) >= target_count:
                break
            target = targets[target_cursor % len(targets)]
            tests.append(
                TestCase(
                    test_id=f"T{idx:03d}",
                    category="AI-Suggested",
                    test_name=idea,
                    target=target,
                    scope_basis=_scope_basis_for_target(target, scope_data, discovery),
                    why="Derived from AI analysis of scope/policy artifacts.",
                )
            )
            idx += 1
            target_cursor += 1

    matrix_path = _write_matrix_csv(discovery.project_key, operator_id, tests)
    notes = [
        f"Step 3 matrix generated with {len(tests)} tests.",
        "Adaptive weighted ranking applied to test templates using discovered scope/policy/context signals.",
    ]
    if ai_ideas:
        notes.append(
            f"AI-added ideas included: {min(len(ai_ideas), max(0, target_count - len(templates)))}"
        )
    else:
        notes.append("No AI ideas available; used weighted local ranking model only.")
    if matrix_path:
        notes.append(f"Test matrix saved: {matrix_path}")
    return AnalysisResult(tests=tests, matrix_path=matrix_path, notes=notes)


def _write_matrix_csv(project_key: str, operator_id: str, tests: list[TestCase]) -> str | None:
    out_dir = Path(".bug_bounty_agent/reports") / operator_id
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_file = out_dir / f"{project_key}_{timestamp}_test_matrix.csv"
    try:
        with out_file.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["test_id", "category", "test_name", "target", "scope_basis", "why"])
            for t in tests:
                writer.writerow([t.test_id, t.category, t.test_name, t.target, t.scope_basis, t.why])
        return str(out_file)
    except Exception:
        return None


def _pick_targets(discovery: DiscoveryData, scope_data: ScopeData) -> list[str]:
    targets: list[str] = []
    for item in scope_data.in_scope:
        if item not in targets:
            targets.append(item)
    for item in discovery.in_scope_domains:
        if item not in targets:
            targets.append(item)
    for item in _verified_in_scope_non_domain_assets(discovery):
        if item not in targets:
            targets.append(item)
    for item in discovery.domain_candidates:
        if item not in targets:
            targets.append(item)
    if not targets:
        if discovery.program_handle:
            targets.append(f"{discovery.program_handle}.program")
        else:
            targets.append(discovery.project_key)
    return targets[:30]


def _scope_basis_for_target(target: str, scope_data: ScopeData, discovery: DiscoveryData) -> str:
    if target in scope_data.in_scope or target in discovery.in_scope_domains:
        return SCOPE_VERIFIED_IN
    if target in _verified_in_scope_non_domain_assets(discovery):
        return SCOPE_VERIFIED_IN
    if target in scope_data.out_scope or target in discovery.out_scope_domains:
        return SCOPE_VERIFIED_OUT
    if target in _verified_out_scope_non_domain_assets(discovery):
        return SCOPE_VERIFIED_OUT
    return SCOPE_DISCOVERED_UNVERIFIED


def _verified_in_scope_non_domain_assets(discovery: DiscoveryData) -> list[str]:
    assets: list[str] = []
    for signal in discovery.allowed_scope_signals:
        candidate = signal.split(" (", 1)[0].strip()
        if not candidate or candidate == "unlabeled asset":
            continue
        if "." in candidate:
            continue
        if candidate not in assets:
            assets.append(candidate)
    return assets[:40]


def _verified_out_scope_non_domain_assets(discovery: DiscoveryData) -> list[str]:
    assets: list[str] = []
    for signal in discovery.out_scope_signals:
        candidate = signal.split(" (", 1)[0].strip()
        if not candidate or candidate == "unlabeled asset":
            continue
        if "." in candidate:
            continue
        if candidate not in assets:
            assets.append(candidate)
    return assets[:40]


def _rank_templates(
    templates: list[TestTemplate],
    discovery: DiscoveryData,
    scope_data: ScopeData,
    targets: list[str],
) -> list[TestTemplate]:
    corpus = _build_feature_corpus(discovery, scope_data, targets)
    scored: list[tuple[int, int, TestTemplate]] = []
    for idx, template in enumerate(templates):
        score = _template_score(template, corpus, targets)
        scored.append((score, idx, template))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [row[2] for row in scored]


def _build_feature_corpus(discovery: DiscoveryData, scope_data: ScopeData, targets: list[str]) -> str:
    pieces: list[str] = [
        discovery.project_url,
        discovery.project_key,
        discovery.program_handle or "",
    ]
    pieces.extend(discovery.candidate_policy_links)
    pieces.extend(discovery.candidate_scope_links)
    pieces.extend(discovery.candidate_doc_links)
    pieces.extend(discovery.previous_bug_links)
    pieces.extend(discovery.social_discussion_links)
    pieces.extend(discovery.allowed_scope_signals)
    pieces.extend(discovery.out_scope_signals)
    pieces.extend(discovery.downloaded_artifact_reasons)
    pieces.extend(discovery.in_scope_domains)
    pieces.extend(discovery.out_scope_domains)
    pieces.extend(targets)
    pieces.extend(scope_data.in_scope)
    pieces.extend(scope_data.out_scope)
    text = " ".join(pieces).lower()
    return re.sub(r"[^a-z0-9._:/-]+", " ", text)


def _template_score(template: TestTemplate, corpus: str, targets: list[str]) -> int:
    score = 10
    for keyword in template.keywords:
        if keyword in corpus:
            score += 8
    target_blob = " ".join(targets).lower()
    for hint in template.target_hints:
        if hint in target_blob:
            score += 5
    if template.category in {"Auth", "Access Control", "API"}:
        score += 2
    return score


def _pick_best_target(
    template: TestTemplate,
    targets: list[str],
    usage_counts: dict[str, int],
) -> str:
    best_target = targets[0]
    best_score = -10_000
    for target in targets:
        low = target.lower()
        score = 0
        for hint in template.target_hints:
            if hint in low:
                score += 8
        for keyword in template.keywords:
            if keyword in low:
                score += 3
        score -= usage_counts.get(target, 0) * 2
        if score > best_score:
            best_score = score
            best_target = target
    return best_target


def _base_templates() -> list[TestTemplate]:
    return [
        TestTemplate("Auth", "Account takeover via weak recovery flow", "High impact auth control weakness.", ("auth", "login", "reset", "account"), ("auth", "login", "account")),
        TestTemplate("Auth", "MFA bypass through alternate flow", "Common bypass path in multi-channel auth.", ("mfa", "2fa", "auth"), ("auth", "login")),
        TestTemplate("Auth", "Session fixation after login", "Confirms session rotation on auth boundaries.", ("session", "auth", "login"), ("auth", "account")),
        TestTemplate("Auth", "Session token invalidation on logout", "Ensures logout revokes active sessions.", ("session", "logout", "token"), ("auth", "account")),
        TestTemplate("Auth", "Password reset token reuse", "Checks one-time token enforcement.", ("password", "reset", "token"), ("auth", "account")),
        TestTemplate("Access Control", "IDOR on profile object IDs", "Validates object-level authorization.", ("profile", "user", "account", "idor"), ("user", "account", "api")),
        TestTemplate("Access Control", "IDOR on payment/order references", "Checks direct object access in business data.", ("payment", "order", "invoice", "billing"), ("pay", "billing", "order")),
        TestTemplate("Access Control", "Horizontal privilege escalation", "Tests same-role user isolation.", ("role", "user", "member"), ("admin", "account", "api")),
        TestTemplate("Access Control", "Vertical privilege escalation", "Tests role boundary enforcement.", ("admin", "privilege", "role"), ("admin", "internal")),
        TestTemplate("Access Control", "Forced browsing of admin endpoints", "Checks route-level authorization.", ("admin", "dashboard", "internal"), ("admin", "manage", "portal")),
        TestTemplate("API", "Mass assignment in update endpoints", "Finds over-posting authorization issues.", ("api", "json", "update", "graphql"), ("api", "graphql")),
        TestTemplate("API", "Hidden parameter privilege toggles", "Discovers unsafe debug/role parameters.", ("debug", "role", "admin", "feature"), ("api", "admin")),
        TestTemplate("API", "Method confusion (GET/POST/PUT/DELETE)", "Finds verb-based auth inconsistencies.", ("api", "rest", "method"), ("api",)),
        TestTemplate("API", "Broken object property authorization", "Checks field-level data exposure.", ("api", "property", "field"), ("api", "graphql")),
        TestTemplate("API", "GraphQL introspection exposure", "Identifies schema disclosure and attack surface.", ("graphql", "schema"), ("graphql", "api")),
        TestTemplate("Input Validation", "SQL injection on key query parameters", "Tests backend query sanitization.", ("sql", "search", "query", "db"), ("api", "search")),
        TestTemplate("Input Validation", "NoSQL injection on JSON fields", "Checks document query operator filtering.", ("nosql", "json", "mongodb"), ("api", "json")),
        TestTemplate("Input Validation", "Command injection on integration hooks", "Validates shell command isolation.", ("command", "webhook", "integration", "ci"), ("api", "hook")),
        TestTemplate("Input Validation", "Template injection in render contexts", "Tests server-side templating safety.", ("template", "render", "ssti"), ("web", "portal")),
        TestTemplate("Input Validation", "Path traversal in file/resource endpoints", "Checks filesystem boundary handling.", ("file", "download", "path", "resource"), ("cdn", "assets", "static")),
        TestTemplate("XSS", "Reflected XSS in search/input endpoints", "Tests output encoding for immediate reflections.", ("xss", "search", "query", "input"), ("www", "app", "portal")),
        TestTemplate("XSS", "Stored XSS in profile/comment fields", "Checks persistent rendering contexts.", ("xss", "comment", "profile", "message"), ("community", "forum", "profile")),
        TestTemplate("XSS", "DOM XSS in client-side parsers", "Evaluates unsafe sink usage in JS.", ("dom", "javascript", "bundle", "client"), ("cdn", "static", "app")),
        TestTemplate("CSRF", "State-changing action without anti-CSRF token", "Tests cross-site action protections.", ("csrf", "state", "token", "form"), ("account", "settings", "profile")),
        TestTemplate("CSRF", "CSRF bypass with content-type changes", "Checks strict token validation logic.", ("csrf", "content-type", "multipart"), ("api", "account")),
        TestTemplate("Rate Limiting", "Brute-force resilience on auth endpoints", "Validates lockout and throttling.", ("login", "auth", "throttle", "rate"), ("auth", "login")),
        TestTemplate("Rate Limiting", "OTP/code brute force resistance", "Checks verification flow throttling.", ("otp", "code", "verify", "mfa"), ("auth", "verify")),
        TestTemplate("Rate Limiting", "Password reset abuse limits", "Prevents account disruption abuse.", ("password", "reset", "rate"), ("auth", "account")),
        TestTemplate("Rate Limiting", "Business action abuse (coupon/refund)", "Protects economic workflows.", ("coupon", "refund", "credit", "promo"), ("billing", "shop", "order")),
        TestTemplate("Rate Limiting", "API burst limits across tokens/IPs", "Tests distributed abuse resistance.", ("api", "burst", "rate", "token"), ("api",)),
        TestTemplate("Business Logic", "Race condition on balance/order operations", "Detects double-spend style flaws.", ("race", "balance", "order", "wallet"), ("billing", "order", "pay")),
        TestTemplate("Business Logic", "Workflow bypass via step skipping", "Checks required state transitions.", ("workflow", "step", "checkout"), ("order", "checkout", "portal")),
        TestTemplate("Business Logic", "Coupon/credit replay abuse", "Tests single-use enforcement.", ("coupon", "credit", "promo"), ("billing", "shop")),
        TestTemplate("Business Logic", "Negative quantity/price edge cases", "Validates monetary input constraints.", ("price", "quantity", "cart"), ("shop", "order", "billing")),
        TestTemplate("Business Logic", "State desync between web/mobile/API", "Finds inconsistent server validation.", ("mobile", "api", "state"), ("api", "mobile")),
        TestTemplate("File Upload", "Malicious file type upload bypass", "Tests extension/MIME verification.", ("upload", "file", "mime", "avatar"), ("upload", "media")),
        TestTemplate("File Upload", "Public bucket/object exposure post-upload", "Checks object ACL defaults.", ("bucket", "s3", "storage", "upload"), ("cdn", "assets", "storage")),
        TestTemplate("File Upload", "Image processing SSRF via URL fetch", "Validates remote fetch restrictions.", ("image", "fetch", "ssrf", "url"), ("media", "api", "upload")),
        TestTemplate("File Upload", "Metadata/script payload persistence", "Tests sanitization of file metadata.", ("metadata", "exif", "script"), ("media", "upload")),
        TestTemplate("File Upload", "Overwrite/replace existing objects", "Checks object naming authorization.", ("upload", "overwrite", "object"), ("storage", "media")),
        TestTemplate("Headers", "Host header injection behavior", "Finds trust on client-controlled host.", ("host", "header", "proxy"), ("api", "gateway")),
        TestTemplate("Headers", "Cache poisoning via response variations", "Tests cache key isolation.", ("cache", "cdn", "poison"), ("cdn", "assets", "static")),
        TestTemplate("Headers", "Open redirect through header manipulation", "Checks redirect target validation.", ("redirect", "location", "header"), ("auth", "login")),
        TestTemplate("Token", "JWT algorithm confusion/none acceptance", "Validates signature enforcement.", ("jwt", "token", "auth"), ("api", "auth")),
        TestTemplate("Token", "JWT claim tampering (role/aud/iss)", "Checks robust claim validation.", ("jwt", "claim", "role", "iss", "aud"), ("api", "admin")),
        TestTemplate("Token", "Long-lived token replay on critical actions", "Tests token lifetime and rotation.", ("token", "refresh", "session"), ("api", "auth")),
        TestTemplate("Infrastructure", "Subdomain takeover exposure", "Checks dangling DNS/service records.", ("subdomain", "cname", "dns"), ("dev", "staging", "cdn")),
        TestTemplate("Infrastructure", "CORS misconfiguration on sensitive APIs", "Prevents cross-origin data exfil.", ("cors", "origin", "api"), ("api",)),
        TestTemplate("Infrastructure", "Debug endpoints and verbose errors", "Reduces info leak and attack guidance.", ("debug", "trace", "error", "stack"), ("api", "admin")),
        TestTemplate("Infrastructure", "Sensitive data in client-side bundles", "Detects exposed secrets/config.", ("bundle", "config", "secret", "source map"), ("cdn", "static", "app")),
        TestTemplate("Infrastructure", "Open cloud storage listing access", "Checks public bucket/object listing.", ("bucket", "storage", "public"), ("storage", "cdn")),
        TestTemplate("Infrastructure", "Unauthenticated internal tooling exposure", "Finds unintended public surfaces.", ("internal", "admin", "grafana", "jenkins"), ("admin", "internal")),
        TestTemplate("Infrastructure", "SSRF in webhook/callback integrations", "Tests server-side egress filtering.", ("webhook", "callback", "ssrf"), ("api", "hook")),
    ]
