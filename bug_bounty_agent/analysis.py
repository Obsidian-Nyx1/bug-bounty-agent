"""Step 3: Analyze collected scope data and generate test matrix."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import csv
from datetime import datetime, timezone

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

    templates = _base_templates()
    tests: list[TestCase] = []
    idx = 1
    target_cursor = 0
    for category, name, why in templates:
        target = targets[target_cursor % len(targets)]
        scope_basis = _scope_basis_for_target(target, scope_data, discovery)
        tests.append(
            TestCase(
                test_id=f"T{idx:03d}",
                category=category,
                test_name=name,
                target=target,
                scope_basis=scope_basis,
                why=why,
            )
        )
        idx += 1
        target_cursor += 1
        if len(tests) >= target_count:
            break

    if ai_ideas:
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
    notes = [f"Step 3 matrix generated with {len(tests)} tests."]
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


def _base_templates() -> list[tuple[str, str, str]]:
    return [
        ("Auth", "Account takeover via weak recovery flow", "High impact auth control weakness."),
        ("Auth", "MFA bypass through alternate flow", "Common bypass path in multi-channel auth."),
        ("Auth", "Session fixation after login", "Confirms session rotation on auth boundaries."),
        ("Auth", "Session token invalidation on logout", "Ensures logout revokes active sessions."),
        ("Auth", "Password reset token reuse", "Checks one-time token enforcement."),
        ("Access Control", "IDOR on profile object IDs", "Validates object-level authorization."),
        ("Access Control", "IDOR on payment/order references", "Checks direct object access in business data."),
        ("Access Control", "Horizontal privilege escalation", "Tests same-role user isolation."),
        ("Access Control", "Vertical privilege escalation", "Tests role boundary enforcement."),
        ("Access Control", "Forced browsing of admin endpoints", "Checks route-level authorization."),
        ("API", "Mass assignment in update endpoints", "Finds over-posting authorization issues."),
        ("API", "Hidden parameter privilege toggles", "Discovers unsafe debug/role parameters."),
        ("API", "Method confusion (GET/POST/PUT/DELETE)", "Finds verb-based auth inconsistencies."),
        ("API", "Broken object property authorization", "Checks field-level data exposure."),
        ("API", "GraphQL introspection exposure", "Identifies schema disclosure and attack surface."),
        ("Input Validation", "SQL injection on key query parameters", "Tests backend query sanitization."),
        ("Input Validation", "NoSQL injection on JSON fields", "Checks document query operator filtering."),
        ("Input Validation", "Command injection on integration hooks", "Validates shell command isolation."),
        ("Input Validation", "Template injection in render contexts", "Tests server-side templating safety."),
        ("Input Validation", "Path traversal in file/resource endpoints", "Checks filesystem boundary handling."),
        ("XSS", "Reflected XSS in search/input endpoints", "Tests output encoding for immediate reflections."),
        ("XSS", "Stored XSS in profile/comment fields", "Checks persistent rendering contexts."),
        ("XSS", "DOM XSS in client-side parsers", "Evaluates unsafe sink usage in JS."),
        ("CSRF", "State-changing action without anti-CSRF token", "Tests cross-site action protections."),
        ("CSRF", "CSRF bypass with content-type changes", "Checks strict token validation logic."),
        ("Rate Limiting", "Brute-force resilience on auth endpoints", "Validates lockout and throttling."),
        ("Rate Limiting", "OTP/code brute force resistance", "Checks verification flow throttling."),
        ("Rate Limiting", "Password reset abuse limits", "Prevents account disruption abuse."),
        ("Rate Limiting", "Business action abuse (coupon/refund)", "Protects economic workflows."),
        ("Rate Limiting", "API burst limits across tokens/IPs", "Tests distributed abuse resistance."),
        ("Business Logic", "Race condition on balance/order operations", "Detects double-spend style flaws."),
        ("Business Logic", "Workflow bypass via step skipping", "Checks required state transitions."),
        ("Business Logic", "Coupon/credit replay abuse", "Tests single-use enforcement."),
        ("Business Logic", "Negative quantity/price edge cases", "Validates monetary input constraints."),
        ("Business Logic", "State desync between web/mobile/API", "Finds inconsistent server validation."),
        ("File Upload", "Malicious file type upload bypass", "Tests extension/MIME verification."),
        ("File Upload", "Public bucket/object exposure post-upload", "Checks object ACL defaults."),
        ("File Upload", "Image processing SSRF via URL fetch", "Validates remote fetch restrictions."),
        ("File Upload", "Metadata/script payload persistence", "Tests sanitization of file metadata."),
        ("File Upload", "Overwrite/replace existing objects", "Checks object naming authorization."),
        ("Headers", "Host header injection behavior", "Finds trust on client-controlled host."),
        ("Headers", "Cache poisoning via response variations", "Tests cache key isolation."),
        ("Headers", "Open redirect through header manipulation", "Checks redirect target validation."),
        ("Token", "JWT algorithm confusion/none acceptance", "Validates signature enforcement."),
        ("Token", "JWT claim tampering (role/aud/iss)", "Checks robust claim validation."),
        ("Token", "Long-lived token replay on critical actions", "Tests token lifetime and rotation."),
        ("Infrastructure", "Subdomain takeover exposure", "Checks dangling DNS/service records."),
        ("Infrastructure", "CORS misconfiguration on sensitive APIs", "Prevents cross-origin data exfil."),
        ("Infrastructure", "Debug endpoints and verbose errors", "Reduces info leak and attack guidance."),
        ("Infrastructure", "Sensitive data in client-side bundles", "Detects exposed secrets/config."),
        ("Infrastructure", "Open cloud storage listing access", "Checks public bucket/object listing."),
        ("Infrastructure", "Unauthenticated internal tooling exposure", "Finds unintended public surfaces."),
        ("Infrastructure", "SSRF in webhook/callback integrations", "Tests server-side egress filtering."),
    ]
