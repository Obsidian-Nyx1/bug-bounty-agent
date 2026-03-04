"""RECON module: persist normalized intake artifacts for downstream steps."""

from __future__ import annotations

import csv
from dataclasses import asdict
import json
import re
from urllib.parse import urlparse

from bug_bounty_agent.modules.schemas import SessionLayout, ensure_layout

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def persist_recon_profile(layout: SessionLayout, result, program_url: str, program_hint: str | None) -> str:
    ensure_layout(layout)
    adaptive = _build_adaptive_recon_outputs(layout, result, program_url)
    discovery = getattr(result, "discovery_data", None) or {}
    payload = {
        "session_id": layout.session_id,
        "program_url": program_url,
        "program_hint": program_hint,
        "status": result.status,
        "summary": result.summary,
        "project_key": discovery.get("project_key") or "",
        "recommendation": asdict(result.recommendation),
        "scope_data": asdict(result.scope_data),
        "downloaded_artifact_reasons": list(result.downloaded_artifact_reasons),
        "sources": list(result.sources),
        "notes": list(result.notes),
        "test_matrix": [asdict(t) for t in result.test_matrix],
        "test_matrix_path": result.test_matrix_path,
        "report_path": result.report_path,
        "discovery_data": discovery,
        "adaptive_recon": adaptive,
    }
    layout.recon_profile_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(layout.recon_profile_file)


def _build_adaptive_recon_outputs(layout: SessionLayout, result, program_url: str) -> dict:
    discovery = getattr(result, "discovery_data", None) or {}
    scope_data = getattr(result, "scope_data", None)
    in_scope_raw = list(getattr(scope_data, "in_scope", []) or [])
    out_scope_raw = list(getattr(scope_data, "out_scope", []) or [])

    in_scope = _collect_domains(in_scope_raw + list(discovery.get("in_scope_domains", []) or []))
    out_scope = _collect_domains(out_scope_raw + list(discovery.get("out_scope_domains", []) or []))
    candidates = _collect_domains(list(discovery.get("domain_candidates", []) or []))
    normalized_scope_assets = _normalize_scope_assets(list(discovery.get("normalized_scope_assets", []) or []))

    recommended = _normalize_domain(getattr(getattr(result, "recommendation", None), "domain", "") or "")
    if recommended and recommended not in candidates:
        candidates.append(recommended)

    scope_objects = []
    for asset in normalized_scope_assets:
        scope_objects.append(
            {
                "type": asset.get("asset_category") or "unknown",
                "value": asset.get("value") or "",
                "scope_status": asset.get("scope_status") or "unknown",
                "asset_type": asset.get("asset_type") or "UNKNOWN",
                "host": asset.get("host") or "",
                "normalized_domains": list(asset.get("normalized_domains", []) or []),
                "sources": list(asset.get("sources", []) or []),
            }
        )
    if not scope_objects:
        for domain in in_scope:
            status = "conflict" if domain in out_scope else "in-scope"
            scope_objects.append({"type": "domain", "value": domain, "scope_status": status})
        for domain in out_scope:
            if domain in in_scope:
                continue
            scope_objects.append({"type": "domain", "value": domain, "scope_status": "out-of-scope"})

    test_targets = {}
    test_categories = {}
    for test in list(getattr(result, "test_matrix", []) or []):
        target = _normalize_domain(getattr(test, "target", "") or "")
        if not target:
            continue
        test_targets[target] = test_targets.get(target, 0) + 1
        category = str(getattr(test, "category", "") or "")
        if category:
            key = f"{target}:{category}"
            test_categories[key] = test_categories.get(key, 0) + 1

    program_host = _normalize_domain(urlparse(program_url).hostname or "")
    graph = _build_graph(
        program_url=program_url,
        program_host=program_host,
        in_scope=in_scope,
        out_scope=out_scope,
        candidates=candidates,
        recommended=recommended,
        test_targets=test_targets,
        test_categories=test_categories,
    )

    state_summary = _build_state_summary(graph)
    gates = _evaluate_readiness_gates(graph, in_scope, out_scope)
    tier = _decide_tier(state_summary, gates)

    scope_log = {
        "tier": tier,
        "gates": gates,
        "in_scope_count": len(in_scope),
        "out_scope_count": len(out_scope),
        "recommended_domain": recommended or None,
        "note": "Outputs are evidence-adaptive. TESTS queue is exported only when readiness gates pass.",
    }

    state_summary_file = layout.recon_dir / "state_summary.json"
    scope_log_file = layout.recon_dir / "scope_decision_log.json"
    scope_inventory_file = layout.recon_dir / "normalized_scope_inventory.json"
    state_summary_file.write_text(json.dumps(state_summary, indent=2), encoding="utf-8")
    scope_log_file.write_text(json.dumps(scope_log, indent=2), encoding="utf-8")
    scope_inventory_file.write_text(json.dumps(normalized_scope_assets, indent=2), encoding="utf-8")

    graph_file = None
    queue_csv_file = None
    tests_queue_file = None

    if state_summary["scoped_assets"] > 0:
        graph_file = layout.recon_dir / "graph.json"
        graph_file.write_text(json.dumps(graph, indent=2), encoding="utf-8")

        queue_csv_file = layout.recon_dir / "asset_queue.csv"
        _write_asset_queue_csv(queue_csv_file, graph)

    if tier == "A_FULL" and any(item.get("passed") is False for item in gates) is False:
        tests_queue = _build_tests_queue(graph, list(getattr(result, "test_matrix", []) or []))
        if tests_queue:
            tests_queue_file = layout.recon_dir / "tests_queue.json"
            tests_queue_file.write_text(json.dumps(tests_queue, indent=2), encoding="utf-8")

    artifacts = {
        "state_summary": str(state_summary_file),
        "scope_decision_log": str(scope_log_file),
        "normalized_scope_inventory": str(scope_inventory_file),
        "graph": str(graph_file) if graph_file else None,
        "asset_queue_csv": str(queue_csv_file) if queue_csv_file else None,
        "tests_queue": str(tests_queue_file) if tests_queue_file else None,
    }

    return {
        "tier": tier,
        "artifacts": artifacts,
        "scope_objects": scope_objects,
        "normalized_scope_assets": normalized_scope_assets,
        "state_summary": state_summary,
        "gates": gates,
    }


def _build_graph(
    program_url: str,
    program_host: str,
    in_scope: list[str],
    out_scope: list[str],
    candidates: list[str],
    recommended: str,
    test_targets: dict[str, int],
    test_categories: dict[str, int],
) -> dict:
    nodes = []
    edges = []

    program_id = "program:root"
    nodes.append(
        {
            "id": program_id,
            "type": "program",
            "value": program_url,
            "state": "NEW",
            "scope_status": "n/a",
            "scores": {"risk": 0, "confidence": 100, "exploitability": 0, "priority": 0},
            "reasons": ["PROGRAM_INPUT"],
        }
    )

    all_domains = _uniq(candidates + in_scope + out_scope)
    for domain in all_domains:
        if not domain:
            continue
        is_in = domain in in_scope
        is_out = domain in out_scope
        evidence_types = []
        evidence_score = 0

        if is_in:
            evidence_types.append("IN_SCOPE_SOURCE")
            evidence_score += 3
        if domain in candidates:
            evidence_types.append("DISCOVERY_CANDIDATE")
            evidence_score += 1
        if recommended and domain == recommended:
            evidence_types.append("RECOMMENDED_DOMAIN")
            evidence_score += 2
        tests = test_targets.get(domain, 0)
        if tests:
            evidence_types.append("TEST_MATRIX_TARGET")
            evidence_score += min(3, tests)

        conflict = is_in and is_out
        if conflict:
            evidence_types.append("SCOPE_CONFLICT")

        category_count = 0
        for key, value in test_categories.items():
            host, _, _ = key.partition(":")
            if host == domain and value > 0:
                category_count += 1

        confidence = min(100, evidence_score * 18 + len(set(evidence_types)) * 8)
        if conflict:
            confidence = max(0, confidence - 35)

        risk = 25
        for token, inc in [
            ("api", 12),
            ("auth", 12),
            ("admin", 14),
            ("account", 9),
            ("billing", 10),
            ("pay", 8),
            ("upload", 9),
            ("cdn", 5),
        ]:
            if token in domain:
                risk += inc
        risk += min(18, tests * 3)
        risk += min(12, category_count * 4)
        risk = min(100, risk)

        exploitability = 35 + min(25, tests * 4)
        if program_host and (domain == program_host or domain.endswith("." + program_host)):
            exploitability += 12
        exploitability = min(100, exploitability)

        priority = int((risk * 0.55) + (confidence * 0.25) + (exploitability * 0.20))

        state = "NEW"
        scope_status = "unknown"
        if conflict:
            scope_status = "conflict"
            state = "NEW"
        elif is_out:
            scope_status = "out-of-scope"
            state = "NEW"
        elif is_in:
            scope_status = "in-scope"
            state = "SCOPED"
            if confidence >= 45 and evidence_score >= 4:
                state = "VERIFIED"
            if tests >= 1 and state in {"VERIFIED", "SCOPED"}:
                state = "MAPPED"
            if (category_count >= 2 or tests >= 2) and state in {"MAPPED", "VERIFIED", "SCOPED"}:
                state = "ENRICHED"
            if priority >= 65 and confidence >= 55 and not conflict:
                state = "PRIORITIZED"

        node_id = f"domain:{domain}"
        nodes.append(
            {
                "id": node_id,
                "type": "domain",
                "value": domain,
                "state": state,
                "scope_status": scope_status,
                "scores": {
                    "risk": risk,
                    "confidence": confidence,
                    "exploitability": exploitability,
                    "priority": priority,
                },
                "reasons": _uniq(evidence_types),
                "tests_count": tests,
                "category_count": category_count,
            }
        )
        edges.append(
            {
                "from": program_id,
                "to": node_id,
                "relation": "contains",
                "scope_status": scope_status,
            }
        )

    return {"nodes": nodes, "edges": edges}


def _build_state_summary(graph: dict) -> dict:
    counts = {
        "NEW": 0,
        "SCOPED": 0,
        "EXPANDED": 0,
        "VERIFIED": 0,
        "MAPPED": 0,
        "ENRICHED": 0,
        "PRIORITIZED": 0,
        "EXPORTED": 0,
    }
    scoped_assets = 0
    prioritized_assets = 0
    verified_assets = 0
    confidence_values = []

    for node in graph.get("nodes", []):
        if node.get("type") != "domain":
            continue
        state = node.get("state", "NEW")
        if state in counts:
            counts[state] += 1
        if node.get("scope_status") == "in-scope":
            scoped_assets += 1
            confidence_values.append(int(node.get("scores", {}).get("confidence", 0)))
        if state == "PRIORITIZED":
            prioritized_assets += 1
        if state in {"VERIFIED", "MAPPED", "ENRICHED", "PRIORITIZED", "EXPORTED"}:
            verified_assets += 1

    avg_conf = int(sum(confidence_values) / len(confidence_values)) if confidence_values else 0
    return {
        "state_counts": counts,
        "scoped_assets": scoped_assets,
        "verified_assets": verified_assets,
        "prioritized_assets": prioritized_assets,
        "avg_scope_confidence": avg_conf,
    }


def _evaluate_readiness_gates(graph: dict, in_scope: list[str], out_scope: list[str]) -> list[dict]:
    scoped_set = set(in_scope)
    out_set = set(out_scope)
    conflicts = sorted(scoped_set.intersection(out_set))

    scoped_nodes = [
        node
        for node in graph.get("nodes", [])
        if node.get("type") == "domain" and node.get("scope_status") == "in-scope"
    ]
    verified_nodes = [
        node
        for node in scoped_nodes
        if node.get("state") in {"VERIFIED", "MAPPED", "ENRICHED", "PRIORITIZED", "EXPORTED"}
    ]

    min_verified = 1 if len(scoped_nodes) <= 2 else 2
    avg_conf = 0
    if scoped_nodes:
        avg_conf = int(
            sum(int(node.get("scores", {}).get("confidence", 0)) for node in scoped_nodes) / len(scoped_nodes)
        )

    gates = [
        {
            "name": "verified_assets_minimum",
            "required": min_verified,
            "actual": len(verified_nodes),
            "passed": len(verified_nodes) >= min_verified,
            "reason": "Need enough verified in-scope assets before exporting TESTS queue.",
        },
        {
            "name": "scope_confidence_threshold",
            "required": 55,
            "actual": avg_conf,
            "passed": avg_conf >= 55,
            "reason": "Average scope confidence must be at least 55.",
        },
        {
            "name": "scope_conflict_check",
            "required": 0,
            "actual": len(conflicts),
            "passed": len(conflicts) == 0,
            "reason": "In-scope/out-of-scope conflicts must be resolved.",
            "conflicts": conflicts[:20],
        },
    ]
    return gates


def _decide_tier(state_summary: dict, gates: list[dict]) -> str:
    if state_summary.get("scoped_assets", 0) <= 0:
        return "C_MINIMAL"
    all_passed = all(bool(item.get("passed")) for item in gates)
    if all_passed:
        return "A_FULL"
    return "B_PARTIAL"


def _write_asset_queue_csv(path, graph: dict) -> None:
    rows = []
    for node in graph.get("nodes", []):
        if node.get("type") != "domain":
            continue
        if node.get("scope_status") != "in-scope":
            continue
        scores = node.get("scores", {})
        rows.append(
            {
                "domain": node.get("value", ""),
                "state": node.get("state", ""),
                "risk": int(scores.get("risk", 0)),
                "confidence": int(scores.get("confidence", 0)),
                "exploitability": int(scores.get("exploitability", 0)),
                "priority": int(scores.get("priority", 0)),
                "tests_count": int(node.get("tests_count", 0)),
                "reasons": ", ".join(node.get("reasons", [])[:8]),
            }
        )
    rows.sort(key=lambda r: (r["priority"], r["confidence"], r["risk"]), reverse=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "domain",
                "state",
                "risk",
                "confidence",
                "exploitability",
                "priority",
                "tests_count",
                "reasons",
            ],
        )
        writer.writeheader()
        writer.writerows(rows[:300])


def _build_tests_queue(graph: dict, test_matrix: list) -> list[dict]:
    prioritized = [
        node
        for node in graph.get("nodes", [])
        if node.get("type") == "domain"
        and node.get("scope_status") == "in-scope"
        and node.get("state") in {"PRIORITIZED", "ENRICHED", "MAPPED", "VERIFIED"}
    ]
    prioritized.sort(
        key=lambda n: int(n.get("scores", {}).get("priority", 0)),
        reverse=True,
    )

    queue = []
    for node in prioritized[:50]:
        domain = node.get("value", "")
        suggested = []
        for test in test_matrix:
            target = _normalize_domain(getattr(test, "target", "") or "")
            if target != domain:
                continue
            suggested.append(
                {
                    "test_id": getattr(test, "test_id", ""),
                    "category": getattr(test, "category", ""),
                    "test_name": getattr(test, "test_name", ""),
                    "scope_basis": getattr(test, "scope_basis", ""),
                }
            )
            if len(suggested) >= 12:
                break

        queue.append(
            {
                "target": domain,
                "state": node.get("state", ""),
                "priority": int(node.get("scores", {}).get("priority", 0)),
                "confidence": int(node.get("scores", {}).get("confidence", 0)),
                "suggested_tests": suggested,
            }
        )

    return queue


def _collect_domains(values: list[str]) -> list[str]:
    domains = []
    for item in values:
        norm = _normalize_domain(item)
        if norm and norm not in domains:
            domains.append(norm)
    return domains


def _normalize_scope_assets(values: list[dict]) -> list[dict]:
    assets = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in values:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        asset_type = str(item.get("asset_type") or "UNKNOWN").strip().upper()
        scope_status = str(item.get("scope_status") or "unknown").strip().lower()
        host = _normalize_domain(str(item.get("host") or ""))
        if not value:
            continue
        key = (value, asset_type, scope_status, host)
        if key in seen:
            continue
        seen.add(key)
        sources = []
        for source in list(item.get("sources", []) or []):
            source_text = str(source).strip()
            if source_text and source_text not in sources:
                sources.append(source_text)
        single_source = str(item.get("source") or "").strip()
        if single_source and single_source not in sources:
            sources.append(single_source)
        assets.append(
            {
                "value": value,
                "asset_type": asset_type,
                "asset_category": str(item.get("asset_category") or "unknown").strip().lower(),
                "scope_status": scope_status,
                "sources": sources,
                "host": host,
                "normalized_hosts": _collect_domains(list(item.get("normalized_hosts", []) or [])),
                "normalized_domains": _collect_domains(list(item.get("normalized_domains", []) or [])),
                "protocol": str(item.get("protocol") or "").strip().lower(),
                "port": str(item.get("port") or "").strip(),
                "path": str(item.get("path") or "").strip(),
                "eligible_for_submission": str(item.get("eligible_for_submission") or "").strip().lower(),
                "eligible_for_bounty": str(item.get("eligible_for_bounty") or "").strip().lower(),
                "max_severity": str(item.get("max_severity") or "").strip().lower(),
                "instruction": str(item.get("instruction") or "").strip(),
            }
        )
    return assets


def _normalize_domain(value: str) -> str:
    raw = (value or "").strip().lower().strip(".")
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        raw = (urlparse(raw).hostname or "").lower().strip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    if not DOMAIN_RE.match(raw):
        return ""
    return raw


def _uniq(items: list[str]) -> list[str]:
    out = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out
