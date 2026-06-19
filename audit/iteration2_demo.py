from __future__ import annotations

import json
from pathlib import Path

from CVEzD3FEND.config import Settings
from CVEzD3FEND.models.bundle import Bundle
from CVEzD3FEND.reasoning.batch import BatchReasoningEngine
from CVEzD3FEND.reasoning.models import BatchAnalysisRequest

settings = Settings()
bundle = Bundle.model_validate_json(settings.bundle_path.read_text(encoding="utf-8"))
request_data = {
    "cve_ids": [
        "CVE-2025-0168",
        "CVE-2026-0544",
        "CVE-2025-99999999",
        "invalid",
    ],
    "context": {
        "technologies": ["Windows", "Active Directory"],
        "exposure": ["internet-facing", "production"],
        "priorities": ["initial access", "credential theft"],
        "audience": "SOC",
    },
    "top_k": 5,
    "use_ai": False,
}
engine = BatchReasoningEngine(settings, bundle)
try:
    selected = engine.analyze(BatchAnalysisRequest(**request_data, include_all_candidates=False))
    all_candidates = engine.analyze(BatchAnalysisRequest(**request_data, include_all_candidates=True))
finally:
    engine.close()

assert selected.status == "partial"
assert selected.found_cves == ["CVE-2025-0168", "CVE-2026-0544"]
assert selected.missing_cves == ["CVE-2025-99999999"]
assert selected.invalid_inputs == ["INVALID"]
assert selected.available_route_count > 5
assert selected.selected_route_count == 5
assert selected.candidate_graph is None
assert all_candidates.candidate_graph is not None
assert len(all_candidates.candidate_routes) == all_candidates.available_route_count
assert [route.route_id for route in selected.selected_routes] == [route.route_id for route in all_candidates.selected_routes]
assert [route.selection_rank for route in selected.selected_routes] == [1, 2, 3, 4, 5]
selected_nodes = {node.id for node in all_candidates.selected_graph.nodes}
selected_edges = {edge.id for edge in all_candidates.selected_graph.edges}
candidate_nodes = {node.id for node in all_candidates.candidate_graph.nodes}
candidate_edges = {edge.id for edge in all_candidates.candidate_graph.edges}
assert selected_nodes <= candidate_nodes
assert selected_edges <= candidate_edges
assert selected.narrative.executive_summary_es
assert selected.narrative.operational_summary_es
assert selected.narrative.technical_summary_es
assert selected.provenance

Path("iteration2-real-selected.json").write_text(selected.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
Path("iteration2-real-all.json").write_text(all_candidates.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
summary = {
    "request": request_data,
    "found": selected.found_cves,
    "missing": selected.missing_cves,
    "invalid": selected.invalid_inputs,
    "available_routes": selected.available_route_count,
    "selected_routes": selected.selected_route_count,
    "ranking": [
        {
            "rank": route.selection_rank,
            "route_id": route.route_id,
            "cve_id": route.cve_id,
            "score": route.score,
            "basis": route.selection_basis,
            "attack_ids": route.attack_ids,
            "defend_ids": route.defend_ids,
        }
        for route in selected.selected_routes
    ],
    "selected_graph": {"nodes": len(selected.selected_graph.nodes), "edges": len(selected.selected_graph.edges)},
    "candidate_graph": {"nodes": len(all_candidates.candidate_graph.nodes), "edges": len(all_candidates.candidate_graph.edges)},
    "selected_subset_candidate": True,
    "attack_selected": selected.shared_attack_techniques_selected,
    "attack_all": selected.shared_attack_techniques_all_candidates,
    "defenses_selected": selected.shared_defenses_selected,
    "defenses_all": selected.shared_defenses_all_candidates,
    "selection_mode": selected.selection_summary.selection_mode,
    "fallback_used": selected.selection_summary.fallback_used,
    "narrative": selected.narrative.model_dump(mode="json"),
    "provenance_keys": sorted(selected.provenance),
}
Path("iteration2-real-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(summary, indent=2, ensure_ascii=False))
