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
    selected = engine.analyze(BatchAnalysisRequest(**request_data))
    all_candidates = engine.analyze(
        BatchAnalysisRequest(**request_data, include_all_candidates=True)
    )
finally:
    engine.close()

assert selected.candidate_graph is None
assert selected.candidate_routes == []
assert all_candidates.candidate_graph is not None
assert len(all_candidates.candidate_routes) == all_candidates.available_route_count
assert [route.route_id for route in selected.selected_routes] == [
    route.route_id for route in all_candidates.selected_routes
]
assert [route.selection_rank for route in selected.selected_routes] == list(
    range(1, selected.selected_route_count + 1)
)
selected_nodes = {node.id for node in all_candidates.selected_graph.nodes}
selected_edges = {edge.id for edge in all_candidates.selected_graph.edges}
candidate_nodes = {node.id for node in all_candidates.candidate_graph.nodes}
candidate_edges = {edge.id for edge in all_candidates.candidate_graph.edges}
assert selected_nodes <= candidate_nodes
assert selected_edges <= candidate_edges

Path("step-a-example-default.json").write_text(
    selected.model_dump_json(indent=2, exclude_none=True), encoding="utf-8"
)
Path("step-a-example-all.json").write_text(
    all_candidates.model_dump_json(indent=2, exclude_none=True), encoding="utf-8"
)
summary = {
    "default": {
        "status": selected.status,
        "found_cves": selected.found_cves,
        "missing_cves": selected.missing_cves,
        "invalid_inputs": selected.invalid_inputs,
        "available_route_count": selected.available_route_count,
        "selected_route_count": selected.selected_route_count,
        "selected_graph": {
            "nodes": len(selected.selected_graph.nodes),
            "edges": len(selected.selected_graph.edges),
        },
        "candidate_graph_in_payload": selected.candidate_graph is not None,
        "selected_routes": [
            {
                "rank": route.selection_rank,
                "route_id": route.route_id,
                "cve_id": route.cve_id,
                "score": route.score,
                "basis": route.selection_basis,
            }
            for route in selected.selected_routes
        ],
        "shared_attack_selected": selected.shared_attack_techniques_selected,
        "shared_attack_all": selected.shared_attack_techniques_all_candidates,
        "shared_defenses_selected": selected.shared_defenses_selected,
        "shared_defenses_all": selected.shared_defenses_all_candidates,
    },
    "all_candidates": {
        "candidate_routes": len(all_candidates.candidate_routes),
        "candidate_graph": {
            "nodes": len(all_candidates.candidate_graph.nodes),
            "edges": len(all_candidates.candidate_graph.edges),
        },
        "selected_graph_is_subset": True,
    },
}
Path("step-a-example-summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
)
