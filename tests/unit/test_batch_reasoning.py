from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from CVEzD3FEND.config import Settings
from CVEzD3FEND.reasoning.batch import (
    BatchLimitError,
    BatchReasoningEngine,
    build_candidate_pool,
    normalize_cve_inputs,
)
from CVEzD3FEND.models.graph import EdgeType
from CVEzD3FEND.reasoning.models import BatchAnalysisRequest


def _write_year(settings: Settings, year: int, records: list[dict]) -> None:
    settings.ensure_dirs()
    with gzip.open(settings.sources_dir / f"CVE-{year}.jsonl.gz", "wt", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def _record(cve_id: str) -> dict:
    return {
        cve_id: {
            "CWE": ["79"],
            "CAPEC": ["100", "999"],
            "TECHNIQUES": ["1059", "9999"],
            "DEFEND": [{"id": "D3-FA"}, {"id": "D3-NOT-REAL"}],
        }
    }


def test_normalize_batch_input_lines_commas_whitespace_and_order():
    request = BatchAnalysisRequest(
        cve_ids="cve-2026-0001, CVE-2019-0002\nCVE-2026-0001 invalid"
    )
    valid, invalid = normalize_cve_inputs(request.cve_ids)
    assert valid == ["CVE-2026-0001", "CVE-2019-0002"]
    assert invalid == ["INVALID"]


def test_candidate_pool_uses_demonstrated_edges_not_cartesian_product(sample_bundle):
    payload = _record("CVE-2099-0002")["CVE-2099-0002"]
    pool = build_candidate_pool(
        sample_bundle,
        {"CVE-2099-0002": payload},
        [],
        max_routes=100,
    )

    assert pool.routes
    assert all("CAPEC-999" not in route.node_ids for route in pool.routes)
    assert all("T9999" not in route.node_ids for route in pool.routes)
    assert all("D3-NOT-REAL" not in route.node_ids for route in pool.routes)

    for route in pool.routes:
        assert len(route.edge_ids) == max(0, len(route.node_ids) - 1)
        for left, right, edge_id in zip(route.node_ids, route.node_ids[1:], route.edge_ids):
            edge = pool.edges[edge_id]
            assert (edge.source, edge.target) == (left, right)


def test_batch_scoring_convergence_reuse_and_bundle_immutability(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])
    before = sample_bundle.model_dump_json()

    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(
        BatchAnalysisRequest(
            cve_ids=["CVE-2099-0002", "CVE-2099-0001", "bad"],
            context={"technologies": ["PowerShell"], "audience": "SOC"},
            top_k=2,
        )
    )
    engine.close()

    assert sample_bundle.model_dump_json() == before
    assert result.found_cves == ["CVE-2099-0002", "CVE-2099-0001"]
    assert result.invalid_inputs == ["BAD"]
    assert result.available_route_count > result.selected_route_count
    assert len(result.selected_routes) == 2
    assert set(result.selection_summary.represented_cves) == {
        "CVE-2099-0001",
        "CVE-2099-0002",
    }
    assert "T1059" in result.shared_attack_techniques
    assert "D3-FA" in result.shared_defenses
    assert any("ATT&CK convergence" in reason for route in result.selected_routes for reason in route.selection_reasons)
    assert any("D3FEND defense reusable" in reason for route in result.selected_routes for reason in route.selection_reasons)


def test_top_k_smaller_than_eligible_cves_reports_unrepresented(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    cves = ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]
    _write_year(settings, 2099, [_record(cve_id) for cve_id in cves])

    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(BatchAnalysisRequest(cve_ids=cves, top_k=2))
    engine.close()

    assert result.selection_summary.eligible_cves == 3
    assert len(result.selection_summary.represented_cves) == 2
    assert len(result.selection_summary.unrepresented_cves) == 1
    assert result.selection_summary.representation_policy == "contextual_priority_due_to_top_k_constraint"
    assert len({route.cve_id for route in result.selected_routes}) == 2


def test_scoring_is_independent_of_input_order(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    cves = ["CVE-2099-0001", "CVE-2099-0002"]
    _write_year(settings, 2099, [_record(cve_id) for cve_id in cves])

    first = BatchReasoningEngine(settings, sample_bundle)
    first_result = first.analyze(
        BatchAnalysisRequest(cve_ids=cves, top_k=4, include_all_candidates=True)
    )
    first.close()
    second = BatchReasoningEngine(settings, sample_bundle)
    second_result = second.analyze(
        BatchAnalysisRequest(
            cve_ids=list(reversed(cves)), top_k=4, include_all_candidates=True
        )
    )
    second.close()

    first_scores = {route.route_id: route.score for route in first_result.candidate_routes}
    second_scores = {route.route_id: route.score for route in second_result.candidate_routes}
    assert first_scores == second_scores
    assert {route.route_id for route in first_result.selected_routes} == {
        route.route_id for route in second_result.selected_routes
    }


class _InvalidRouteProvider:
    name = "invalid-test"

    def complete(self, system: str, prompt: str) -> str:
        return json.dumps({"route_ids": ["ROUTE-DOES-NOT-EXIST"]})


class _ValidRouteProvider:
    name = "valid-test"

    def __init__(self) -> None:
        self.shortlist_ids: list[str] = []

    def complete(self, system: str, prompt: str) -> str:
        payload = json.loads(prompt)
        self.shortlist_ids = [route["route_id"] for route in payload["routes"]]
        return json.dumps({"route_ids": list(reversed(self.shortlist_ids))})


def test_ai_cannot_introduce_route_ids_and_falls_back(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path, ai_enabled=True)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])
    engine = BatchReasoningEngine(settings, sample_bundle, provider=_InvalidRouteProvider())
    result = engine.analyze(
        BatchAnalysisRequest(cve_ids=["CVE-2099-0001", "CVE-2099-0002"], top_k=2, use_ai=True)
    )
    engine.close()

    assert result.selection_summary.selection_mode == "deterministic"
    assert result.selection_summary.fallback_used is True
    assert any("unknown route ids" in warning for warning in result.warnings)
    assert all(route.route_id != "ROUTE-DOES-NOT-EXIST" for route in result.selected_routes)


def test_valid_ai_rerank_uses_only_deterministic_shortlist(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path, ai_enabled=True)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])
    provider = _ValidRouteProvider()
    engine = BatchReasoningEngine(settings, sample_bundle, provider=provider)
    result = engine.analyze(
        BatchAnalysisRequest(
            cve_ids=["CVE-2099-0001", "CVE-2099-0002"],
            top_k=2,
            use_ai=True,
            include_all_candidates=True,
        )
    )
    engine.close()

    assert result.selection_summary.selection_mode == "ai_reranked"
    assert result.selection_summary.fallback_used is False
    assert {route.route_id for route in result.selected_routes} <= set(provider.shortlist_ids)
    assert set(provider.shortlist_ids) <= {
        route.route_id for route in result.candidate_routes
    }


def test_batch_operational_limits_are_explicit(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path, max_batch_cves=1, max_batch_years=1)
    engine = BatchReasoningEngine(settings, sample_bundle)
    with pytest.raises(BatchLimitError, match="maximum is 1"):
        engine.analyze(BatchAnalysisRequest(cve_ids=["CVE-2019-0001", "CVE-2020-0002"]))
    engine.close()


def test_candidate_pool_ignores_build_time_top_routes_limit(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path, top_routes_per_cve=1)
    _write_year(settings, 2099, [_record("CVE-2099-0001")])
    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(
        BatchAnalysisRequest(
            cve_ids="CVE-2099-0001", top_k=10, include_all_candidates=True
        )
    )
    engine.close()

    assert result.available_route_count > settings.top_routes_per_cve
    assert any(route.completeness == 1.0 for route in result.candidate_routes)
    assert any(route.gaps for route in result.candidate_routes)


def test_distinct_year_limit_is_explicit(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path, max_batch_cves=10, max_batch_years=1)
    engine = BatchReasoningEngine(settings, sample_bundle)
    with pytest.raises(BatchLimitError, match="spans 2 years"):
        engine.analyze(BatchAnalysisRequest(cve_ids=["CVE-2019-0001", "CVE-2020-0002"]))
    engine.close()


def test_include_all_candidates_defaults_to_false():
    request = BatchAnalysisRequest(cve_ids="CVE-2099-0001")
    assert request.include_all_candidates is False


def test_selected_graph_is_always_present_and_candidate_graph_is_opt_in(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])

    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(
        BatchAnalysisRequest(cve_ids=["CVE-2099-0001", "CVE-2099-0002"], top_k=2)
    )
    engine.close()

    assert result.selected_graph.nodes
    assert result.selected_graph.edges
    assert result.candidate_graph is None
    assert result.candidate_routes == []
    assert result.nodes == result.selected_graph.nodes
    assert result.edges == result.selected_graph.edges


def test_candidate_graph_is_complete_deduplicated_and_preserves_ephemeral_provenance(
    tmp_path, sample_bundle
):
    settings = Settings(data_dir=tmp_path)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])

    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(
        BatchAnalysisRequest(
            cve_ids=["CVE-2099-0001", "CVE-2099-0002"],
            top_k=2,
            include_all_candidates=True,
        )
    )
    engine.close()

    assert result.candidate_graph is not None
    candidate_node_ids = {node.id for node in result.candidate_graph.nodes}
    candidate_edge_ids = {edge.id for edge in result.candidate_graph.edges}
    selected_node_ids = {node.id for node in result.selected_graph.nodes}
    selected_edge_ids = {edge.id for edge in result.selected_graph.edges}

    assert len(candidate_node_ids) == len(result.candidate_graph.nodes)
    assert len(candidate_edge_ids) == len(result.candidate_graph.edges)
    assert len(selected_node_ids) == len(result.selected_graph.nodes)
    assert len(selected_edge_ids) == len(result.selected_graph.edges)
    assert selected_node_ids <= candidate_node_ids
    assert selected_edge_ids <= candidate_edge_ids

    for route in result.candidate_routes:
        assert set(route.node_ids) <= candidate_node_ids
        assert set(route.edge_ids) <= candidate_edge_ids

    ephemeral = [
        edge
        for edge in result.candidate_graph.edges
        if edge.type == EdgeType.CVE_HAS_CWE and edge.metadata.get("request_scoped") is True
    ]
    assert ephemeral
    assert all(edge.source_ref == "cve2capec:cve_2099" for edge in ephemeral)
    assert all(edge.evidence for edge in ephemeral)
    assert "candidate_route_sources" in result.provenance


def test_selection_rank_is_stable_contiguous_and_independent_of_input_order(
    tmp_path, sample_bundle
):
    settings = Settings(data_dir=tmp_path)
    cves = ["CVE-2099-0001", "CVE-2099-0002"]
    _write_year(settings, 2099, [_record(cve_id) for cve_id in cves])

    engine = BatchReasoningEngine(settings, sample_bundle)
    first = engine.analyze(BatchAnalysisRequest(cve_ids=cves, top_k=4))
    second = engine.analyze(BatchAnalysisRequest(cve_ids=list(reversed(cves)), top_k=4))
    engine.close()

    first_order = [
        (route.route_id, route.selection_rank, route.selection_basis)
        for route in first.selected_routes
    ]
    second_order = [
        (route.route_id, route.selection_rank, route.selection_basis)
        for route in second.selected_routes
    ]
    assert first_order == second_order
    assert [route.selection_rank for route in first.selected_routes] == list(
        range(1, len(first.selected_routes) + 1)
    )
    assert len({route.selection_rank for route in first.selected_routes}) == len(
        first.selected_routes
    )
    assert {route.selection_basis for route in first.selected_routes} <= {
        "coverage_floor",
        "contextual_utility",
    }


def test_top_k_constraint_has_explicit_selection_basis(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    cves = ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]
    _write_year(settings, 2099, [_record(cve_id) for cve_id in cves])

    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(BatchAnalysisRequest(cve_ids=cves, top_k=2))
    engine.close()

    assert {route.selection_basis for route in result.selected_routes} == {"top_k_constraint"}
    assert [route.selection_rank for route in result.selected_routes] == [1, 2]


def test_selected_and_all_candidate_convergences_are_distinct_and_narrative_uses_selected(
    tmp_path, sample_bundle
):
    settings = Settings(data_dir=tmp_path)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])

    engine = BatchReasoningEngine(settings, sample_bundle)
    result = engine.analyze(
        BatchAnalysisRequest(
            cve_ids=["CVE-2099-0001", "CVE-2099-0002"],
            top_k=1,
            include_all_candidates=True,
        )
    )
    engine.close()

    assert result.shared_attack_techniques_selected == []
    assert "T1059" in result.shared_attack_techniques_all_candidates
    assert result.shared_defenses_selected == []
    assert "D3-FA" in result.shared_defenses_all_candidates
    assert result.shared_attack_techniques == result.shared_attack_techniques_selected
    assert result.shared_defenses == result.shared_defenses_selected
    assert "sin convergencias seleccionadas" in result.narrative.operational_summary_es
    assert "T1059" not in result.narrative.operational_summary_es


def test_audience_changes_presentation_not_deterministic_ranking(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    cves = ["CVE-2099-0001", "CVE-2099-0002"]
    _write_year(settings, 2099, [_record(cve_id) for cve_id in cves])

    engine = BatchReasoningEngine(settings, sample_bundle)
    soc = engine.analyze(
        BatchAnalysisRequest(cve_ids=cves, top_k=2, context={"audience": "SOC"})
    )
    executive = engine.analyze(
        BatchAnalysisRequest(cve_ids=cves, top_k=2, context={"audience": "Executive"})
    )
    engine.close()

    assert [route.route_id for route in soc.selected_routes] == [
        route.route_id for route in executive.selected_routes
    ]
    assert [route.selection_rank for route in soc.selected_routes] == [
        route.selection_rank for route in executive.selected_routes
    ]
    assert "Para SOC" in soc.narrative.operational_summary_es
    assert "Para Executive" in executive.narrative.operational_summary_es


def test_valid_ai_rerank_has_validated_order_and_ai_basis(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path, ai_enabled=True)
    _write_year(settings, 2099, [_record("CVE-2099-0001"), _record("CVE-2099-0002")])
    provider = _ValidRouteProvider()
    engine = BatchReasoningEngine(settings, sample_bundle, provider=provider)
    result = engine.analyze(
        BatchAnalysisRequest(
            cve_ids=["CVE-2099-0001", "CVE-2099-0002"],
            top_k=2,
            use_ai=True,
            include_all_candidates=True,
        )
    )
    engine.close()

    candidate_ids = {route.route_id for route in result.candidate_routes}
    assert result.selection_summary.selection_mode == "ai_reranked"
    assert all(route.route_id in candidate_ids for route in result.selected_routes)
    assert {route.route_id for route in result.selected_routes} <= set(provider.shortlist_ids)
    assert [route.selection_rank for route in result.selected_routes] == [1, 2]
    assert {route.selection_basis for route in result.selected_routes} == {"ai_rerank"}
