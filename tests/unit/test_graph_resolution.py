from __future__ import annotations

from CVEzD3FEND.graph.builder import add_capec_db, build_attack_universe
from CVEzD3FEND.graph.context import GraphContext, make_edge
from CVEzD3FEND.graph.resolution import AttackUniverse, ConfidenceBasis, LifecycleState, ResolutionState, normalize_attack_id, resolve_attack_id
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.models.graph import EdgeType, NodeType
from CVEzD3FEND.util import now_iso


def _source() -> Source:
    return Source(
        source_id="cve2capec:capec_db",
        name="Test CAPEC DB",
        kind="capec_db",
        fetched_at=now_iso(),
        status="ok",
    )


def test_normalize_attack_id_pads_numeric_inputs():
    assert normalize_attack_id("1574.010") == "T1574.010"
    assert normalize_attack_id(" t1059 ") == "T1059"


def test_normalize_attack_id_rejects_non_numeric_inputs():
    assert normalize_attack_id("") == ""
    assert normalize_attack_id("ATTACK") == ""


def test_legacy_short_ids_are_rejected():
    universe = AttackUniverse.from_techniques_db({"T1059": []})
    for raw in ("34", "18"):
        result = resolve_attack_id(raw, universe)
        assert result.resolution_state is ResolutionState.INVALID
        assert not result.is_mappable
        assert result.resolution_method == "legacy_numeric_unmapped"


def test_exact_registry_match_uses_exact_id_basis():
    universe = AttackUniverse.from_techniques_db({"T1059": []})
    result = resolve_attack_id("T1059", universe)
    assert result.is_mappable
    assert result.lifecycle_state is LifecycleState.ACTIVE
    assert result.confidence_basis is ConfidenceBasis.EXACT_ID


def test_numeric_padding_is_traced_in_confidence_basis():
    universe = AttackUniverse.from_techniques_db({"T1574.010": []})
    result = resolve_attack_id("1574.010", universe)
    assert result.is_mappable
    assert result.confidence_basis is ConfidenceBasis.NUMERIC_PADDING
    assert result.normalized_candidate == "T1574.010"


def test_parent_family_match_keeps_real_subtechnique():
    universe = AttackUniverse.from_techniques_db({"T1562": []})
    result = resolve_attack_id("1562.003", universe)
    assert result.is_mappable
    assert result.confidence_basis is ConfidenceBasis.PARENT_IN_REGISTRY
    assert result.resolution_method == "subtechnique_parent_match"


def test_unavailable_registry_degrades_gracefully():
    universe = AttackUniverse.empty()
    result = resolve_attack_id("1574.010", universe)
    assert result.is_mappable
    assert result.lifecycle_state is LifecycleState.UNKNOWN
    assert result.confidence_basis is ConfidenceBasis.UNVERIFIED


def test_build_attack_universe_unions_all_sources_and_parent_families():
    universe = build_attack_universe(
        {"T1083": []},
        defend_records=[{"T1611": []}],
        atlas_data={"T1040": []},
        techniques_association={"T1562.001": {}},
    )
    assert universe.available
    assert "T1083" in universe.techniques
    assert "T1611" in universe.techniques
    assert "T1040" in universe.techniques
    assert "T1562" in universe.techniques


def test_edge_defaults_remain_backward_compatible():
    edge = make_edge(EdgeType.CVE_HAS_CWE, "CVE-1", "CWE-79")
    assert edge.resolution_state == "resolved"
    assert edge.lifecycle_state == "active"
    assert edge.scope_state == "included"
    assert edge.assertion_type == "canonical"
    assert edge.confidence_basis is None


def test_add_capec_db_records_unresolved_refs_without_phantoms():
    ctx = GraphContext()
    data = {
        "1": {
            "name": "Exact",
            "techniques": "TAXONOMY NAME:ATTACK:ENTRY ID:1574.010:ENTRY NAME:x::",
        },
        "2": {
            "name": "Legacy",
            "techniques": "TAXONOMY NAME:ATTACK:ENTRY ID:34:ENTRY NAME:y::",
        },
    }
    universe = AttackUniverse.from_techniques_db({"T1574.010": []})

    add_capec_db(ctx, data, _source(), universe)

    attack_ids = {node.id for node in ctx.nodes.values() if node.type is NodeType.ATTACK}
    assert "T1574.010" in attack_ids
    assert "T34" not in attack_ids

    edges = [edge for edge in ctx.edges.values() if edge.type is EdgeType.CAPEC_MAPS_TO_ATTACK]
    assert len(edges) == 1
    assert edges[0].confidence_basis == "numeric_padding"
    assert edges[0].metadata["resolution_method"] == "registry_exact_match"

    capec_2 = ctx.nodes["CAPEC-2"]
    unresolved = capec_2.metadata["unresolved_attack_refs"]
    assert unresolved[0]["raw_id"] == "34"
    assert any("unresolved" in warning for warning in ctx.warnings)


def test_capec_with_only_unresolved_attack_refs_writes_no_attack_edge():
    ctx = GraphContext()
    data = {
        "9": {
            "name": "Legacy only",
            "techniques": "TAXONOMY NAME:ATTACK:ENTRY ID:18:ENTRY NAME:z::",
        }
    }
    universe = AttackUniverse.from_techniques_db({"T1574.010": []})

    add_capec_db(ctx, data, _source(), universe)

    assert not [edge for edge in ctx.edges.values() if edge.type is EdgeType.CAPEC_MAPS_TO_ATTACK]
