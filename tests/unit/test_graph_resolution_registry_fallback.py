from __future__ import annotations

from CVEzD3FEND.graph.builder import add_capec_db, build_attack_universe
from CVEzD3FEND.graph.context import GraphContext
from CVEzD3FEND.graph.resolution import ConfidenceBasis, LifecycleState, resolve_attack_id
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.models.graph import EdgeType
from CVEzD3FEND.util import now_iso


def _source() -> Source:
    return Source(
        source_id="cve2capec:capec_db",
        name="Test CAPEC DB",
        kind="capec_db",
        fetched_at=now_iso(),
        status="ok",
    )


def test_auxiliary_ids_do_not_make_missing_attack_registry_available():
    universe = build_attack_universe(
        {},
        defend_records=[{"T1611": []}],
        atlas_data={"T1040": []},
        techniques_association={"T1562.001": {}},
    )

    assert not universe.available
    assert "T1611" in universe.techniques
    assert "T1040" in universe.techniques
    assert "T1562" in universe.techniques

    result = resolve_attack_id("1574.010", universe)
    assert result.is_mappable
    assert result.lifecycle_state is LifecycleState.UNKNOWN
    assert result.confidence_basis is ConfidenceBasis.UNVERIFIED
    assert result.resolution_method == "structural_only_registry_unavailable"


def test_capec_mapping_uses_structural_fallback_when_registry_is_missing_but_auxiliary_ids_exist():
    universe = build_attack_universe(
        {},
        defend_records=[{"T1611": []}],
        atlas_data={},
        techniques_association={},
    )
    ctx = GraphContext()
    data = {
        "42": {
            "name": "Registry outage fallback",
            "techniques": "TAXONOMY NAME:ATTACK:ENTRY ID:1574.010:ENTRY NAME:x::",
        }
    }

    add_capec_db(ctx, data, _source(), universe)

    edges = [edge for edge in ctx.edges.values() if edge.type is EdgeType.CAPEC_MAPS_TO_ATTACK]
    assert len(edges) == 1
    assert edges[0].target == "T1574.010"
    assert edges[0].confidence_basis == "unverified"
    assert edges[0].metadata["resolution_method"] == "structural_only_registry_unavailable"
