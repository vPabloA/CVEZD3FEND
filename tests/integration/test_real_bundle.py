"""Integration checks against the real generated `data/dist/knowledge-bundle.json`.

These tests are skipped (not failed) if the bundle hasn't been built yet —
run `make build` first. They exercise the same read paths the CLI/API/web
frontend use against production data.
"""

from __future__ import annotations

from CVEzD3FEND.actions.soc_action_pack import build_soc_action_pack
from CVEzD3FEND.export.markdown import render_route_markdown, render_soc_action_pack_markdown
from CVEzD3FEND.lookup import resolve_attack_id, resolve_route, search_nodes
from CVEzD3FEND.validation.schema import validate_structure


def test_bundle_passes_structural_validation(real_bundle):
    assert validate_structure(real_bundle) == []


def test_bundle_has_expected_top_level_shape(real_bundle):
    assert real_bundle.nodes
    assert real_bundle.edges
    assert real_bundle.routes
    assert real_bundle.coverage.techniques
    assert real_bundle.schema_version


def test_search_finds_known_cve(real_bundle):
    results = search_nodes(real_bundle, "CVE-2025-0168", limit=5)
    assert any(n.id == "CVE-2025-0168" for n in results)


def test_resolve_route_for_first_route(real_bundle):
    expected = real_bundle.routes[0]
    resolved = resolve_route(real_bundle, expected.route_id)
    assert resolved is not None
    assert resolved.route_id == expected.route_id


def test_resolve_route_via_cve_id(real_bundle):
    cve_routes = real_bundle.indexes.get("cve_routes", {})
    cve_id, route_ids = next(iter(cve_routes.items()))
    resolved = resolve_route(real_bundle, cve_id)
    assert resolved is not None
    assert resolved.route_id == route_ids[0]


def test_render_route_markdown_for_real_route(real_bundle):
    route = real_bundle.routes[0]
    text = render_route_markdown(real_bundle, route)
    assert text.startswith(f"# Route {route.route_id}")
    assert "## Summary" in text


def test_soc_action_pack_for_attack_with_defend(real_bundle):
    attack_to_defend = real_bundle.indexes.get("attack_to_defend", {})
    attack_id = next(iter(attack_to_defend))
    pack = build_soc_action_pack(real_bundle, attack_id)
    assert pack.id == f"PACK-{attack_id.replace('.', '_')}"
    assert pack.defensive_path

    text = render_soc_action_pack_markdown(real_bundle, pack)
    assert text.startswith(f"# {pack.title}")


def test_soc_action_pack_for_gap_attack(real_bundle):
    gap_technique = next(
        (t for t in real_bundle.coverage.techniques if t.coverage_status == "gap"), None
    )
    if gap_technique is None:
        return
    pack = build_soc_action_pack(real_bundle, gap_technique.attack_technique)
    assert pack.priority == "High"
    assert pack.confidence == 0.30


def test_resolve_attack_id_from_route(real_bundle):
    route = next(r for r in real_bundle.routes if "attack" in r.path)
    attack_id = route.nodes[route.path.index("attack")]
    assert resolve_attack_id(real_bundle, route.route_id) == attack_id
