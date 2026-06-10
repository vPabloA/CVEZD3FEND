from CVEzD3FEND.actions.soc_action_pack import build_soc_action_pack
from CVEzD3FEND.export.markdown import render_route_markdown, render_soc_action_pack_markdown


def _route_to_defend(bundle):
    return next(r for r in bundle.routes if r.start_node == "CVE-2099-0001" and r.end_node == "D3-FA")


def test_render_route_markdown_contains_key_sections(sample_bundle):
    route = _route_to_defend(sample_bundle)
    text = render_route_markdown(sample_bundle, route)

    assert text.startswith(f"# Route {route.route_id}: CVE-2099-0001 -> D3-FA")
    assert "## Summary" in text
    assert "## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)" in text
    assert "## Recommended Actions" in text
    assert "- **CTRL-D3-FA**" in text
    assert "## Detection Opportunities" in text
    assert "DET-T1059-D3-FA" in text
    assert "## Required Evidence / Logs" in text
    assert "EVID-DET-T1059-D3-FA" in text
    assert "## Mitigations" in text
    assert "MIT-D3-FA" in text
    assert "## Sources" in text
    assert "test:source" in text


def test_render_route_markdown_for_gapped_route_has_none_sections(sample_bundle):
    route = next(r for r in sample_bundle.routes if r.end_node == "T1059.001")
    text = render_route_markdown(sample_bundle, route)

    assert "## Recommended Actions" in text
    assert "## Gaps" in text
    assert "GAP-T1059_001-ATTACK_WITHOUT_DEFEND" in text


def test_render_soc_action_pack_markdown(sample_bundle):
    pack = build_soc_action_pack(sample_bundle, "T1059")
    text = render_soc_action_pack_markdown(sample_bundle, pack)

    assert text.startswith(f"# {pack.title}")
    assert pack.executive_summary in text
    assert "## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)" in text
    assert "## Hunting Hypotheses" in text
    assert "HUNT-T1059" in text
    assert "## Required Evidence / Logs" in text
    assert "DS-1" in text
    assert f"- Priority: {pack.priority}" in text
