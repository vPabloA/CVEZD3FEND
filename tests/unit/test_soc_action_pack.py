import pytest

from CVEzD3FEND.actions.soc_action_pack import build_all_soc_action_packs, build_soc_action_pack


def test_build_soc_action_pack_for_covered_technique(sample_bundle):
    pack = build_soc_action_pack(sample_bundle, "T1059")

    assert pack.id == "PACK-T1059"
    assert "T1059" in pack.title
    assert pack.priority == "Low"
    assert pack.confidence == 1.0
    assert pack.defensive_path == ["D3-FA", "CTRL-D3-FA"]
    assert pack.recommended_actions == ["CTRL-D3-FA"]
    assert pack.hunting_hypotheses == ["HUNT-T1059"]
    assert pack.detection_opportunities == ["DET-T1059-D3-FA"]
    assert pack.required_evidence == ["EVID-DET-T1059-D3-FA"]
    assert pack.required_logs == ["DS-1"]
    assert pack.mitigations == ["MIT-D3-FA"]
    assert pack.gaps == []
    assert pack.attack_path[0] == "CVE-2099-0001"
    assert pack.attack_path[-1] == "D3-FA"
    assert "test:source" in pack.source_refs


def test_build_soc_action_pack_for_gapped_technique(sample_bundle):
    pack = build_soc_action_pack(sample_bundle, "T1059.001")

    assert pack.priority == "High"
    assert pack.confidence == 0.30
    assert pack.defensive_path == []
    assert pack.recommended_actions == []
    assert pack.hunting_hypotheses == []
    assert pack.detection_opportunities == []
    assert pack.gaps == ["GAP-T1059_001-ATTACK_WITHOUT_DEFEND"]


def test_build_soc_action_pack_unknown_id_raises(sample_bundle):
    with pytest.raises(ValueError):
        build_soc_action_pack(sample_bundle, "NOT-AN-ATTACK-ID")


def test_build_soc_action_pack_non_attack_node_raises(sample_bundle):
    with pytest.raises(ValueError):
        build_soc_action_pack(sample_bundle, "D3-FA")


def test_build_all_soc_action_packs_covers_every_attack_node(sample_bundle):
    packs = build_all_soc_action_packs(sample_bundle)
    pack_ids = {p.id for p in packs}
    assert pack_ids == {"PACK-T1059", "PACK-T1059_001"}
