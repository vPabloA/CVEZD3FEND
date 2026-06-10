"""Deterministic SOC Action Pack generation, one per ATT&CK technique.

Every field is a read-only projection over `bundle.nodes`/`edges`/`indexes` —
no AI, no invented ids (per AI_ASSISTANCE_CONTRACT, "the graph validates, AI
proposes, human promotes"; this generator is part of "the graph validates").
"""

from __future__ import annotations

from CVEzD3FEND.models.bundle import Bundle
from CVEzD3FEND.models.graph import EdgeType, Node, NodeType
from CVEzD3FEND.models.soc import Priority, SocActionPack
from CVEzD3FEND.util import safe_id_fragment

_PRIORITY_BY_COVERAGE: dict[str, Priority] = {
    "gap": "High",
    "partial": "Medium",
    "covered": "Low",
    "unknown": "Medium",
}
_CONFIDENCE_BY_COVERAGE = {"gap": 0.30, "partial": 0.60, "covered": 1.0, "unknown": 0.30}


def build_soc_action_pack(bundle: Bundle, attack_id: str) -> SocActionPack:
    nodes_by_id: dict[str, Node] = {n.id: n for n in bundle.nodes}
    attack_node = nodes_by_id.get(attack_id)
    if attack_node is None or attack_node.type != NodeType.ATTACK:
        raise ValueError(f"Unknown ATT&CK technique: {attack_id}")

    indexes = bundle.indexes
    defend_ids: list[str] = indexes.get("attack_to_defend", {}).get(attack_id, [])
    detections: list[str] = indexes.get("attack_to_detections", {}).get(attack_id, [])
    coverage_status: str = indexes.get("coverage_by_technique", {}).get(attack_id, "unknown")
    gap_ids: list[str] = indexes.get("gaps_by_technique", {}).get(attack_id, [])

    controls: list[str] = []
    mitigations: list[str] = []
    for d in defend_ids:
        for c in indexes.get("defend_to_controls", {}).get(d, []):
            if c not in controls:
                controls.append(c)
        mit_id = f"MIT-{d}"
        if mit_id in nodes_by_id and mit_id not in mitigations:
            mitigations.append(mit_id)

    soc_actions: list[str] = []
    for e in bundle.edges:
        if e.type == EdgeType.SOC_ACTION_OPERATIONALIZES_DEFEND and e.target in defend_ids:
            if e.source not in soc_actions:
                soc_actions.append(e.source)

    evidence: list[str] = []
    data_sources: list[str] = []
    log_sources: list[str] = []
    detection_set = set(detections)
    for e in bundle.edges:
        if e.type == EdgeType.EVIDENCE_SUPPORTS_DETECTION and e.target in detection_set:
            if e.source not in evidence:
                evidence.append(e.source)
        elif e.type == EdgeType.DATA_SOURCE_ENABLES_DETECTION and e.target in detection_set:
            src_node = nodes_by_id.get(e.source)
            if src_node and src_node.type == NodeType.LOG_SOURCE and e.source not in log_sources:
                log_sources.append(e.source)
            elif src_node and src_node.type == NodeType.DATA_SOURCE and e.source not in data_sources:
                data_sources.append(e.source)

    hunt_id = f"HUNT-{safe_id_fragment(attack_id)}"
    hunting_hypotheses = [hunt_id] if hunt_id in nodes_by_id else []

    attack_path: list[str] = [attack_id]
    for r in bundle.routes:
        if r.start_node.startswith("CVE-") and attack_id in r.nodes:
            attack_path = r.nodes
            break

    defensive_path = [*defend_ids, *controls]

    source_refs: list[str] = []
    for nid in [attack_id, *defend_ids, *controls, *detections]:
        node = nodes_by_id.get(nid)
        if not node:
            continue
        for ref in node.source_refs:
            if ref not in source_refs:
                source_refs.append(ref)

    executive_summary = (
        f"{attack_id} ({attack_node.name}) is currently '{coverage_status}'. "
        f"{len(defend_ids)} D3FEND technique(s), {len(detections)} detection opportunity(ies), "
        f"and {len(gap_ids)} open gap(s) are tracked for this technique."
    )
    technical_summary = (
        f"D3FEND mappings: {', '.join(defend_ids) or 'none'}. "
        f"Controls: {', '.join(controls) or 'none'}. "
        f"Mitigations: {', '.join(mitigations) or 'none'}. "
        f"Detections: {', '.join(detections) or 'none'}."
    )

    return SocActionPack(
        id=f"PACK-{safe_id_fragment(attack_id)}",
        title=f"SOC Action Pack: {attack_node.name} ({attack_id})",
        executive_summary=executive_summary,
        technical_summary=technical_summary,
        attack_path=attack_path,
        defensive_path=defensive_path,
        recommended_actions=[*controls, *soc_actions],
        hunting_hypotheses=hunting_hypotheses,
        detection_opportunities=detections,
        required_logs=[*data_sources, *log_sources],
        required_evidence=evidence,
        mitigations=mitigations,
        gaps=gap_ids,
        priority=_PRIORITY_BY_COVERAGE.get(coverage_status, "Medium"),
        confidence=_CONFIDENCE_BY_COVERAGE.get(coverage_status, 0.30),
        source_refs=source_refs,
    )


def build_all_soc_action_packs(bundle: Bundle) -> list[SocActionPack]:
    return [
        build_soc_action_pack(bundle, n.id)
        for n in sorted(bundle.nodes, key=lambda x: x.id)
        if n.type == NodeType.ATTACK
    ]
