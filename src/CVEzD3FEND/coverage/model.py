"""Coverage computation + first-class `gap`/`ctem_action` generation.

Implements the `gap_blocks_coverage` / `ctem_action_prioritizes_gap` rules of
contracts/MAPPING_CONTRACT.md and the Coverage shape of contracts/BUNDLE_CONTRACT.md.

Gap generation is capped per-reason (`settings.max_gaps_per_reason`) to keep
the static bundle bounded (UIX_CONTRACT — UI never floods). True totals are
always reported via `CoverageResult.gap_totals` so `quality-report.json` never
silently under-reports the real gap count.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from CVEzD3FEND.config import Settings
from CVEzD3FEND.graph.catalogs import GAP_REASON_DESCRIPTIONS
from CVEzD3FEND.graph.context import GraphContext, make_edge, make_node
from CVEzD3FEND.models.bundle import Coverage, CoverageSummary, CoverageTechnique
from CVEzD3FEND.models.graph import EdgeType, NodeType
from CVEzD3FEND.util import safe_id_fragment

GAP_SOURCE_REF = "CVEzD3FEND:coverage_engine"


@dataclass
class CoverageResult:
    coverage: Coverage
    coverage_by_attack: dict[str, str] = field(default_factory=dict)
    gap_totals: dict[str, int] = field(default_factory=dict)
    gap_emitted: dict[str, int] = field(default_factory=dict)


def compute_coverage(ctx: GraphContext, settings: Settings) -> CoverageResult:
    nodes = ctx.nodes
    edges = list(ctx.edges.values())
    cap = settings.max_gaps_per_reason

    attack_to_defend: dict[str, list[tuple[str, str | None]]] = {}
    defend_to_controls: dict[str, list[str]] = {}
    attack_to_detections: dict[str, list[str]] = {}
    detection_to_evidence: dict[str, list[str]] = {}
    detection_to_data: dict[str, list[str]] = {}
    detection_to_log: dict[str, list[str]] = {}
    cve_has_cwe: set[str] = set()
    cwe_has_capec: set[str] = set()
    capec_has_attack: set[str] = set()

    for e in edges:
        if e.type == EdgeType.ATTACK_MAPS_TO_DEFEND:
            attack_to_defend.setdefault(e.source, []).append((e.target, e.metadata.get("tactic")))
        elif e.type == EdgeType.CONTROL_IMPLEMENTS_DEFEND:
            defend_to_controls.setdefault(e.target, []).append(e.source)
        elif e.type == EdgeType.DETECTION_DETECTS_ATTACK:
            attack_to_detections.setdefault(e.target, []).append(e.source)
        elif e.type == EdgeType.EVIDENCE_SUPPORTS_DETECTION:
            detection_to_evidence.setdefault(e.target, []).append(e.source)
        elif e.type == EdgeType.DATA_SOURCE_ENABLES_DETECTION:
            src_node = nodes.get(e.source)
            if src_node is None:
                continue
            if src_node.type == NodeType.DATA_SOURCE:
                detection_to_data.setdefault(e.target, []).append(e.source)
            elif src_node.type == NodeType.LOG_SOURCE:
                detection_to_log.setdefault(e.target, []).append(e.source)
        elif e.type == EdgeType.CVE_HAS_CWE:
            cve_has_cwe.add(e.source)
        elif e.type == EdgeType.CWE_MAPS_TO_CAPEC:
            cwe_has_capec.add(e.source)
        elif e.type == EdgeType.CAPEC_MAPS_TO_ATTACK:
            capec_has_attack.add(e.source)

    gap_totals = {k: 0 for k in GAP_REASON_DESCRIPTIONS}
    gap_emitted = {k: 0 for k in GAP_REASON_DESCRIPTIONS}

    def emit_gap(reason: str, target_id: str) -> None:
        gap_totals[reason] += 1
        if gap_emitted[reason] >= cap:
            return
        gap_emitted[reason] += 1
        gap_id = f"GAP-{safe_id_fragment(target_id)}-{reason.upper()}"
        ctx.add_node(
            make_node(
                gap_id,
                NodeType.GAP,
                f"Gap: {reason} ({target_id})",
                description=f"{GAP_REASON_DESCRIPTIONS[reason]} Target: {target_id}.",
                source_refs=[GAP_SOURCE_REF],
                confidence=1.0,
                metadata={"reason": reason, "target": target_id, "derivation": "coverage_engine"},
            )
        )
        ctx.add_edge(
            make_edge(
                EdgeType.GAP_BLOCKS_COVERAGE,
                gap_id,
                target_id,
                confidence=1.0,
                source_ref=GAP_SOURCE_REF,
                metadata={"reason": reason, "derivation": "coverage_engine"},
            )
        )
        ctem_id = f"CTEM-{gap_id}"
        ctx.add_node(
            make_node(
                ctem_id,
                NodeType.CTEM_ACTION,
                f"CTEM action: remediate {gap_id}",
                description=(
                    f"Prioritized CTEM action to remediate {gap_id} "
                    f"({GAP_REASON_DESCRIPTIONS[reason]})"
                ),
                source_refs=[GAP_SOURCE_REF],
                confidence=0.30,
                metadata={"template": True, "gap": gap_id, "reason": reason},
            )
        )
        ctx.add_edge(
            make_edge(
                EdgeType.CTEM_ACTION_PRIORITIZES_GAP,
                ctem_id,
                gap_id,
                confidence=0.30,
                source_ref=GAP_SOURCE_REF,
                metadata={"template": True, "derivation": "coverage_engine"},
            )
        )

    for node_id, node in sorted(nodes.items()):
        if node.type == NodeType.CVE and node_id not in cve_has_cwe:
            emit_gap("cve_without_cwe", node_id)
        elif node.type == NodeType.CWE and node_id not in cwe_has_capec:
            emit_gap("cwe_without_capec", node_id)
        elif node.type == NodeType.CAPEC and node_id not in capec_has_attack:
            emit_gap("capec_without_attack", node_id)

    techniques: list[CoverageTechnique] = []
    summary = CoverageSummary()
    coverage_by_attack: dict[str, str] = {}

    for node_id, node in sorted(nodes.items()):
        if node.type != NodeType.ATTACK:
            continue
        defends = attack_to_defend.get(node_id, [])
        defend_ids = sorted({d for d, _ in defends})
        controls = sorted({c for d in defend_ids for c in defend_to_controls.get(d, [])})
        detections = sorted(attack_to_detections.get(node_id, []))
        evidence = sorted({ev for det in detections for ev in detection_to_evidence.get(det, [])})
        data_sources = sorted({ds for det in detections for ds in detection_to_data.get(det, [])})
        log_sources = sorted({ls for det in detections for ls in detection_to_log.get(det, [])})

        if not defend_ids:
            status = "gap"
            reason: str | None = "attack_without_defend"
            emit_gap(reason, node_id)
        elif not detections:
            status = "partial"
            reason = "attack_without_detection"
            emit_gap(reason, node_id)
        else:
            status = "covered"
            reason = None

        coverage_by_attack[node_id] = status
        setattr(summary, status, getattr(summary, status) + 1)
        techniques.append(
            CoverageTechnique(
                attack_technique=node_id,
                defend_techniques=defend_ids,
                controls=controls,
                detections=detections,
                evidence=evidence,
                data_sources=data_sources,
                log_sources=log_sources,
                coverage_status=status,
                gap_reason=reason,
                confidence=1.0,
            )
        )

    coverage = Coverage(techniques=techniques, summary=summary)
    return CoverageResult(
        coverage=coverage,
        coverage_by_attack=coverage_by_attack,
        gap_totals=gap_totals,
        gap_emitted=gap_emitted,
    )
