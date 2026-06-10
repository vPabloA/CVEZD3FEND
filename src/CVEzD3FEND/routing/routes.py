"""Route generation per contracts/BUNDLE_CONTRACT.md §3.

Two families of routes are produced, both purely as read-only projections
over `nodes`/`edges` (GRAPH_CONTRACT §5):

1. **CVE-anchored routes**: ``cve -> cwe -> capec -> attack [-> defend]``,
   ranked by confidence (product of edge confidences), top
   ``settings.top_routes_per_cve`` per CVE.
2. **Framework routes**: canonical ``cwe -> capec -> attack -> defend`` chains
   (no CVE), used to populate the Defensive Coverage view. Capped at
   ``settings.max_framework_routes`` (highest confidence first); the true
   total is reported separately so nothing is silently dropped.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from CVEzD3FEND.config import Settings
from CVEzD3FEND.models.bundle import Route
from CVEzD3FEND.models.graph import Edge, EdgeType, Node


@dataclass
class RouteResult:
    routes: list[Route]
    framework_routes_total: int = 0
    framework_routes_emitted: int = 0


def _route_id(prefix: str, path: list[str]) -> str:
    digest = hashlib.sha1(f"{prefix}:{'->'.join(path)}".encode("utf-8")).hexdigest()
    return f"ROUTE-{prefix}-{digest[:12]}"


def _edges_by_type_and_source(edges: list[Edge]) -> dict[EdgeType, dict[str, list[Edge]]]:
    out: dict[EdgeType, dict[str, list[Edge]]] = {}
    for e in edges:
        out.setdefault(e.type, {}).setdefault(e.source, []).append(e)
    return out


def compute_routes(
    nodes: list[Node],
    edges: list[Edge],
    coverage_by_attack: dict[str, str],
    settings: Settings,
) -> RouteResult:
    node_index = {n.id: n for n in nodes}
    by_type = _edges_by_type_and_source(edges)

    cve_has_cwe = by_type.get(EdgeType.CVE_HAS_CWE, {})
    cwe_maps_to_capec = by_type.get(EdgeType.CWE_MAPS_TO_CAPEC, {})
    capec_maps_to_attack = by_type.get(EdgeType.CAPEC_MAPS_TO_ATTACK, {})
    attack_maps_to_defend = by_type.get(EdgeType.ATTACK_MAPS_TO_DEFEND, {})

    defend_to_controls: dict[str, list[str]] = {}
    for e in by_type.get(EdgeType.CONTROL_IMPLEMENTS_DEFEND, {}).values():
        for edge in e:
            defend_to_controls.setdefault(edge.target, []).append(edge.source)

    defend_to_soc_actions: dict[str, list[str]] = {}
    for e in by_type.get(EdgeType.SOC_ACTION_OPERATIONALIZES_DEFEND, {}).values():
        for edge in e:
            defend_to_soc_actions.setdefault(edge.target, []).append(edge.source)

    attack_to_detections: dict[str, list[str]] = {}
    for e in by_type.get(EdgeType.DETECTION_DETECTS_ATTACK, {}).values():
        for edge in e:
            attack_to_detections.setdefault(edge.target, []).append(edge.source)

    detection_to_evidence: dict[str, list[str]] = {}
    for e in by_type.get(EdgeType.EVIDENCE_SUPPORTS_DETECTION, {}).values():
        for edge in e:
            detection_to_evidence.setdefault(edge.target, []).append(edge.source)

    def recommended_actions_for(defend_id: str | None) -> list[str]:
        if not defend_id:
            return []
        actions = sorted(defend_to_controls.get(defend_id, []))
        actions += sorted(defend_to_soc_actions.get(defend_id, []))
        return actions

    def evidence_required_for(attack_id: str) -> list[str]:
        out: set[str] = set()
        for det in attack_to_detections.get(attack_id, []):
            out.update(detection_to_evidence.get(det, []))
        return sorted(out)

    def source_refs_for(path_edges: list[Edge]) -> list[str]:
        refs: list[str] = []
        for e in path_edges:
            if e.source_ref and e.source_ref not in refs:
                refs.append(e.source_ref)
        return refs

    routes: list[Route] = []

    # -- 1. CVE-anchored routes ------------------------------------------
    for cve_id, e1_list in sorted(cve_has_cwe.items()):
        candidates: list[Route] = []
        for e1 in e1_list:
            cwe_id = e1.target
            for e2 in cwe_maps_to_capec.get(cwe_id, []):
                capec_id = e2.target
                for e3 in capec_maps_to_attack.get(capec_id, []):
                    attack_id = e3.target
                    base_edges = [e1, e2, e3]
                    base_path = [cve_id, cwe_id, capec_id, attack_id]
                    base_types = ["cve", "cwe", "capec", "attack"]

                    defend_edges = attack_maps_to_defend.get(attack_id, [])
                    if defend_edges:
                        for e4 in defend_edges:
                            defend_id = e4.target
                            path_edges = [*base_edges, e4]
                            confidence = round(
                                e1.confidence * e2.confidence * e3.confidence * e4.confidence, 2
                            )
                            candidates.append(
                                Route(
                                    route_id=_route_id("CVE", [*base_path, defend_id]),
                                    start_node=cve_id,
                                    end_node=defend_id,
                                    path=[*base_types, "defend"],
                                    nodes=[*base_path, defend_id],
                                    edges=[e.id for e in path_edges],
                                    confidence=confidence,
                                    canonical=all(e.deterministic for e in path_edges),
                                    inferred=any(e.inferred for e in path_edges),
                                    coverage_status=coverage_by_attack.get(attack_id, "unknown"),
                                    recommended_actions=recommended_actions_for(defend_id),
                                    evidence_required=evidence_required_for(attack_id),
                                    source_refs=source_refs_for(path_edges),
                                )
                            )
                    else:
                        confidence = round(e1.confidence * e2.confidence * e3.confidence, 2)
                        candidates.append(
                            Route(
                                route_id=_route_id("CVE", base_path),
                                start_node=cve_id,
                                end_node=attack_id,
                                path=base_types,
                                nodes=base_path,
                                edges=[e.id for e in base_edges],
                                confidence=confidence,
                                canonical=all(e.deterministic for e in base_edges),
                                inferred=any(e.inferred for e in base_edges),
                                coverage_status=coverage_by_attack.get(attack_id, "unknown"),
                                recommended_actions=[],
                                evidence_required=evidence_required_for(attack_id),
                                source_refs=source_refs_for(base_edges),
                            )
                        )

        candidates.sort(key=lambda r: r.confidence, reverse=True)
        routes.extend(candidates[: settings.top_routes_per_cve])

    # -- 2. Framework routes (cwe -> capec -> attack -> defend) ----------
    framework_candidates: list[Route] = []
    for cwe_id, e1_list in sorted(cwe_maps_to_capec.items()):
        for e1 in e1_list:
            capec_id = e1.target
            for e2 in capec_maps_to_attack.get(capec_id, []):
                attack_id = e2.target
                for e3 in attack_maps_to_defend.get(attack_id, []):
                    defend_id = e3.target
                    path_edges = [e1, e2, e3]
                    path_nodes = [cwe_id, capec_id, attack_id, defend_id]
                    confidence = round(e1.confidence * e2.confidence * e3.confidence, 2)
                    framework_candidates.append(
                        Route(
                            route_id=_route_id("FW", path_nodes),
                            start_node=cwe_id,
                            end_node=defend_id,
                            path=["cwe", "capec", "attack", "defend"],
                            nodes=path_nodes,
                            edges=[e.id for e in path_edges],
                            confidence=confidence,
                            canonical=all(e.deterministic for e in path_edges),
                            inferred=any(e.inferred for e in path_edges),
                            coverage_status=coverage_by_attack.get(attack_id, "unknown"),
                            recommended_actions=recommended_actions_for(defend_id),
                            evidence_required=evidence_required_for(attack_id),
                            source_refs=source_refs_for(path_edges),
                        )
                    )

    framework_candidates.sort(key=lambda r: r.confidence, reverse=True)
    framework_total = len(framework_candidates)
    framework_emitted = framework_candidates[: settings.max_framework_routes]
    routes.extend(framework_emitted)

    return RouteResult(
        routes=routes,
        framework_routes_total=framework_total,
        framework_routes_emitted=len(framework_emitted),
    )
