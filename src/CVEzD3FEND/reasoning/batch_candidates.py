"""Catalog-backed candidate route construction for batch reasoning."""

from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from CVEzD3FEND.graph.builder import attack_id_from_raw, capec_id_from_raw, cwe_id_from_raw
from CVEzD3FEND.graph.context import make_edge, make_node
from CVEzD3FEND.models.bundle import Bundle, Source
from CVEzD3FEND.models.graph import Edge, EdgeType, LifecycleState, Node, NodeType, ResolutionState
from CVEzD3FEND.reasoning.models import RankedRoute

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class BatchLimitError(ValueError):
    """Raised when a request exceeds an explicit operational limit."""


@dataclass
class CandidatePool:
    routes: list[RankedRoute] = field(default_factory=list)
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)


def normalize_cve_inputs(values: Iterable[str]) -> tuple[list[str], list[str]]:
    """Uppercase, validate, and deduplicate while preserving input order."""

    valid: list[str] = []
    invalid: list[str] = []
    seen_valid: set[str] = set()
    seen_invalid: set[str] = set()
    for raw in values:
        normalized = str(raw).strip().upper()
        if not normalized:
            continue
        if _CVE_RE.fullmatch(normalized):
            if normalized not in seen_valid:
                seen_valid.add(normalized)
                valid.append(normalized)
        elif normalized not in seen_invalid:
            seen_invalid.add(normalized)
            invalid.append(normalized)
    return valid, invalid


def _route_id(node_ids: list[str]) -> str:
    digest = hashlib.sha1("->".join(node_ids).encode("utf-8")).hexdigest()[:16]
    return f"BATCH-ROUTE-{digest}"


def _defend_ids(payload: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for item in payload.get("DEFEND", []) or []:
        if isinstance(item, dict) and item.get("id"):
            result.add(str(item["id"]).strip())
        elif isinstance(item, str) and item.strip():
            result.add(item.strip())
    return result


def _reported_sets(payload: dict[str, Any]) -> dict[str, set[str]]:
    return {
        "cwe": {cwe_id_from_raw(value) for value in payload.get("CWE", []) or []},
        "capec": {capec_id_from_raw(value) for value in payload.get("CAPEC", []) or []},
        "attack": {attack_id_from_raw(value) for value in payload.get("TECHNIQUES", []) or []},
        "defend": _defend_ids(payload),
    }


def _eligible_framework_edge(edge: Edge) -> bool:
    return (
        edge.deterministic
        and not edge.inferred
        and edge.resolution_state == ResolutionState.RESOLVED
        and edge.lifecycle_state != LifecycleState.REVOKED
    )


def build_candidate_pool(
    bundle: Bundle,
    records: dict[str, dict[str, Any]],
    sources: list[Source],
    *,
    max_routes: int,
) -> CandidatePool:
    """Reconstruct all valid routes by traversing demonstrated graph edges.

    The only request-created edge is CVE->CWE, directly asserted by the exact
    Galeax year record. Every later edge is an existing deterministic bundle
    edge produced from CWE, CAPEC/Phase-2B, and D3FEND catalogs.
    """

    pool = CandidatePool()
    pool.nodes.update({node.id: node for node in bundle.nodes})
    source_by_year = {
        int(source.metadata["year"]): source
        for source in sources
        if isinstance(source.metadata.get("year"), int)
    }

    by_type_source: dict[tuple[EdgeType, str], list[Edge]] = defaultdict(list)
    for edge in bundle.edges:
        if _eligible_framework_edge(edge):
            by_type_source[(edge.type, edge.source)].append(edge)
    for edges in by_type_source.values():
        edges.sort(key=lambda item: (item.target, item.id))

    def emit(
        cve_id: str,
        node_ids: list[str],
        path_edges: list[Edge],
        assertions: dict[str, set[str]],
        gaps: list[str],
    ) -> None:
        if len(pool.routes) >= max_routes:
            raise BatchLimitError(
                f"candidate route limit exceeded ({max_routes}); narrow the CVE request or raise "
                "CVEZD3FEND_MAX_BATCH_CANDIDATE_ROUTES"
            )
        attack_ids = [node_id for node_id in node_ids if node_id.startswith("T")]
        defend_ids = [
            node_id
            for node_id in node_ids
            if pool.nodes.get(node_id) is not None and pool.nodes[node_id].type == NodeType.DEFEND
        ]
        corroborated: list[str] = []
        for node_id in node_ids:
            if node_id == cve_id:
                corroborated.append(node_id)
            elif node_id.startswith("CWE-") and node_id in assertions["cwe"]:
                corroborated.append(node_id)
            elif node_id.startswith("CAPEC-") and node_id in assertions["capec"]:
                corroborated.append(node_id)
            elif node_id.startswith("T") and node_id in assertions["attack"]:
                corroborated.append(node_id)
            elif node_id in assertions["defend"]:
                corroborated.append(node_id)

        confidence = math.prod(edge.confidence for edge in path_edges) if path_edges else 1.0
        stage_count = sum(
            1
            for stage in (
                bool(node_ids),
                any(node_id.startswith("CWE-") for node_id in node_ids),
                any(node_id.startswith("CAPEC-") for node_id in node_ids),
                bool(attack_ids),
                bool(defend_ids),
            )
            if stage
        )
        provenance = list(
            dict.fromkeys(edge.source_ref for edge in path_edges if edge.source_ref)
        )
        pool.routes.append(
            RankedRoute(
                route_id=_route_id(node_ids),
                cve_id=cve_id,
                cve_ids=[cve_id],
                node_ids=node_ids,
                edge_ids=[edge.id for edge in path_edges],
                attack_ids=attack_ids,
                defend_ids=defend_ids,
                confidence=round(confidence, 6),
                completeness=round(stage_count / 5, 2),
                provenance=provenance,
                corroborated_nodes=corroborated,
                gaps=gaps,
            )
        )
        for edge in path_edges:
            pool.edges[edge.id] = edge

    for cve_id in sorted(records):
        payload = records[cve_id]
        assertions = _reported_sets(payload)
        year = int(cve_id.split("-", 2)[1])
        source = source_by_year.get(year)
        source_id = source.source_id if source else f"cve2capec:cve_{year}"
        source_url = source.url if source else None

        cve_node = pool.nodes.get(cve_id) or make_node(
            cve_id,
            NodeType.CVE,
            cve_id,
            description=f"{cve_id} — exact request-scoped Galeax assertion.",
            external_refs=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            source_refs=[source_id],
            metadata={
                "year": year,
                "request_scoped": True,
                "reported_cwe": sorted(assertions["cwe"]),
                "reported_capec": sorted(assertions["capec"]),
                "reported_techniques": sorted(assertions["attack"]),
                "reported_defend": sorted(assertions["defend"]),
            },
        )
        pool.nodes[cve_id] = cve_node

        if not assertions["cwe"]:
            emit(cve_id, [cve_id], [], assertions, ["cve_without_cwe_assertion"])
            continue

        for cwe_id in sorted(assertions["cwe"]):
            if cwe_id not in pool.nodes:
                pool.nodes[cwe_id] = make_node(
                    cwe_id,
                    NodeType.CWE,
                    cwe_id,
                    description=f"{cwe_id} asserted by exact Galeax CVE record.",
                    external_refs=[f"https://cwe.mitre.org/data/definitions/{cwe_id.removeprefix('CWE-')}.html"],
                    source_refs=[source_id],
                    confidence=0.6,
                    metadata={"request_scoped": True},
                )
            cve_edge = make_edge(
                EdgeType.CVE_HAS_CWE,
                cve_id,
                cwe_id,
                confidence=1.0,
                source_ref=source_id,
                source_url=source_url,
                evidence=[f"Exact Galeax {cve_id}.CWE assertion includes {cwe_id}"],
                metadata={"request_scoped": True, "year": year},
            )
            pool.edges[cve_edge.id] = cve_edge

            cwe_edges = by_type_source.get((EdgeType.CWE_MAPS_TO_CAPEC, cwe_id), [])
            if not cwe_edges:
                emit(cve_id, [cve_id, cwe_id], [cve_edge], assertions, ["cwe_without_catalog_capec"])
                continue

            for cwe_capec in cwe_edges:
                capec_id = cwe_capec.target
                capec_edges = by_type_source.get((EdgeType.CAPEC_MAPS_TO_ATTACK, capec_id), [])
                if not capec_edges:
                    emit(
                        cve_id,
                        [cve_id, cwe_id, capec_id],
                        [cve_edge, cwe_capec],
                        assertions,
                        ["capec_without_resolved_attack"],
                    )
                    continue

                for capec_attack in capec_edges:
                    attack_id = capec_attack.target
                    defend_edges = by_type_source.get((EdgeType.ATTACK_MAPS_TO_DEFEND, attack_id), [])
                    if not defend_edges:
                        emit(
                            cve_id,
                            [cve_id, cwe_id, capec_id, attack_id],
                            [cve_edge, cwe_capec, capec_attack],
                            assertions,
                            ["attack_without_defend"],
                        )
                        continue

                    for attack_defend in defend_edges:
                        emit(
                            cve_id,
                            [cve_id, cwe_id, capec_id, attack_id, attack_defend.target],
                            [cve_edge, cwe_capec, capec_attack, attack_defend],
                            assertions,
                            [],
                        )

    unique: dict[str, RankedRoute] = {}
    for route in pool.routes:
        unique.setdefault(route.route_id, route)
    pool.routes = sorted(unique.values(), key=lambda route: (route.cve_id, route.route_id))
    return pool
