"""Bundle index construction per contracts/BUNDLE_CONTRACT.md §4.

All indexes are pure derivations over `nodes`/`edges`/`routes`/coverage — they
carry no information that isn't already present elsewhere in the bundle.
"""

from __future__ import annotations

import re
from collections import defaultdict

from CVEzD3FEND.models.bundle import Route
from CVEzD3FEND.models.graph import Edge, EdgeType, Node

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(*texts: str) -> set[str]:
    tokens: set[str] = set()
    for text in texts:
        tokens.update(t for t in _TOKEN_RE.findall(text.lower()) if len(t) >= 2)
    return tokens


def _dedup_sorted(d: dict[str, list[str]]) -> dict[str, list[str]]:
    return {k: sorted(set(v)) for k, v in d.items()}


def build_indexes(
    nodes: list[Node],
    edges: list[Edge],
    routes: list[Route],
    coverage_by_attack: dict[str, str],
) -> dict:
    by_id: dict[str, int] = {}
    by_alias: dict[str, list[str]] = defaultdict(list)
    by_text: dict[str, list[str]] = defaultdict(list)
    sources_by_node: dict[str, list[str]] = {}
    sources_by_edge: dict[str, list[str]] = {}

    cwe_to_capec: dict[str, list[str]] = defaultdict(list)
    capec_to_attack: dict[str, list[str]] = defaultdict(list)
    attack_to_defend: dict[str, list[str]] = defaultdict(list)
    attack_to_atlas: dict[str, list[str]] = defaultdict(list)
    defend_to_controls: dict[str, list[str]] = defaultdict(list)
    attack_to_detections: dict[str, list[str]] = defaultdict(list)
    gaps_by_technique: dict[str, list[str]] = defaultdict(list)
    cve_routes: dict[str, list[str]] = defaultdict(list)

    for i, n in enumerate(nodes):
        by_id[n.id] = i
        for alias in n.aliases:
            by_alias[alias].append(n.id)
        for token in _tokenize(n.id, n.name, n.title):
            by_text[token].append(n.id)
        if n.source_refs:
            sources_by_node[n.id] = list(n.source_refs)

    for e in edges:
        if e.source_ref:
            sources_by_edge[e.id] = [e.source_ref]

        if e.type == EdgeType.CWE_MAPS_TO_CAPEC:
            cwe_to_capec[e.source].append(e.target)
        elif e.type == EdgeType.CAPEC_MAPS_TO_ATTACK:
            capec_to_attack[e.source].append(e.target)
        elif e.type == EdgeType.ATTACK_MAPS_TO_DEFEND:
            attack_to_defend[e.source].append(e.target)
        elif e.type == EdgeType.ATTACK_MAPS_TO_ATLAS:
            attack_to_atlas[e.source].append(e.target)
        elif e.type == EdgeType.CONTROL_IMPLEMENTS_DEFEND:
            defend_to_controls[e.target].append(e.source)
        elif e.type == EdgeType.DETECTION_DETECTS_ATTACK:
            attack_to_detections[e.target].append(e.source)
        elif e.type == EdgeType.GAP_BLOCKS_COVERAGE:
            gaps_by_technique[e.target].append(e.source)

    for r in routes:
        if r.start_node.startswith("CVE-"):
            cve_routes[r.start_node].append(r.route_id)

    return {
        "by_id": by_id,
        "by_alias": _dedup_sorted(by_alias),
        "by_text": _dedup_sorted(by_text),
        "cve_routes": _dedup_sorted(cve_routes),
        "cwe_to_capec": _dedup_sorted(cwe_to_capec),
        "capec_to_attack": _dedup_sorted(capec_to_attack),
        "attack_to_defend": _dedup_sorted(attack_to_defend),
        "attack_to_atlas": _dedup_sorted(attack_to_atlas),
        "defend_to_controls": _dedup_sorted(defend_to_controls),
        "attack_to_detections": _dedup_sorted(attack_to_detections),
        "gaps_by_technique": _dedup_sorted(gaps_by_technique),
        "coverage_by_technique": dict(sorted(coverage_by_attack.items())),
        "sources_by_node": sources_by_node,
        "sources_by_edge": sources_by_edge,
    }
