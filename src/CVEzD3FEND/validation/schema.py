"""Structural (fatal) checks per contracts/VALIDATION_CONTRACT.md §1.

`validate_structure` returns a list of human-readable fatal error strings.
An empty list means the bundle is structurally sound; `CVEzD3FEND validate`
exits non-zero iff this list (plus any pydantic parse errors) is non-empty.
"""

from __future__ import annotations

from CVEzD3FEND.models.bundle import Bundle


def validate_structure(bundle: Bundle) -> list[str]:
    errors: list[str] = []

    node_ids = [n.id for n in bundle.nodes]
    node_id_set = set(node_ids)
    if len(node_ids) != len(node_id_set):
        seen: set[str] = set()
        dupes: set[str] = set()
        for nid in node_ids:
            if nid in seen:
                dupes.add(nid)
            seen.add(nid)
        errors.append(f"Duplicate node ids: {sorted(dupes)[:10]}{'...' if len(dupes) > 10 else ''}")

    edge_ids = [e.id for e in bundle.edges]
    edge_id_set = set(edge_ids)
    if len(edge_ids) != len(edge_id_set):
        seen = set()
        dupes = set()
        for eid in edge_ids:
            if eid in seen:
                dupes.add(eid)
            seen.add(eid)
        errors.append(f"Duplicate edge ids: {sorted(dupes)[:10]}{'...' if len(dupes) > 10 else ''}")

    source_id_set = {s.source_id for s in bundle.sources}

    seen_triples: set[tuple[str, str, str]] = set()
    for e in bundle.edges:
        if e.source not in node_id_set:
            errors.append(f"Edge {e.id} has unknown source node: {e.source}")
        if e.target not in node_id_set:
            errors.append(f"Edge {e.id} has unknown target node: {e.target}")
        if e.source_ref is None:
            errors.append(f"Edge {e.id} has source_ref=null")
        elif e.source_ref not in source_id_set:
            errors.append(f"Edge {e.id} has source_ref '{e.source_ref}' not in bundle.sources[]")
        if e.deterministic and e.inferred:
            errors.append(f"Edge {e.id} has deterministic=true AND inferred=true")
        triple = (e.source, e.target, e.type.value)
        if triple in seen_triples:
            errors.append(f"Duplicate edge for (source, target, type)={triple}")
        seen_triples.add(triple)

    for n in bundle.nodes:
        if not n.source_refs:
            errors.append(f"Node {n.id} has empty source_refs[]")

    route_ids = [r.route_id for r in bundle.routes]
    if len(route_ids) != len(set(route_ids)):
        errors.append("Duplicate route_id values in bundle.routes[]")

    edge_id_set_full = edge_id_set
    for r in bundle.routes:
        for nid in r.nodes:
            if nid not in node_id_set:
                errors.append(f"Route {r.route_id} references unknown node: {nid}")
        for eid in r.edges:
            if eid not in edge_id_set_full:
                errors.append(f"Route {r.route_id} references unknown edge: {eid}")

    return errors
