"""Shared read-only lookup helpers over a loaded `Bundle`.

Used by the optional API sidecar (`api/app.py`) and MCP server
(`mcp/server.py`) to resolve routes/techniques/nodes the same way
`CVEzD3FEND.cli` does.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from CVEzD3FEND.models.bundle import Bundle, Route
from CVEzD3FEND.models.graph import Node, NodeType

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def resolve_route(bundle: Bundle, ref: str) -> Route | None:
    route = next((r for r in bundle.routes if r.route_id == ref), None)
    if route is not None:
        return route
    route_ids: list[str] = bundle.indexes.get("cve_routes", {}).get(ref, [])
    if route_ids:
        return next((r for r in bundle.routes if r.route_id == route_ids[0]), None)
    return None


def resolve_attack_id(bundle: Bundle, ref: str) -> str | None:
    nodes_by_id = {n.id: n for n in bundle.nodes}
    node = nodes_by_id.get(ref)
    if node is not None and node.type == NodeType.ATTACK:
        return ref
    route = resolve_route(bundle, ref)
    if route is not None:
        for node_id in route.nodes:
            candidate = nodes_by_id.get(node_id)
            if candidate is not None and candidate.type == NodeType.ATTACK:
                return node_id
    return None


def search_nodes(bundle: Bundle, query: str, limit: int) -> list[Node]:
    nodes_by_id = {n.id: n for n in bundle.nodes}
    stripped = query.strip()
    if stripped in nodes_by_id:
        return [nodes_by_id[stripped]]

    tokens = [t for t in _TOKEN_RE.findall(stripped.lower()) if len(t) >= 2]
    by_text: dict[str, list[str]] = bundle.indexes.get("by_text", {})
    by_alias: dict[str, list[str]] = bundle.indexes.get("by_alias", {})
    scores: Counter[str] = Counter()
    for token in tokens:
        for node_id in by_text.get(token, []):
            scores[node_id] += 1
        for node_id in by_alias.get(token, []):
            scores[node_id] += 2

    if not scores:
        needle = stripped.lower()
        for node in bundle.nodes:
            if needle in node.id.lower() or needle in node.name.lower():
                scores[node.id] += 1

    return [nodes_by_id[node_id] for node_id, _ in scores.most_common(limit) if node_id in nodes_by_id]


def node_summary(node: Node) -> dict[str, Any]:
    return {
        "id": node.id,
        "type": node.type.value,
        "name": node.name,
        "confidence": node.confidence,
        "canonical": node.canonical,
        "inferred": node.inferred,
    }
