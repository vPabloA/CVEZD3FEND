"""Mermaid `graph LR` export for routes (EXPORT_CONTRACT §2)."""

from __future__ import annotations

import re

from CVEzD3FEND.models.bundle import Bundle, Route
from CVEzD3FEND.models.graph import EdgeType

_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_]")


def _sanitize(node_id: str) -> str:
    return _SANITIZE_RE.sub("_", node_id)


def render_route_mermaid(bundle: Bundle, route: Route) -> str:
    edges = {e.id: e for e in bundle.edges}
    declared: set[str] = set()

    def labeled(node_id: str) -> str:
        sid = _sanitize(node_id)
        if sid in declared:
            return sid
        declared.add(sid)
        return f'{sid}["{node_id}"]'

    lines = ["graph LR"]
    if len(route.nodes) < 2:
        for node_id in route.nodes:
            lines.append(f"  {labeled(node_id)}")
        return "\n".join(lines)

    for i in range(len(route.nodes) - 1):
        a = labeled(route.nodes[i])
        b = labeled(route.nodes[i + 1])
        edge = edges.get(route.edges[i]) if i < len(route.edges) else None
        if edge and edge.type == EdgeType.GAP_BLOCKS_COVERAGE:
            arrow = "-->|gap|"
        elif edge and edge.inferred:
            arrow = "-.->"
        else:
            arrow = "-->"
        lines.append(f"  {a} {arrow} {b}")

    return "\n".join(lines)
