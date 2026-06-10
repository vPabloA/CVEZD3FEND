"""Read-only query helpers over a loaded `Bundle`.

Shared by the CLI (`cli.py`), the optional FastAPI sidecar (`api/app.py`), and
the optional MCP server (`mcp/server.py`) so all three surfaces resolve ids,
search, and paginate edges identically.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from CVEzD3FEND.config import Settings
from CVEzD3FEND.models.bundle import Bundle, Route
from CVEzD3FEND.models.graph import Edge, Node, NodeType

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class BundleNotFoundError(FileNotFoundError):
    pass


def load_bundle(settings: Settings) -> Bundle:
    if not settings.bundle_path.exists():
        raise BundleNotFoundError(str(settings.bundle_path))
    data = json.loads(settings.bundle_path.read_text(encoding="utf-8"))
    return Bundle.model_validate(data)


def load_promoted_edges(settings: Settings) -> list[Edge]:
    path = settings.promoted_edges_path
    if not path.exists():
        return []
    return [Edge.model_validate(e) for e in json.loads(path.read_text(encoding="utf-8"))]


def search_nodes(bundle: Bundle, query: str, limit: int = 20, types: list[str] | None = None) -> list[Node]:
    """Rank nodes against `query` by exact id, alias index, then text index."""
    nodes_by_id = {n.id: n for n in bundle.nodes}
    stripped = query.strip()

    candidates: list[Node]
    if stripped in nodes_by_id:
        candidates = [nodes_by_id[stripped]]
    else:
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

        candidates = [nodes_by_id[node_id] for node_id, _ in scores.most_common(None) if node_id in nodes_by_id]

    if types:
        type_set = set(types)
        candidates = [n for n in candidates if n.type.value in type_set]

    return candidates[:limit]


def resolve_route(bundle: Bundle, ref: str) -> Route | None:
    """Resolve `ref` as a route id, or as a CVE id (-> its top-ranked route)."""
    route = next((r for r in bundle.routes if r.route_id == ref), None)
    if route is not None:
        return route
    route_ids: list[str] = bundle.indexes.get("cve_routes", {}).get(ref, [])
    if route_ids:
        return next((r for r in bundle.routes if r.route_id == route_ids[0]), None)
    return None


def resolve_attack_id(bundle: Bundle, ref: str) -> str | None:
    """Resolve `ref` to an ATT&CK technique id directly, or via a route."""
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


def get_node(bundle: Bundle, node_id: str) -> Node | None:
    return next((n for n in bundle.nodes if n.id == node_id), None)


def get_node_edges(bundle: Bundle, node_id: str, limit: int = 20, offset: int = 0) -> dict:
    """Return `{incoming, outgoing, incoming_total, outgoing_total}` for `node_id`, paginated."""
    incoming = [e for e in bundle.edges if e.target == node_id]
    outgoing = [e for e in bundle.edges if e.source == node_id]
    return {
        "incoming": incoming[offset : offset + limit],
        "outgoing": outgoing[offset : offset + limit],
        "incoming_total": len(incoming),
        "outgoing_total": len(outgoing),
    }


def list_gaps(bundle: Bundle, technique: str | None = None, reason: str | None = None, limit: int | None = None) -> list[Node]:
    gaps = [n for n in bundle.nodes if n.type == NodeType.GAP]
    if technique is not None:
        gap_ids = set(bundle.indexes.get("gaps_by_technique", {}).get(technique, []))
        gaps = [g for g in gaps if g.id in gap_ids]
    if reason is not None:
        gaps = [g for g in gaps if g.metadata.get("reason") == reason]
    if limit is not None:
        gaps = gaps[:limit]
    return gaps


REPO_ROOT = Path(__file__).resolve().parents[2]
