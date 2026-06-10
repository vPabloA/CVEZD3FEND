"""MCP stdio server implementing contracts/MCP_CONTRACT.md.

Read-mostly over `data/dist/knowledge-bundle.json` for use by AI agents.
Never mutates the bundle. `generate_hunt_hypothesis` is the one tool that
writes anything: it appends an `inferred=true`, `canonical=false` `note`
candidate to `data/review/ai-candidates.jsonl` (AI_ASSISTANCE_CONTRACT §3-4),
never the bundle itself.

Unknown ids return `{"error": "not_found", "id": "..."}` rather than raising.
If the bundle is missing, every tool returns
`{"error": "bundle_unavailable", "hint": "run `CVEzD3FEND build`"}`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Callable

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from CVEzD3FEND.actions.soc_action_pack import build_soc_action_pack
from CVEzD3FEND.config import Settings, get_settings
from CVEzD3FEND.export.markdown import render_route_markdown
from CVEzD3FEND.intelligence import candidates as ai_candidates
from CVEzD3FEND.intelligence import explain as ai_explain
from CVEzD3FEND.lookup import node_summary, resolve_attack_id, resolve_route, search_nodes
from CVEzD3FEND.models.ai import AICandidate
from CVEzD3FEND.models.bundle import Bundle
from CVEzD3FEND.models.graph import EdgeType, Node, NodeType
from CVEzD3FEND.util import now_iso, safe_id_fragment

SERVER_NAME = "CVEzD3FEND"

_BUNDLE_UNAVAILABLE = {"error": "bundle_unavailable", "hint": "run `CVEzD3FEND build`"}


def _load_bundle(settings: Settings) -> Bundle | None:
    path = settings.bundle_path
    if not path.exists():
        return None
    return Bundle.model_validate(json.loads(path.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# Tool implementations: (bundle, settings, arguments) -> JSON-serializable dict
# ---------------------------------------------------------------------------


def _tool_search(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    query = str(args.get("query", "")).strip()
    if not query:
        return {"error": "invalid_arguments", "hint": "provide 'query'"}
    types_filter = args.get("types")
    limit = int(args.get("limit", 20))
    results = search_nodes(bundle, query, limit * 5 if types_filter else limit)
    if types_filter:
        wanted = {str(t) for t in types_filter}
        results = [n for n in results if n.type.value in wanted]
    results = results[:limit]
    return {"results": [node_summary(n) for n in results]}


def _tool_get_node(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    node_id = args.get("id")
    if not node_id:
        return {"error": "invalid_arguments", "hint": "provide 'id'"}
    limit = int(args.get("limit", 20))
    offset = int(args.get("offset", 0))
    nodes_by_id = {n.id: n for n in bundle.nodes}
    node = nodes_by_id.get(node_id)
    if node is None:
        return {"error": "not_found", "id": node_id}

    outgoing = [e for e in bundle.edges if e.source == node_id]
    incoming = [e for e in bundle.edges if e.target == node_id]
    return {
        "node": node.model_dump(mode="json"),
        "outgoing": {
            "total": len(outgoing),
            "items": [e.model_dump(mode="json") for e in outgoing[offset : offset + limit]],
        },
        "incoming": {
            "total": len(incoming),
            "items": [e.model_dump(mode="json") for e in incoming[offset : offset + limit]],
        },
    }


def _tool_get_route(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    ref = args.get("id") or args.get("cve")
    if not ref:
        return {"error": "invalid_arguments", "hint": "provide 'id' or 'cve'"}
    route = resolve_route(bundle, ref)
    if route is None:
        return {"error": "not_found", "id": ref}
    return route.model_dump(mode="json")


def _tool_get_soc_action_pack(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    ref = args.get("cve_or_technique")
    if not ref:
        return {"error": "invalid_arguments", "hint": "provide 'cve_or_technique'"}
    attack_id = resolve_attack_id(bundle, ref)
    if attack_id is None:
        return {"error": "not_found", "id": ref}
    pack = build_soc_action_pack(bundle, attack_id)
    return pack.model_dump(mode="json")


def _tool_get_defensive_coverage(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    technique = args.get("technique")
    if technique:
        entry = next((t for t in bundle.coverage.techniques if t.attack_technique == technique), None)
        if entry is None:
            return {"error": "not_found", "id": technique}
        return entry.model_dump(mode="json")
    return {
        "summary": bundle.coverage.summary.model_dump(mode="json"),
        "total": len(bundle.coverage.techniques),
        "techniques": [t.model_dump(mode="json") for t in bundle.coverage.techniques],
    }


def _tool_list_gaps(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    technique = args.get("technique")
    reason = args.get("reason")
    limit = int(args.get("limit", 50))
    nodes = [n for n in bundle.nodes if n.type == NodeType.GAP]
    if technique:
        gap_ids = set(bundle.indexes.get("gaps_by_technique", {}).get(technique, []))
        nodes = [n for n in nodes if n.id in gap_ids]
    if reason:
        nodes = [n for n in nodes if n.metadata.get("reason") == reason]
    return {"total": len(nodes), "items": [n.model_dump(mode="json") for n in nodes[:limit]]}


def _tool_explain_route(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    route_id = args.get("route_id")
    if not route_id:
        return {"error": "invalid_arguments", "hint": "provide 'route_id'"}
    try:
        return ai_explain.explain_route(bundle, settings, route_id)
    except ValueError:
        return {"error": "not_found", "id": route_id}


def _tool_generate_detection_brief(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    technique = args.get("technique")
    if not technique:
        return {"error": "invalid_arguments", "hint": "provide 'technique'"}
    try:
        result = ai_explain.generate_detection_brief(bundle, settings, technique)
    except ValueError:
        return {"error": "not_found", "id": technique}
    return {"brief": result["text"], "citations": result["citations"]}


def _hunt_queries(bundle: Bundle, attack_id: str) -> list[dict]:
    hunt_id = f"HUNT-{safe_id_fragment(attack_id)}"
    nodes_by_id = {n.id: n for n in bundle.nodes}
    queries: list[dict] = []
    for e in bundle.edges:
        if e.type == EdgeType.QUERY_SUPPORTS_HUNT and e.target == hunt_id:
            qnode = nodes_by_id.get(e.source)
            if qnode is not None:
                queries.append({"id": qnode.id, "name": qnode.name, "description": qnode.description})
    return queries


def _record_hunt_candidate(settings: Settings, attack_id: str, hypothesis_text: str) -> None:
    """Append a `note` candidate so the hypothesis is queued for human review."""
    candidate_id = f"AIC-HUNT-{safe_id_fragment(attack_id)}"
    existing = ai_candidates.load_candidates(settings)
    if any(c.candidate_id == candidate_id for c in existing):
        return

    note_node = Node(
        id=f"NOTE-HUNT-{safe_id_fragment(attack_id)}",
        type=NodeType.NOTE,
        name=f"Threat hunt hypothesis: {attack_id}",
        description=hypothesis_text,
        source_refs=[],
        created_at=now_iso(),
        updated_at=now_iso(),
        confidence=0.20,
        canonical=False,
        inferred=True,
        metadata={"derivation": "mcp_generate_hunt_hypothesis", "attack": attack_id},
    )
    candidate = AICandidate(
        candidate_id=candidate_id,
        created_at=now_iso(),
        provider="mcp",
        prompt_hash=hashlib.sha256(hypothesis_text.encode("utf-8")).hexdigest(),
        input_refs=[attack_id],
        proposed_nodes=[note_node.model_dump(mode="json")],
        proposed_edges=[],
        rationale=hypothesis_text,
        confidence=0.20,
        validation_status="pending",
        final_status="candidate",
    )
    ai_candidates.save_candidates(settings, [*existing, candidate])


def _tool_generate_hunt_hypothesis(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    technique = args.get("technique")
    if not technique:
        return {"error": "invalid_arguments", "hint": "provide 'technique'"}
    try:
        result = ai_explain.generate_hunt_hypothesis(bundle, settings, technique)
    except ValueError:
        return {"error": "not_found", "id": technique}

    _record_hunt_candidate(settings, technique, result["text"])
    return {
        "hypothesis": result["text"],
        "queries": _hunt_queries(bundle, technique),
        "citations": result["citations"],
    }


def _tool_export_route_markdown(bundle: Bundle, settings: Settings, args: dict[str, Any]) -> dict:
    route_id = args.get("route_id")
    if not route_id:
        return {"error": "invalid_arguments", "hint": "provide 'route_id'"}
    route = resolve_route(bundle, route_id)
    if route is None:
        return {"error": "not_found", "id": route_id}
    return {"markdown": render_route_markdown(bundle, route)}


_TOOL_HANDLERS: dict[str, Callable[[Bundle, Settings, dict[str, Any]], dict]] = {
    "search_CVEzD3FEND": _tool_search,
    "get_node": _tool_get_node,
    "get_route": _tool_get_route,
    "get_soc_action_pack": _tool_get_soc_action_pack,
    "get_defensive_coverage": _tool_get_defensive_coverage,
    "list_gaps": _tool_list_gaps,
    "explain_route": _tool_explain_route,
    "generate_hunt_hypothesis": _tool_generate_hunt_hypothesis,
    "generate_detection_brief": _tool_generate_detection_brief,
    "export_route_markdown": _tool_export_route_markdown,
}

_TOOLS: list[types.Tool] = [
    types.Tool(
        name="search_CVEzD3FEND",
        description="Search the knowledge bundle by free text, node id, or alias.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "types": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["query"],
        },
    ),
    types.Tool(
        name="get_node",
        description="Get a node by id with its incoming/outgoing edges (paginated, default 20).",
        inputSchema={
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["id"],
        },
    ),
    types.Tool(
        name="get_route",
        description="Get a route by route id, or the top route for a CVE id.",
        inputSchema={
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "cve": {"type": "string"},
            },
        },
    ),
    types.Tool(
        name="get_soc_action_pack",
        description="Get the SOC Action Pack for an ATT&CK technique, route id, or CVE id.",
        inputSchema={
            "type": "object",
            "properties": {
                "cve_or_technique": {"type": "string"},
                "asset": {"type": "string", "description": "Reserved for future asset-scoped packs"},
            },
            "required": ["cve_or_technique"],
        },
    ),
    types.Tool(
        name="get_defensive_coverage",
        description="Get coverage for one ATT&CK technique, or the overall coverage summary.",
        inputSchema={
            "type": "object",
            "properties": {"technique": {"type": "string"}},
        },
    ),
    types.Tool(
        name="list_gaps",
        description="List coverage-gap nodes, optionally filtered by technique and/or reason.",
        inputSchema={
            "type": "object",
            "properties": {
                "technique": {"type": "string"},
                "reason": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    ),
    types.Tool(
        name="explain_route",
        description="Grounded, citation-backed explanation of a route (inferred=true context).",
        inputSchema={
            "type": "object",
            "properties": {"route_id": {"type": "string"}},
            "required": ["route_id"],
        },
    ),
    types.Tool(
        name="generate_hunt_hypothesis",
        description=(
            "Threat hunting hypothesis + draft queries for an ATT&CK technique. "
            "Also queues the hypothesis as a 'note' candidate in "
            "data/review/ai-candidates.jsonl for human review."
        ),
        inputSchema={
            "type": "object",
            "properties": {"technique": {"type": "string"}},
            "required": ["technique"],
        },
    ),
    types.Tool(
        name="generate_detection_brief",
        description="Detection brief for an ATT&CK technique (inferred=true context).",
        inputSchema={
            "type": "object",
            "properties": {"technique": {"type": "string"}},
            "required": ["technique"],
        },
    ),
    types.Tool(
        name="export_route_markdown",
        description="Render a route as Markdown (EXPORT_CONTRACT §1).",
        inputSchema={
            "type": "object",
            "properties": {"route_id": {"type": "string"}},
            "required": ["route_id"],
        },
    ),
]


server: Server = Server(SERVER_NAME)


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return _TOOLS


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> dict:
    settings = get_settings()
    bundle = _load_bundle(settings)
    if bundle is None:
        return _BUNDLE_UNAVAILABLE

    handler = _TOOL_HANDLERS.get(name)
    if handler is None:
        return {"error": "unknown_tool", "name": name}
    return handler(bundle, settings, arguments or {})


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    run()
