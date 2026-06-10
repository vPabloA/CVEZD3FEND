"""Markdown export for routes and SOC Action Packs (EXPORT_CONTRACT §1)."""

from __future__ import annotations

from CVEzD3FEND.models.bundle import Bundle, Route
from CVEzD3FEND.models.graph import Node
from CVEzD3FEND.models.soc import SocActionPack


def _node_by_id(bundle: Bundle) -> dict[str, Node]:
    return {n.id: n for n in bundle.nodes}


def _section(lines: list[str], title: str, items: list[str], nodes: dict[str, Node]) -> None:
    lines.append(f"## {title}")
    if not items:
        lines.append("_None_")
    else:
        for item_id in items:
            node = nodes.get(item_id)
            if node and node.name and node.name != item_id:
                lines.append(f"- **{item_id}** — {node.name}")
            else:
                lines.append(f"- **{item_id}**")
    lines.append("")


def render_route_markdown(bundle: Bundle, route: Route) -> str:
    nodes = _node_by_id(bundle)
    edges = {e.id: e for e in bundle.edges}
    sources = {s.source_id: s for s in bundle.sources}

    lines: list[str] = []
    end_node = nodes.get(route.end_node)
    title = f"Route {route.route_id}: {route.start_node} -> {route.end_node}"
    lines.append(f"# {title}")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- Confidence: {route.confidence:.2f}")
    lines.append(f"- Canonical: {route.canonical}")
    lines.append(f"- Inferred: {route.inferred}")
    lines.append(f"- Coverage status: {route.coverage_status}")
    if end_node:
        lines.append(f"- Target: **{route.end_node}** — {end_node.name}")
    lines.append("")

    lines.append("## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)")
    for i, node_id in enumerate(route.nodes):
        node = nodes.get(node_id)
        name = node.name if node else node_id
        if i == 0:
            lines.append(f"- **{node_id}** — {name}")
        else:
            edge = edges.get(route.edges[i - 1]) if i - 1 < len(route.edges) else None
            conf = edge.confidence if edge else route.confidence
            src = edge.source_ref if edge else "-"
            lines.append(f"- **{node_id}** — {name} _(confidence: {conf:.2f}, source: {src})_")
    lines.append("")

    _section(lines, "Recommended Actions", route.recommended_actions, nodes)
    _section(lines, "Detection Opportunities", _attack_detections(bundle, route), nodes)
    _section(lines, "Required Evidence / Logs", route.evidence_required, nodes)
    _section(lines, "Mitigations", _attack_mitigations(bundle, route), nodes)
    _section(lines, "Gaps", _attack_gaps(bundle, route), nodes)

    lines.append("## Sources")
    if not route.source_refs:
        lines.append("_None_")
    for source_id in route.source_refs:
        s = sources.get(source_id)
        if s:
            lines.append(f"- `{s.source_id}` — {s.name} ({s.url or 'internal'}), fetched_at={s.fetched_at}")
        else:
            lines.append(f"- `{source_id}`")
    lines.append("")

    return "\n".join(lines)


def _attack_node_id(route: Route) -> str | None:
    for node_id, kind in zip(route.nodes, route.path):
        if kind == "attack":
            return node_id
    return None


def _attack_detections(bundle: Bundle, route: Route) -> list[str]:
    attack_id = _attack_node_id(route)
    if not attack_id:
        return []
    return bundle.indexes.get("attack_to_detections", {}).get(attack_id, [])


def _attack_mitigations(bundle: Bundle, route: Route) -> list[str]:
    attack_id = _attack_node_id(route)
    if not attack_id:
        return []
    defend_ids = bundle.indexes.get("attack_to_defend", {}).get(attack_id, [])
    nodes = _node_by_id(bundle)
    return [f"MIT-{d}" for d in defend_ids if f"MIT-{d}" in nodes]


def _attack_gaps(bundle: Bundle, route: Route) -> list[str]:
    attack_id = _attack_node_id(route)
    if not attack_id:
        return []
    return bundle.indexes.get("gaps_by_technique", {}).get(attack_id, [])


def render_soc_action_pack_markdown(bundle: Bundle, pack: SocActionPack) -> str:
    nodes = _node_by_id(bundle)
    sources = {s.source_id: s for s in bundle.sources}

    lines: list[str] = [f"# {pack.title}", ""]
    lines.append("## Summary")
    lines.append(pack.executive_summary)
    lines.append("")
    lines.append(pack.technical_summary)
    lines.append(f"- Priority: {pack.priority}")
    lines.append(f"- Confidence: {pack.confidence:.2f}")
    lines.append("")

    lines.append("## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)")
    if not pack.attack_path:
        lines.append("_None_")
    for node_id in pack.attack_path:
        node = nodes.get(node_id)
        name = node.name if node else node_id
        lines.append(f"- **{node_id}** — {name}")
    lines.append("")

    _section(lines, "Recommended Actions", pack.recommended_actions, nodes)
    _section(lines, "Hunting Hypotheses", pack.hunting_hypotheses, nodes)
    _section(lines, "Detection Opportunities", pack.detection_opportunities, nodes)
    _section(lines, "Required Evidence / Logs", [*pack.required_evidence, *pack.required_logs], nodes)
    _section(lines, "Mitigations", pack.mitigations, nodes)
    _section(lines, "Gaps", pack.gaps, nodes)

    lines.append("## Sources")
    if not pack.source_refs:
        lines.append("_None_")
    for source_id in pack.source_refs:
        s = sources.get(source_id)
        if s:
            lines.append(f"- `{s.source_id}` — {s.name} ({s.url or 'internal'}), fetched_at={s.fetched_at}")
        else:
            lines.append(f"- `{source_id}`")
    lines.append("")

    return "\n".join(lines)
