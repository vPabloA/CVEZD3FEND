from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"Unexpected source shape: {path}")
    p.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "web/src/components/reasoning/graph/graphTypes.ts",
    "  routeChain: string[];\n  routeConfidence: number;\n}",
    "  routeChain: string[];\n  routeConfidence: number;\n  focusedRouteComplete: boolean;\n  focusedRouteGaps: string[];\n}",
)

replace_once(
    "web/src/components/reasoning/graph/graphAdapter.ts",
    'function visibleCap(mode: string): number {\n  return MODE_CAP[mode] ?? MODE_CAP["focused-route"];\n}\n\nexport function buildGraphModel',
    '''function visibleCap(mode: string): number {
  return MODE_CAP[mode] ?? MODE_CAP["focused-route"];
}

const REQUIRED_ROUTE_KINDS: GraphNodeKind[] = ["cve", "cwe", "capec", "attack", "defend"];

function routeLayerGaps(nodeIds: string[], nodes: GraphNodeData[]): string[] {
  const sourceNodeIds = new Set(nodes.map((node) => node.id));
  const presentKinds = new Set(nodeIds.filter((id) => sourceNodeIds.has(id)).map((id) => nodeKindForId(id)));
  return REQUIRED_ROUTE_KINDS.filter((kind) => !presentKinds.has(kind)).map((kind) => `Missing ${kind.toUpperCase()} layer`);
}

function singleRouteIntegrity(routeChain: string[], nodes: GraphNodeData[], links: GraphLinkData[]): { complete: boolean; gaps: string[] } {
  const sourceNodeIds = new Set(nodes.map((node) => node.id));
  const gaps = routeLayerGaps(routeChain, nodes);
  routeChain.filter((id) => !sourceNodeIds.has(id)).forEach((id) => gaps.push(`Missing node ${id}`));
  routeChain.slice(1).forEach((targetId, index) => {
    const sourceId = routeChain[index];
    if (!links.some((link) => graphLinkSourceId(link) === sourceId && graphLinkTargetId(link) === targetId)) {
      gaps.push(`Missing edge ${sourceId} → ${targetId}`);
    }
  });
  const uniqueGaps = [...new Set(gaps)];
  return { complete: uniqueGaps.length === 0, gaps: uniqueGaps };
}

function batchRouteIntegrity(route: RankedRoute | undefined, nodes: GraphNodeData[], links: GraphLinkData[]): { complete: boolean; gaps: string[] } {
  if (!route) return { complete: false, gaps: ["No focused route"] };
  const sourceNodeIds = new Set(nodes.map((node) => node.id));
  const sourceLinkIds = new Set(links.map((link) => link.id));
  const gaps = [...route.gaps, ...routeLayerGaps(route.node_ids, nodes)];
  route.node_ids.filter((id) => !sourceNodeIds.has(id)).forEach((id) => gaps.push(`Missing node ${id}`));
  route.edge_ids.filter((id) => !sourceLinkIds.has(id)).forEach((id) => gaps.push(`Missing edge ${id}`));
  if (route.completeness < 1) gaps.push(`Backend completeness ${route.completeness}`);
  const uniqueGaps = [...new Set(gaps)];
  return { complete: route.completeness >= 1 && uniqueGaps.length === 0, gaps: uniqueGaps };
}

export function buildGraphModel''',
)

replace_once(
    "web/src/components/reasoning/graph/graphAdapter.ts",
    '''  const baseVisible = prioritizeIds([...seeds], result, selection);
  const cap = visibleCap(mode);
  const visibleIds = new Set<string>(baseVisible.slice(0, cap));
  if (selection?.kind === "node") visibleIds.add(selection.id);
  if (selection?.kind === "edge") {
    const selectedEdge = links.find((link) => link.id === selection.id);
    if (selectedEdge) {
      visibleIds.add(graphLinkSourceId(selectedEdge));
      visibleIds.add(graphLinkTargetId(selectedEdge));
    }
  }

  const visibleLinks = links.filter((link) => visibleIds.has(graphLinkSourceId(link)) && visibleIds.has(graphLinkTargetId(link)));
  visibleLinks.forEach((link) => {
    visibleIds.add(graphLinkSourceId(link));
    visibleIds.add(graphLinkTargetId(link));
  });

  // If the selected route still leaves room, retain a few extra neighbors so the
  // canvas stays honest without becoming a wall of nodes.
  if (visibleIds.size < cap) {''',
    '''  const baseVisible = prioritizeIds([...seeds], result, selection);
  const cap = visibleCap(mode);
  const visibleIds = new Set<string>(routeChain.filter((id) => nodesById.has(id)));
  if (selection?.kind === "node" && nodesById.has(selection.id)) visibleIds.add(selection.id);
  if (selection?.kind === "edge") {
    const selectedEdge = links.find((link) => link.id === selection.id);
    if (selectedEdge) {
      visibleIds.add(graphLinkSourceId(selectedEdge));
      visibleIds.add(graphLinkTargetId(selectedEdge));
    }
  }

  // The cap applies only to surrounding context. Canonical route truth and the
  // active selection are never removed to satisfy a visual budget.
  baseVisible.filter((id) => !visibleIds.has(id)).slice(0, Math.max(0, cap - visibleIds.size)).forEach((id) => visibleIds.add(id));

  if (visibleIds.size < cap) {''',
)

replace_once(
    "web/src/components/reasoning/graph/graphAdapter.ts",
    "  const routeConfidence = canonicalConfidences.length > 0 ? canonicalConfidences.reduce((sum, value) => sum + value, 0) / canonicalConfidences.length : num(result.edges[0]?.confidence, 0.5);\n\n  return {",
    "  const routeConfidence = canonicalConfidences.length > 0 ? canonicalConfidences.reduce((sum, value) => sum + value, 0) / canonicalConfidences.length : num(result.edges[0]?.confidence, 0.5);\n  const integrity = singleRouteIntegrity(routeChain, [...nodesById.values()], links);\n\n  return {",
)
replace_once(
    "web/src/components/reasoning/graph/graphAdapter.ts",
    "    routeChain,\n    routeConfidence,\n  };\n}",
    "    routeChain,\n    routeConfidence,\n    focusedRouteComplete: integrity.complete,\n    focusedRouteGaps: integrity.gaps,\n  };\n}",
)
