import type { GraphLinkData, GraphModel, GraphNodeData, GraphSelection } from "./graphTypes";
import { graphLinkSourceId, graphLinkTargetId, isDefensiveGraphNode } from "./graphRuntime";

export interface HighlightState {
  highlightedNodes: Set<string>;
  highlightedLinks: Set<string>;
  focusedNodes: Set<string>;
  focusedLinks: Set<string>;
  mitigationNodes: Set<string>;
  mitigationLinks: Set<string>;
}

function buildAdjacency(links: GraphLinkData[]): Map<string, Set<string>> {
  const adjacency = new Map<string, Set<string>>();
  links.forEach((link) => {
    const sourceId = graphLinkSourceId(link);
    const targetId = graphLinkTargetId(link);
    const source = adjacency.get(sourceId) ?? new Set<string>();
    const target = adjacency.get(targetId) ?? new Set<string>();
    source.add(targetId);
    target.add(sourceId);
    adjacency.set(sourceId, source);
    adjacency.set(targetId, target);
  });
  return adjacency;
}

function selectNodeNeighbors(nodeId: string, adjacency: Map<string, Set<string>>, depth: number): Set<string> {
  const result = new Set<string>([nodeId]);
  let frontier = new Set<string>([nodeId]);
  for (let step = 0; step < depth; step += 1) {
    const next = new Set<string>();
    frontier.forEach((id) => {
      adjacency.get(id)?.forEach((neighbor) => {
        if (!result.has(neighbor)) {
          result.add(neighbor);
          next.add(neighbor);
        }
      });
    });
    if (next.size === 0) break;
    frontier = next;
  }
  return result;
}

function canonicalPathSegments(chain: string[]): Set<string> {
  const selected = new Set<string>(chain);
  chain.forEach((id, index) => {
    if (index > 0) {
      selected.add(`${chain[index - 1]}→${id}`);
    }
  });
  return selected;
}

export function buildHighlightState(model: GraphModel, selection: GraphSelection, mode: string): HighlightState {
  const adjacency = buildAdjacency(model.links);
  const nodesById = new Map(model.nodes.map((node) => [node.id, node]));
  const highlightedNodes = new Set<string>();
  const highlightedLinks = new Set<string>();
  const focusedNodes = new Set<string>();
  const focusedLinks = new Set<string>();
  const mitigationNodes = new Set<string>();
  const mitigationLinks = new Set<string>();

  const seedNodes = new Set<string>(model.routeChain);
  if (selection?.kind === "node") {
    seedNodes.add(selection.id);
  } else if (selection?.kind === "edge") {
    const link = model.links.find((item) => item.id === selection.id);
    if (link) {
      seedNodes.add(graphLinkSourceId(link));
      seedNodes.add(graphLinkTargetId(link));
    }
  }

  model.links.forEach((link) => {
    if (!isMitigationLink(link, model.nodes)) return;
    const sourceId = graphLinkSourceId(link);
    const targetId = graphLinkTargetId(link);
    mitigationLinks.add(link.id);
    mitigationNodes.add(sourceId);
    mitigationNodes.add(targetId);
    adjacency.get(sourceId)?.forEach((neighbor) => {
      if (isDefensiveGraphNode(nodesById.get(neighbor)) || isDefensiveGraphNode(nodesById.get(targetId))) mitigationNodes.add(neighbor);
    });
  });

  if (mode === "mitigation-path") {
    mitigationNodes.forEach((id) => seedNodes.add(id));
  }

  const modeDepth = mode === "full-traceability" ? 3 : mode === "reasoning-neighborhood" ? 2 : mode === "mitigation-path" ? 2 : 1;
  seedNodes.forEach((id) => {
    selectNodeNeighbors(id, adjacency, modeDepth).forEach((neighbor) => highlightedNodes.add(neighbor));
  });

  model.links.forEach((link) => {
    const sourceId = graphLinkSourceId(link);
    const targetId = graphLinkTargetId(link);
    const nodeVisible = highlightedNodes.has(sourceId) && highlightedNodes.has(targetId);
    const canonical = canonicalPathSegments(model.routeChain).has(`${sourceId}→${targetId}`);
    if (nodeVisible || canonical || (mode === "mitigation-path" && mitigationLinks.has(link.id))) {
      highlightedLinks.add(link.id);
    }
  });

  if (mode === "mitigation-path") {
    mitigationNodes.forEach((id) => highlightedNodes.add(id));
    mitigationLinks.forEach((id) => highlightedLinks.add(id));
  }

  if (selection?.kind === "node") {
    focusedNodes.add(selection.id);
    adjacency.get(selection.id)?.forEach((neighbor) => {
      focusedNodes.add(neighbor);
      model.links.forEach((link) => {
        const sourceId = graphLinkSourceId(link);
        const targetId = graphLinkTargetId(link);
        if ((sourceId === selection.id && targetId === neighbor) || (targetId === selection.id && sourceId === neighbor)) {
          focusedLinks.add(link.id);
        }
      });
    });
  }

  if (selection?.kind === "edge") {
    const link = model.links.find((item) => item.id === selection.id);
    if (link) {
      const sourceId = graphLinkSourceId(link);
      const targetId = graphLinkTargetId(link);
      focusedNodes.add(sourceId);
      focusedNodes.add(targetId);
      focusedLinks.add(link.id);
      adjacency.get(sourceId)?.forEach((neighbor) => focusedNodes.add(neighbor));
      adjacency.get(targetId)?.forEach((neighbor) => focusedNodes.add(neighbor));
    }
  }

  return { highlightedNodes, highlightedLinks, focusedNodes, focusedLinks, mitigationNodes, mitigationLinks };
}

export function visibleNodeIdsForModel(model: GraphModel, selection: GraphSelection, mode: string): Set<string> {
  const highlighted = buildHighlightState(model, selection, mode).highlightedNodes;
  return highlighted.size > 0 ? highlighted : new Set(model.visibleNodeIds);
}

export function isMitigationLink(link: Pick<GraphLinkData, "source" | "target" | "classification">, nodes: GraphNodeData[]): boolean {
  const source = nodes.find((node) => node.id === graphLinkSourceId(link));
  const target = nodes.find((node) => node.id === graphLinkTargetId(link));
  return Boolean(source && target && !isDefensiveGraphNode(source) && isDefensiveGraphNode(target));
}
