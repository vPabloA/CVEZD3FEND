import type { GraphLinkData, GraphModel, GraphNodeData, GraphSelection } from "./graphTypes";

export interface HighlightState {
  highlightedNodes: Set<string>;
  highlightedLinks: Set<string>;
  focusedNodes: Set<string>;
  focusedLinks: Set<string>;
}

function buildAdjacency(links: GraphLinkData[]): Map<string, Set<string>> {
  const adjacency = new Map<string, Set<string>>();
  links.forEach((link) => {
    const source = adjacency.get(link.source) ?? new Set<string>();
    const target = adjacency.get(link.target) ?? new Set<string>();
    source.add(link.target);
    target.add(link.source);
    adjacency.set(link.source, source);
    adjacency.set(link.target, target);
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
  const highlightedNodes = new Set<string>();
  const highlightedLinks = new Set<string>();
  const focusedNodes = new Set<string>();
  const focusedLinks = new Set<string>();

  const seedNodes = new Set<string>(model.routeChain);
  if (selection?.kind === "node") {
    seedNodes.add(selection.id);
  } else if (selection?.kind === "edge") {
    const link = model.links.find((item) => item.id === selection.id);
    if (link) {
      seedNodes.add(link.source);
      seedNodes.add(link.target);
    }
  }

  const modeDepth = mode === "full-traceability" ? 3 : mode === "reasoning-neighborhood" ? 2 : mode === "mitigation-path" ? 2 : 1;
  seedNodes.forEach((id) => {
    selectNodeNeighbors(id, adjacency, modeDepth).forEach((neighbor) => highlightedNodes.add(neighbor));
  });

  model.links.forEach((link) => {
    const nodeVisible = highlightedNodes.has(link.source) && highlightedNodes.has(link.target);
    const canonical = canonicalPathSegments(model.routeChain).has(`${link.source}→${link.target}`);
    if (nodeVisible || canonical) {
      highlightedLinks.add(link.id);
    }
  });

  if (selection?.kind === "node") {
    focusedNodes.add(selection.id);
    adjacency.get(selection.id)?.forEach((neighbor) => {
      focusedNodes.add(neighbor);
      model.links.forEach((link) => {
        if ((link.source === selection.id && link.target === neighbor) || (link.target === selection.id && link.source === neighbor)) {
          focusedLinks.add(link.id);
        }
      });
    });
  }

  if (selection?.kind === "edge") {
    const link = model.links.find((item) => item.id === selection.id);
    if (link) {
      focusedNodes.add(link.source);
      focusedNodes.add(link.target);
      focusedLinks.add(link.id);
      adjacency.get(link.source)?.forEach((neighbor) => focusedNodes.add(neighbor));
      adjacency.get(link.target)?.forEach((neighbor) => focusedNodes.add(neighbor));
    }
  }

  return { highlightedNodes, highlightedLinks, focusedNodes, focusedLinks };
}

export function visibleNodeIdsForModel(model: GraphModel, selection: GraphSelection, mode: string): Set<string> {
  const highlighted = buildHighlightState(model, selection, mode).highlightedNodes;
  return highlighted.size > 0 ? highlighted : new Set(model.visibleNodeIds);
}

export function isMitigationLink(link: Pick<GraphLinkData, "source" | "target" | "classification">, nodes: GraphNodeData[]): boolean {
  const source = nodes.find((node) => node.id === link.source);
  const target = nodes.find((node) => node.id === link.target);
  return Boolean(source && target && source.kind !== "defend" && target.kind === "defend");
}
