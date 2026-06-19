import { classificationNeedsReview } from "@/lib/colors";
import type { GraphSlice, RankedRoute, ReasoningEdge, ReasoningResult } from "@/lib/reasoningTypes";
import type { BundleEdge, BundleNode } from "@/lib/types";
import { buildTrustedOfficialUrl } from "./officialUrlBuilder";
import { graphLinkSourceId, graphLinkTargetId } from "./graphRuntime";
import type { GraphLinkData, GraphModel, GraphNodeData, GraphNodeKind, GraphRouteRole, GraphSelection } from "./graphTypes";

const ROUTE_ROLE_PRIORITY: Record<GraphRouteRole, number> = {
  canonical: 0,
  primary: 1,
  secondary: 2,
  conditional: 3,
  defensive: 4,
  "weak-fit": 5,
  context: 6,
};

const KIND_PRIORITY: Record<GraphNodeKind, number> = {
  cve: 0,
  cwe: 1,
  capec: 2,
  attack: 3,
  defend: 4,
  mitigation: 5,
  control: 6,
  detection: 7,
  evidence: 8,
  gap: 9,
  candidate: 10,
  context: 11,
};

const MODE_CAP: Record<string, number> = {
  "focused-route": 28,
  "reasoning-neighborhood": 44,
  "mitigation-path": 40,
  "full-traceability": 64,
  "evidence-view": 52,
};

function num(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function safeExternalUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}


function routeRoleFor(id: string, result: ReasoningResult): GraphRouteRole {
  if (result.route.canonical_chain.includes(id)) return "canonical";
  if (result.route.primary_nodes.includes(id)) return "primary";
  if (result.route.secondary_nodes.includes(id)) return "secondary";
  if (result.route.conditional_nodes.includes(id)) return "conditional";
  if (result.route.defensive_nodes.includes(id)) return "defensive";
  if (result.route.weak_fit_nodes.includes(id)) return "weak-fit";
  return "context";
}

export function nodeKindForId(id: string): GraphNodeKind {
  if (/^CVE-/i.test(id)) return "cve";
  if (/^CWE-/i.test(id)) return "cwe";
  if (/^CAPEC-/i.test(id)) return "capec";
  if (/^T\d/i.test(id) || /^TA\d/i.test(id)) return "attack";
  if (/^D3-/i.test(id) || /^D3F:/i.test(id)) return "defend";
  if (/^CTRL-/i.test(id)) return "control";
  if (/^DET-/i.test(id)) return "detection";
  if (/^(?:MIT-|MITIG-|MITIGATION-)/i.test(id)) return "mitigation";
  if (/^EVID-/i.test(id)) return "evidence";
  if (/^GAP-/i.test(id)) return "gap";
  if (/^AI-/i.test(id) || /candidate/i.test(id)) return "candidate";
  return "context";
}

function shortLabel(id: string): string {
  return id.length > 18 ? `${id.slice(0, 15)}…` : id;
}

function nodeDescription(kind: GraphNodeKind, routeRole: GraphRouteRole): string {
  const routeText =
    routeRole === "canonical"
      ? "Canonical route node"
      : routeRole === "primary"
        ? "Primary route node"
        : routeRole === "secondary"
          ? "Secondary route node"
          : routeRole === "conditional"
            ? "Conditional branch"
            : routeRole === "defensive"
              ? "Defensive path node"
              : routeRole === "weak-fit"
                ? "Weak-fit relation"
                : "Context node";

  const kindText: Record<GraphNodeKind, string> = {
    cve: "CVE vulnerability entry",
    cwe: "CWE weakness",
    capec: "CAPEC attack pattern",
    attack: "MITRE ATT&CK technique",
    defend: "MITRE D3FEND technique",
    control: "Operational control",
    detection: "Detection opportunity",
    mitigation: "Mitigation path node",
    evidence: "Evidence reference",
    gap: "Coverage gap",
    candidate: "AI candidate relation",
    context: "Context node",
  };

  return `${routeText} · ${kindText[kind]}`;
}

function collectEvidence(edges: ReasoningEdge[], nodeId: string): string[] {
  const evidence = new Set<string>();
  edges.forEach((edge) => {
    if (edge.source === nodeId || edge.target === nodeId) {
      edge.evidence.forEach((item) => evidence.add(item));
    }
  });
  return [...evidence].slice(0, 5);
}

function collectSourceRefs(edges: ReasoningEdge[], nodeId: string): string[] {
  const refs = new Set<string>();
  edges.forEach((edge) => {
    if (edge.source === nodeId || edge.target === nodeId) {
      edge.source_refs.forEach((ref) => refs.add(ref));
    }
  });
  return [...refs].slice(0, 5);
}

function nodeConfidence(result: ReasoningResult, id: string): number {
  const nodeEdges = result.edges.filter((edge) => edge.source === id || edge.target === id);
  if (nodeEdges.length === 0) return 1;
  return Math.max(...nodeEdges.map((edge) => num(edge.confidence, 0.5)));
}

function prioritizeIds(ids: string[], result: ReasoningResult, selection: GraphSelection): string[] {
  const focusNodeId = selection?.kind === "node" ? selection.id : null;
  const focusEdge = selection?.kind === "edge" ? result.edges.find((edge) => edge.id === selection.id) : null;
  return [...new Set(ids)].sort((a, b) => {
    const roleA = ROUTE_ROLE_PRIORITY[routeRoleFor(a, result)];
    const roleB = ROUTE_ROLE_PRIORITY[routeRoleFor(b, result)];
    if (roleA !== roleB) return roleA - roleB;
    const kindA = KIND_PRIORITY[nodeKindForId(a)];
    const kindB = KIND_PRIORITY[nodeKindForId(b)];
    if (kindA !== kindB) return kindA - kindB;
    const focusBoostA = a === focusNodeId || (focusEdge && (a === focusEdge.source || a === focusEdge.target)) ? -2 : 0;
    const focusBoostB = b === focusNodeId || (focusEdge && (b === focusEdge.source || b === focusEdge.target)) ? -2 : 0;
    if (focusBoostA !== focusBoostB) return focusBoostA - focusBoostB;
    return a.localeCompare(b);
  });
}

function collectSeedIds(result: ReasoningResult): Set<string> {
  const seeds = new Set<string>([
    ...result.route.canonical_chain,
    ...result.route.primary_nodes,
    ...result.route.secondary_nodes,
    ...result.route.conditional_nodes,
    ...result.route.defensive_nodes,
    ...result.route.weak_fit_nodes,
  ]);
  result.edges.forEach((edge) => {
    seeds.add(edge.source);
    seeds.add(edge.target);
  });
  return seeds;
}

function visibleCap(mode: string): number {
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

export function buildGraphModel(result: ReasoningResult, mode: string, selection: GraphSelection): GraphModel {
  const seeds = collectSeedIds(result);
  const routeChain = result.route.canonical_chain.slice();
  const routeIds = new Set<string>([
    ...routeChain,
    ...result.route.primary_nodes,
    ...result.route.secondary_nodes,
    ...result.route.conditional_nodes,
    ...result.route.defensive_nodes,
    ...result.route.weak_fit_nodes,
  ]);

  const nodesById = new Map<string, GraphNodeData>();
  const links: GraphLinkData[] = result.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: edge.type,
    label: edge.type.replace(/_/g, " "),
    classification: edge.classification,
    confidence: num(edge.confidence, 0.5),
    evidence: edge.evidence.slice(),
    sourceRefs: edge.source_refs.slice(),
    sourceUrl: safeExternalUrl(edge.source_url),
    note: edge.note,
    deterministic: edge.deterministic,
    inferred: edge.inferred,
    conditional: edge.conditional,
    weakFit: edge.weak_fit,
    reviewRequired: classificationNeedsReview(edge.classification),
    cveIds: [],
    routeIds: [],
    backendMetadata: {},
  }));

  const ensureNode = (id: string): GraphNodeData => {
    const existing = nodesById.get(id);
    if (existing) return existing;
    const routeRole = routeRoleFor(id, result);
    const kind = nodeKindForId(id);
    const node: GraphNodeData = {
      id,
      kind,
      label: id,
      shortLabel: shortLabel(id),
      routeRole,
      confidence: nodeConfidence(result, id),
      description: nodeDescription(kind, routeRole),
      tags: [kind.toUpperCase(), routeRole],
      evidence: collectEvidence(result.edges, id),
      sourceRefs: collectSourceRefs(result.edges, id),
      sourceUrl: result.edges.find((edge) => edge.source === id || edge.target === id)?.source_url ?? null,
      officialUrl: buildTrustedOfficialUrl(id, result.edges.find((edge) => edge.source === id || edge.target === id)?.source_url ?? null),
      reviewRequired: routeRole === "conditional" || routeRole === "weak-fit" || result.edges.some((edge) => (edge.source === id || edge.target === id) && classificationNeedsReview(edge.classification)),
      synthetic: false,
      cveIds: [],
      routeIds: [],
      sharedCveCount: 1,
      defensiveReuseCount: 1,
      backendMetadata: {},
    };
    nodesById.set(id, node);
    return node;
  };

  seeds.forEach((id) => ensureNode(id));
  links.forEach((link) => {
    ensureNode(graphLinkSourceId(link));
    ensureNode(graphLinkTargetId(link));
  });

  const baseVisible = prioritizeIds([...seeds], result, selection);
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

  if (visibleIds.size < cap) {
    const extras = prioritizeIds(
      [...new Set([...result.edges.flatMap((edge) => [edge.source, edge.target]), ...routeIds])].filter((id) => !visibleIds.has(id)),
      result,
      selection
    );
    extras.slice(0, cap - visibleIds.size).forEach((id) => visibleIds.add(id));
  }

  const visibleNodes = [...visibleIds].map((id) => nodesById.get(id) ?? ensureNode(id));
  const filteredLinks = links.filter((link) => visibleIds.has(graphLinkSourceId(link)) && visibleIds.has(graphLinkTargetId(link)));

  const canonicalConfidences = routeChain
    .slice(1)
    .map((targetId, index) => {
      const sourceId = routeChain[index];
      return links.find((link) => graphLinkSourceId(link) === sourceId && graphLinkTargetId(link) === targetId)?.confidence;
    })
    .filter((value): value is number => typeof value === "number");
  const routeConfidence = canonicalConfidences.length > 0 ? canonicalConfidences.reduce((sum, value) => sum + value, 0) / canonicalConfidences.length : num(result.edges[0]?.confidence, 0.5);
  const integrity = singleRouteIntegrity(routeChain, [...nodesById.values()], links);

  return {
    nodes: visibleNodes,
    links: filteredLinks,
    hiddenNodeCount: Math.max(0, nodesById.size - visibleIds.size),
    hiddenLinkCount: Math.max(0, links.length - filteredLinks.length),
    visibleNodeIds: visibleIds,
    visibleLinkIds: new Set(filteredLinks.map((link) => link.id)),
    routeChain,
    routeConfidence,
    focusedRouteComplete: integrity.complete,
    focusedRouteGaps: integrity.gaps,
  };
}


function edgeState(edge: BundleEdge, field: "resolution_state" | "scope_state"): string | undefined {
  const direct = edge[field];
  if (typeof direct === "string") return direct;
  const metadataValue = edge.metadata?.[field];
  return typeof metadataValue === "string" ? metadataValue : undefined;
}

function classificationForBundleEdge(edge: BundleEdge): ReasoningEdge["classification"] {
  if (edge.inferred) return "analytical_inferred";
  const resolution = edgeState(edge, "resolution_state");
  if (resolution === "unresolved" || resolution === "invalid") return "unverified";
  if (edgeState(edge, "scope_state") === "contextual") return "conditional";
  return edge.deterministic ? "dataset_derived" : "official_incomplete";
}

function batchRouteRole(node: BundleNode, routeIds: string[], primaryRouteIds: Set<string>): GraphRouteRole {
  if (node.type === "defend" || node.type === "control" || node.type === "mitigation") return "defensive";
  if (node.type === "gap") return "weak-fit";
  if (routeIds.some((routeId) => primaryRouteIds.has(routeId))) return "primary";
  return routeIds.length > 0 ? "secondary" : "context";
}

function routeIndex(routes: RankedRoute[]): {
  nodeRoutes: Map<string, Set<string>>;
  edgeRoutes: Map<string, Set<string>>;
  nodeCves: Map<string, Set<string>>;
  edgeCves: Map<string, Set<string>>;
} {
  const nodeRoutes = new Map<string, Set<string>>();
  const edgeRoutes = new Map<string, Set<string>>();
  const nodeCves = new Map<string, Set<string>>();
  const edgeCves = new Map<string, Set<string>>();
  routes.forEach((route) => {
    route.node_ids.forEach((id) => {
      const routesForNode = nodeRoutes.get(id) ?? new Set<string>();
      routesForNode.add(route.route_id);
      nodeRoutes.set(id, routesForNode);
      const cvesForNode = nodeCves.get(id) ?? new Set<string>();
      cvesForNode.add(route.cve_id);
      nodeCves.set(id, cvesForNode);
    });
    route.edge_ids.forEach((id) => {
      const routesForEdge = edgeRoutes.get(id) ?? new Set<string>();
      routesForEdge.add(route.route_id);
      edgeRoutes.set(id, routesForEdge);
      const cvesForEdge = edgeCves.get(id) ?? new Set<string>();
      cvesForEdge.add(route.cve_id);
      edgeCves.set(id, cvesForEdge);
    });
  });
  return { nodeRoutes, edgeRoutes, nodeCves, edgeCves };
}

function prioritizeBatchIds(
  nodes: GraphNodeData[],
  links: GraphLinkData[],
  selection: GraphSelection
): string[] {
  const focusNodeId = selection?.kind === "node" ? selection.id : null;
  const focusEdge = selection?.kind === "edge" ? links.find((edge) => edge.id === selection.id) : null;
  return [...nodes]
    .sort((a, b) => {
      const roleDifference = ROUTE_ROLE_PRIORITY[a.routeRole] - ROUTE_ROLE_PRIORITY[b.routeRole];
      if (roleDifference !== 0) return roleDifference;
      const kindDifference = KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind];
      if (kindDifference !== 0) return kindDifference;
      const focusBoostA =
        a.id === focusNodeId ||
        (focusEdge && (a.id === graphLinkSourceId(focusEdge) || a.id === graphLinkTargetId(focusEdge)))
          ? -2
          : 0;
      const focusBoostB =
        b.id === focusNodeId ||
        (focusEdge && (b.id === graphLinkSourceId(focusEdge) || b.id === graphLinkTargetId(focusEdge)))
          ? -2
          : 0;
      if (focusBoostA !== focusBoostB) return focusBoostA - focusBoostB;
      return a.id.localeCompare(b.id);
    })
    .map((node) => node.id);
}

export function projectGraphSliceByRoutes(slice: GraphSlice, routes: RankedRoute[]): GraphSlice {
  const nodeIds = new Set(routes.flatMap((route) => route.node_ids));
  const edgeIds = new Set(routes.flatMap((route) => route.edge_ids));
  return {
    nodes: slice.nodes.filter((node) => nodeIds.has(node.id)),
    edges: slice.edges.filter((edge) => edgeIds.has(edge.id) && nodeIds.has(edge.source) && nodeIds.has(edge.target)),
  };
}

export function buildBatchGraphModel(
  slice: GraphSlice,
  routes: RankedRoute[],
  mode: string,
  selection: GraphSelection,
  focusedRouteId?: string | null
): GraphModel {
  const { nodeRoutes, edgeRoutes, nodeCves, edgeCves } = routeIndex(routes);
  const focusedRoute = routes.find((route) => route.route_id === focusedRouteId) ?? routes[0];
  const primaryRouteIds = new Set(focusedRoute ? [focusedRoute.route_id] : []);
  const routeChain = focusedRoute?.node_ids.slice() ?? [];
  const nodes: GraphNodeData[] = slice.nodes.map((node) => {
    const routeIds = [...(nodeRoutes.get(node.id) ?? new Set<string>())].sort();
    const cveIds = [...(nodeCves.get(node.id) ?? new Set<string>())].sort();
    const routeRole = batchRouteRole(node, routeIds, primaryRouteIds);
    const evidence = new Set<string>();
    const sourceRefs = new Set<string>(node.source_refs);
    slice.edges.forEach((edge) => {
      if (edge.source === node.id || edge.target === node.id) {
        edge.evidence.forEach((item) => evidence.add(item));
        if (edge.source_ref) sourceRefs.add(edge.source_ref);
      }
    });
    return {
      id: node.id,
      kind: nodeKindForId(node.id),
      label: node.title || node.name || node.id,
      shortLabel: shortLabel(node.id),
      routeRole,
      confidence: num(node.confidence, 1),
      description: node.description || nodeDescription(nodeKindForId(node.id), routeRole),
      tags: [...new Set([node.type.toUpperCase(), routeRole, ...node.tags])],
      evidence: [...evidence].slice(0, 8),
      sourceRefs: [...sourceRefs].slice(0, 8),
      sourceUrl: safeExternalUrl(node.external_refs.find((ref) => /^https?:\/\//i.test(ref))),
      officialUrl: buildTrustedOfficialUrl(node.id, safeExternalUrl(node.external_refs.find((ref) => /^https?:\/\//i.test(ref)))) ,
      reviewRequired: node.inferred || routeRole === "weak-fit" || routeRole === "conditional",
      synthetic: false,
      cveIds,
      routeIds,
      sharedCveCount: cveIds.length || 1,
      defensiveReuseCount: node.type === "defend" ? cveIds.length || 1 : 1,
      backendMetadata: node.metadata,
    };
  });

  const links: GraphLinkData[] = slice.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: edge.type,
    label: edge.label || edge.type.replace(/_/g, " "),
    classification: classificationForBundleEdge(edge),
    confidence: num(edge.confidence, 0.5),
    evidence: edge.evidence.slice(),
    sourceRefs: edge.source_ref ? [edge.source_ref] : [],
    sourceUrl: safeExternalUrl(edge.source_url),
    note: null,
    deterministic: edge.deterministic,
    inferred: edge.inferred,
    conditional: edgeState(edge, "scope_state") === "contextual",
    weakFit: edgeState(edge, "resolution_state") === "unresolved" || edgeState(edge, "resolution_state") === "invalid",
    reviewRequired: edge.inferred || edgeState(edge, "resolution_state") === "unresolved" || edgeState(edge, "resolution_state") === "invalid",
    cveIds: [...(edgeCves.get(edge.id) ?? new Set<string>())].sort(),
    routeIds: [...(edgeRoutes.get(edge.id) ?? new Set<string>())].sort(),
    backendMetadata: edge.metadata,
  }));

  const orderedIds = prioritizeBatchIds(nodes, links, selection);
  const cap = visibleCap(mode);
  const sourceNodeIds = new Set(nodes.map((node) => node.id));
  const visibleNodeIds = new Set((focusedRoute?.node_ids ?? []).filter((id) => sourceNodeIds.has(id)));

  // Preserve every backend-delivered focused-route edge and endpoint. Missing
  // source edges remain explicit gaps and are never synthesized in React.
  const focusedEdgeIds = new Set(focusedRoute?.edge_ids ?? []);
  links.filter((link) => focusedEdgeIds.has(link.id)).forEach((link) => {
    visibleNodeIds.add(graphLinkSourceId(link));
    visibleNodeIds.add(graphLinkTargetId(link));
  });
  if (selection?.kind === "node" && sourceNodeIds.has(selection.id)) visibleNodeIds.add(selection.id);
  if (selection?.kind === "edge") {
    const selectedEdge = links.find((link) => link.id === selection.id);
    if (selectedEdge) {
      visibleNodeIds.add(graphLinkSourceId(selectedEdge));
      visibleNodeIds.add(graphLinkTargetId(selectedEdge));
    }
  }

  orderedIds.filter((id) => !visibleNodeIds.has(id)).slice(0, Math.max(0, cap - visibleNodeIds.size)).forEach((id) => visibleNodeIds.add(id));

  const visibleLinks = links.filter((link) => visibleNodeIds.has(graphLinkSourceId(link)) && visibleNodeIds.has(graphLinkTargetId(link)));
  const visibleNodes = nodes.filter((node) => visibleNodeIds.has(node.id));
  const integrity = batchRouteIntegrity(focusedRoute, nodes, links);
  return {
    nodes: visibleNodes,
    links: visibleLinks,
    hiddenNodeCount: Math.max(0, nodes.length - visibleNodes.length),
    hiddenLinkCount: Math.max(0, links.length - visibleLinks.length),
    visibleNodeIds,
    visibleLinkIds: new Set(visibleLinks.map((link) => link.id)),
    routeChain,
    routeConfidence: focusedRoute?.confidence ?? 0,
    focusedRouteComplete: integrity.complete,
    focusedRouteGaps: integrity.gaps,
  };
}
