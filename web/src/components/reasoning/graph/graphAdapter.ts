import { classificationNeedsReview } from "@/lib/colors";
import type { ReasoningEdge, ReasoningResult } from "@/lib/reasoningTypes";
import { buildOfficialUrl } from "./officialUrlBuilder";
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
    sourceUrl: edge.source_url,
    note: edge.note,
    deterministic: edge.deterministic,
    inferred: edge.inferred,
    conditional: edge.conditional,
    weakFit: edge.weak_fit,
    reviewRequired: classificationNeedsReview(edge.classification),
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
      officialUrl: buildOfficialUrl(id),
      reviewRequired: routeRole === "conditional" || routeRole === "weak-fit" || result.edges.some((edge) => (edge.source === id || edge.target === id) && classificationNeedsReview(edge.classification)),
      synthetic: false,
    };
    nodesById.set(id, node);
    return node;
  };

  seeds.forEach((id) => ensureNode(id));
  links.forEach((link) => {
    ensureNode(link.source);
    ensureNode(link.target);
  });

  const baseVisible = prioritizeIds([...seeds], result, selection);
  const cap = visibleCap(mode);
  const visibleIds = new Set<string>(baseVisible.slice(0, cap));
  if (selection?.kind === "node") visibleIds.add(selection.id);
  if (selection?.kind === "edge") {
    const selectedEdge = links.find((link) => link.id === selection.id);
    if (selectedEdge) {
      visibleIds.add(selectedEdge.source);
      visibleIds.add(selectedEdge.target);
    }
  }

  const visibleLinks = links.filter((link) => visibleIds.has(link.source) && visibleIds.has(link.target));
  visibleLinks.forEach((link) => {
    visibleIds.add(link.source);
    visibleIds.add(link.target);
  });

  // If the selected route still leaves room, retain a few extra neighbors so the
  // canvas stays honest without becoming a wall of nodes.
  if (visibleIds.size < cap) {
    const extras = prioritizeIds(
      [...new Set([...result.edges.flatMap((edge) => [edge.source, edge.target]), ...routeIds])].filter((id) => !visibleIds.has(id)),
      result,
      selection
    );
    extras.slice(0, cap - visibleIds.size).forEach((id) => visibleIds.add(id));
  }

  const visibleNodes = [...visibleIds].map((id) => nodesById.get(id) ?? ensureNode(id));
  const filteredLinks = links.filter((link) => visibleIds.has(link.source) && visibleIds.has(link.target));

  const canonicalConfidences = routeChain
    .slice(1)
    .map((targetId, index) => {
      const sourceId = routeChain[index];
      return links.find((link) => link.source === sourceId && link.target === targetId)?.confidence;
    })
    .filter((value): value is number => typeof value === "number");
  const routeConfidence = canonicalConfidences.length > 0 ? canonicalConfidences.reduce((sum, value) => sum + value, 0) / canonicalConfidences.length : num(result.edges[0]?.confidence, 0.5);

  return {
    nodes: visibleNodes,
    links: filteredLinks,
    hiddenNodeCount: Math.max(0, nodesById.size - visibleIds.size),
    hiddenLinkCount: Math.max(0, links.length - filteredLinks.length),
    visibleNodeIds: visibleIds,
    visibleLinkIds: new Set(filteredLinks.map((link) => link.id)),
    routeChain,
    routeConfidence,
  };
}
