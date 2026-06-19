import type { ReasoningEdgeClassification, ReasoningResult } from "@/lib/reasoningTypes";

export type GraphMode = "focused-route" | "reasoning-neighborhood" | "mitigation-path" | "full-traceability" | "evidence-view";

/** Stage layout: deterministic semantic-layer trace vs. free force simulation. */
export type GraphLayout = "trace" | "force";

/** Route emphasis cherry-picker: full route vs. primary/canonical spine only. */
export type GraphRouteEmphasis = "all" | "primary";

export type GraphSelection =
  | { kind: "node"; id: string }
  | { kind: "edge"; id: string }
  | null;

export type GraphNodeKind = "cve" | "cwe" | "capec" | "attack" | "defend" | "control" | "detection" | "mitigation" | "evidence" | "gap" | "candidate" | "context";

export type GraphRouteRole = "canonical" | "primary" | "secondary" | "conditional" | "defensive" | "weak-fit" | "context";

export interface GraphNodeData {
  id: string;
  kind: GraphNodeKind;
  label: string;
  shortLabel: string;
  routeRole: GraphRouteRole;
  confidence: number;
  description: string;
  tags: string[];
  evidence: string[];
  sourceRefs: string[];
  sourceUrl: string | null;
  officialUrl: string | null;
  reviewRequired: boolean;
  synthetic: boolean;
  cveIds: string[];
  routeIds: string[];
  sharedCveCount: number;
  defensiveReuseCount: number;
  backendMetadata: Record<string, unknown>;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number;
  fy?: number;
}

export type GraphEndpoint = string | number | Pick<GraphNodeData, "id">;

export interface GraphLinkData {
  id: string;
  source: GraphEndpoint;
  target: GraphEndpoint;
  type: string;
  label: string;
  classification: ReasoningEdgeClassification;
  confidence: number;
  evidence: string[];
  sourceRefs: string[];
  sourceUrl: string | null;
  note: string | null;
  deterministic: boolean;
  inferred: boolean;
  conditional: boolean;
  weakFit: boolean;
  reviewRequired: boolean;
  cveIds: string[];
  routeIds: string[];
  backendMetadata: Record<string, unknown>;
}

export interface GraphModel {
  nodes: GraphNodeData[];
  links: GraphLinkData[];
  hiddenNodeCount: number;
  hiddenLinkCount: number;
  visibleNodeIds: Set<string>;
  visibleLinkIds: Set<string>;
  routeChain: string[];
  routeConfidence: number;
}

export interface NodeViewModel {
  kind: "node";
  node: GraphNodeData;
  selected: boolean;
  focused: boolean;
  highlighted: boolean;
}

export interface LinkViewModel {
  kind: "edge";
  link: GraphLinkData;
  selected: boolean;
  highlighted: boolean;
}

export function isGraphSelection(value: GraphSelection): value is NonNullable<GraphSelection> {
  return Boolean(value);
}

export function routeConfidenceLabel(result: ReasoningResult): string {
  const chain = result.route.canonical_chain.length > 0 ? result.route.canonical_chain.join(" → ") : "Partial route";
  return chain;
}
