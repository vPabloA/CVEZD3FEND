// Trace layout — deterministic semantic-layer placement for the graph stage.
//
// Inspired by the layered "causal chain" reading explored in Attack2Defend:
// fixed columns CVE → CWE → CAPEC → ATT&CK → D3FEND (+ a context lane), with
// the canonical route spine pinned to the top row and alternatives stacked
// below it. Implemented as pure position assignment on the existing
// react-force-graph node copies (fx/fy pinning) — no new dependencies and no
// change to the graph model contract.
import type { GraphNodeData, GraphNodeKind, GraphRouteRole } from "./graphTypes";

export interface TraceLayer {
  id: "cve" | "cwe" | "capec" | "attack" | "defend" | "context";
  label: string;
  defensive: boolean;
}

export const TRACE_LAYERS: TraceLayer[] = [
  { id: "cve", label: "CVE", defensive: false },
  { id: "cwe", label: "CWE", defensive: false },
  { id: "capec", label: "CAPEC", defensive: false },
  { id: "attack", label: "ATT&CK", defensive: false },
  { id: "defend", label: "D3FEND · DEFENSE", defensive: true },
  { id: "context", label: "EVIDENCE · CONTEXT", defensive: false },
];

export const TRACE_COLUMN_GAP = 200;
export const TRACE_ROW_GAP = 56;

const KIND_TO_LAYER: Record<GraphNodeKind, TraceLayer["id"]> = {
  cve: "cve",
  cwe: "cwe",
  capec: "capec",
  attack: "attack",
  defend: "defend",
  mitigation: "defend",
  control: "defend",
  detection: "context",
  evidence: "context",
  gap: "context",
  candidate: "context",
  context: "context",
};

const ROW_ROLE_PRIORITY: Record<GraphRouteRole, number> = {
  canonical: 0,
  primary: 1,
  defensive: 2,
  secondary: 3,
  conditional: 4,
  "weak-fit": 5,
  context: 6,
};

export function traceLayerIdForKind(kind: GraphNodeKind): TraceLayer["id"] {
  return KIND_TO_LAYER[kind] ?? "context";
}

export function traceLayerIdForNode(node: Pick<GraphNodeData, "kind" | "routeRole">): TraceLayer["id"] {
  if (node.routeRole === "defensive") return "defend";
  return traceLayerIdForKind(node.kind);
}

export function traceLayerIndexForKind(kind: GraphNodeKind): number {
  const id = traceLayerIdForKind(kind);
  return TRACE_LAYERS.findIndex((layer) => layer.id === id);
}

export interface TraceLane {
  layer: TraceLayer;
  x: number;
  nodeCount: number;
}

export interface TraceLayoutPlan {
  /** Lanes that actually contain nodes, in left→right order. */
  lanes: TraceLane[];
  /** Top y (canonical spine row) and bottom y across all lanes, for band painting. */
  top: number;
  bottom: number;
}

/**
 * Pin every node to its semantic lane. Mutates the supplied node copies
 * (fx/fy/x/y) — callers pass per-render clones, never the adapter's model.
 *
 * Row order inside a lane: canonical chain (in chain order) first — so the
 * CVE→…→D3FEND spine reads as a straight left→right line — then primary,
 * defensive, secondary, conditional, weak-fit and context nodes below.
 */
export function applyTraceLayout(nodes: GraphNodeData[], routeChain: string[]): TraceLayoutPlan {
  const chainOrder = new Map(routeChain.map((id, index) => [id, index] as const));
  const byLayer = new Map<TraceLayer["id"], GraphNodeData[]>();
  nodes.forEach((node) => {
    const layerId = traceLayerIdForNode(node);
    const bucket = byLayer.get(layerId) ?? [];
    bucket.push(node);
    byLayer.set(layerId, bucket);
  });

  const occupied = TRACE_LAYERS.filter((layer) => (byLayer.get(layer.id)?.length ?? 0) > 0);
  const lanes: TraceLane[] = [];
  let maxRows = 1;

  occupied.forEach((layer, laneIndex) => {
    const laneNodes = (byLayer.get(layer.id) ?? []).slice().sort((a, b) => {
      const chainA = chainOrder.has(a.id) ? 0 : 1;
      const chainB = chainOrder.has(b.id) ? 0 : 1;
      if (chainA !== chainB) return chainA - chainB;
      if (chainA === 0) return (chainOrder.get(a.id) ?? 0) - (chainOrder.get(b.id) ?? 0);
      const roleA = ROW_ROLE_PRIORITY[a.routeRole];
      const roleB = ROW_ROLE_PRIORITY[b.routeRole];
      if (roleA !== roleB) return roleA - roleB;
      return a.id.localeCompare(b.id);
    });

    const x = laneIndex * TRACE_COLUMN_GAP;
    laneNodes.forEach((node, row) => {
      node.fx = x;
      node.fy = row * TRACE_ROW_GAP;
      node.x = x;
      node.y = row * TRACE_ROW_GAP;
    });
    maxRows = Math.max(maxRows, laneNodes.length);
    lanes.push({ layer, x, nodeCount: laneNodes.length });
  });

  return {
    lanes,
    top: -TRACE_ROW_GAP * 0.9,
    bottom: (maxRows - 1) * TRACE_ROW_GAP + TRACE_ROW_GAP * 0.9,
  };
}

/** Remove trace pinning so the force simulation owns positions again. */
export function clearTraceLayout(nodes: GraphNodeData[]): void {
  nodes.forEach((node) => {
    delete node.fx;
    delete node.fy;
  });
}
