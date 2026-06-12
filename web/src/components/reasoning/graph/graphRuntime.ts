import type { GraphEndpoint, GraphLinkData, GraphNodeData } from "./graphTypes";

export function graphNodeId(value: GraphEndpoint | null | undefined): string {
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (value && typeof value === "object" && "id" in value && value.id !== undefined && value.id !== null) {
    return String(value.id);
  }
  return "";
}

export function graphLinkSourceId(link: Pick<GraphLinkData, "source">): string {
  return graphNodeId(link.source);
}

export function graphLinkTargetId(link: Pick<GraphLinkData, "target">): string {
  return graphNodeId(link.target);
}

export function isDefensiveGraphNode(node: GraphNodeData | undefined): boolean {
  return Boolean(node && (node.kind === "defend" || node.kind === "control" || node.kind === "mitigation" || node.routeRole === "defensive"));
}
