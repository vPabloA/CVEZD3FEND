// Canonical/inferred/gap/evidence/offense/defense/template color tokens.
// UIX_CONTRACT §4 — all node/edge color decisions go through this module,
// no inline hex anywhere else.
import type { BundleNode, BundleEdge, CoverageStatus, NodeType } from "./types";

export const COLORS = {
  ok: "#1a7f37",
  link: "#1f6feb",
  inferred: "#d97706",
  gap: "#b91c1c",
  evidence: "#7c3aed",
  offense: "#c2410c",
  defense: "#15803d",
  template: "#6b7280",
} as const;

export type ColorToken = keyof typeof COLORS;

const OFFENSE_TYPES = new Set<NodeType>(["attack", "capec", "atlas"]);
const DEFENSE_TYPES = new Set<NodeType>(["defend", "control", "mitigation"]);
const TEMPLATE_TYPES = new Set<NodeType>([
  "playbook",
  "soc_action",
  "ctem_action",
  "rule",
  "query",
  "data_source",
  "log_source",
  "threat_hunt",
]);

/** Tailwind text-color class for a node, per UIX_CONTRACT semantics. */
export function nodeColorClass(node: Pick<BundleNode, "type" | "inferred">): string {
  if (node.inferred) return "text-inferred";
  if (node.type === "gap") return "text-gap";
  if (node.type === "evidence") return "text-evidence";
  if (OFFENSE_TYPES.has(node.type)) return "text-offense";
  if (DEFENSE_TYPES.has(node.type)) return "text-defense";
  if (TEMPLATE_TYPES.has(node.type)) return "text-template";
  return "text-link";
}

/** Tailwind border-color class for a node card/box. */
export function nodeBorderClass(node: Pick<BundleNode, "type" | "inferred">): string {
  if (node.inferred) return "border-inferred";
  if (node.type === "gap") return "border-gap";
  if (node.type === "evidence") return "border-evidence";
  if (OFFENSE_TYPES.has(node.type)) return "border-offense";
  if (DEFENSE_TYPES.has(node.type)) return "border-defense";
  if (TEMPLATE_TYPES.has(node.type)) return "border-template";
  return "border-link";
}

/** Border style — dashed for template/scaffolding nodes and AI-promoted edges. */
export function nodeBorderStyle(node: Pick<BundleNode, "type">): "dashed" | "solid" {
  return TEMPLATE_TYPES.has(node.type) ? "dashed" : "solid";
}

export function edgeColorClass(edge: Pick<BundleEdge, "inferred" | "type">): string {
  if (edge.inferred) return "text-inferred";
  if (edge.type === "gap_blocks_coverage") return "text-gap";
  return "text-link";
}

export function edgeIsAiPromoted(edge: Pick<BundleEdge, "metadata">): boolean {
  return Boolean((edge.metadata as Record<string, unknown> | undefined)?.promoted_from_candidate);
}

export function coverageColorClass(status: CoverageStatus): string {
  switch (status) {
    case "covered":
      return "text-ok";
    case "partial":
    case "gap":
      return "text-gap";
    default:
      return "text-template";
  }
}

export function coverageBgClass(status: CoverageStatus): string {
  switch (status) {
    case "covered":
      return "bg-green-50 text-ok border-ok";
    case "partial":
      return "bg-amber-50 text-amber-700 border-amber-300";
    case "gap":
      return "bg-red-50 text-gap border-gap";
    default:
      return "bg-slate-100 text-template border-template";
  }
}

/** Human-readable label for an ATT&CK/CAPEC/etc node-type code, for icons/aria-labels. */
export function nodeTypeLabel(type: NodeType): string {
  return type
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
