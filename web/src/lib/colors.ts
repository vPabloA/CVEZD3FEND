// Canonical/inferred/gap/evidence/offense/defense/template color tokens.
// UIX_CONTRACT §4 — all node/edge color decisions go through this module,
// no inline hex anywhere else.
import type { BundleNode, BundleEdge, CoverageStatus, NodeType } from "./types";
import type { ReasoningEdgeClassification, SourceMode } from "./reasoningTypes";

export const COLORS = {
  ok: "#1a7f37",
  link: "#1f6feb",
  inferred: "#d97706",
  gap: "#b91c1c",
  evidence: "#7c3aed",
  offense: "#c2410c",
  defense: "#15803d",
  template: "#6b7280",
  conditional: "#0e7490",
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

// ---------------------------------------------------------------------------
// Reasoning workbench extensions (UIX_CONTRACT §4 extension)
//
// The live reasoning plane classifies every edge into one of 7 levels —
// finer-grained than the bundle's canonical/inferred booleans. Each level
// maps onto an existing color token plus a distinct icon/label so color is
// never the only signal (UIX_CONTRACT §7); "conditional" is the only new token.
// ---------------------------------------------------------------------------

export const REASONING_CLASSIFICATION_LABELS: Record<ReasoningEdgeClassification, string> = {
  official_explicit: "Official",
  official_incomplete: "Official (partial)",
  dataset_derived: "Dataset-derived",
  analytical_inferred: "Analytical (AI)",
  conditional: "Conditional",
  weak_fit: "Weak fit",
  unverified: "Unverified",
};

export const REASONING_CLASSIFICATION_ICONS: Record<ReasoningEdgeClassification, string> = {
  official_explicit: "✓",
  official_incomplete: "✓~",
  dataset_derived: "◆",
  analytical_inferred: "✦",
  conditional: "◐",
  weak_fit: "┄",
  unverified: "?",
};

/** Tailwind text/border/bg classes for an edge-classification badge. */
export function classificationClass(classification: ReasoningEdgeClassification): string {
  switch (classification) {
    case "official_explicit":
      return "text-ok border-ok bg-green-50";
    case "official_incomplete":
      return "text-ok border-ok bg-green-50/60";
    case "dataset_derived":
      return "text-link border-link bg-blue-50";
    case "analytical_inferred":
      return "text-inferred border-inferred bg-amber-50";
    case "conditional":
      return "text-conditional border-conditional bg-cyan-50";
    case "weak_fit":
      return "text-template border-template bg-slate-100";
    case "unverified":
      return "text-gap border-gap bg-red-50";
  }
}

/** Dashed border for the two least-certain classifications, matching the AI-promoted edge convention. */
export function classificationBorderStyle(classification: ReasoningEdgeClassification): "dashed" | "solid" {
  return classification === "weak_fit" || classification === "unverified" ? "dashed" : "solid";
}

/** Whether a reasoning edge represents content a human should consider promoting/reviewing. */
export function classificationNeedsReview(classification: ReasoningEdgeClassification): boolean {
  return classification !== "official_explicit" && classification !== "official_incomplete";
}

export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown";

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
};

export function riskLevelClass(level: RiskLevel): string {
  switch (level) {
    case "critical":
    case "high":
      return "text-gap border-gap bg-red-50";
    case "medium":
      return "text-inferred border-inferred bg-amber-50";
    case "low":
      return "text-ok border-ok bg-green-50";
    default:
      return "text-template border-template bg-slate-100";
  }
}

/** Derive a coarse risk level from a CVSS base score (0-10) plus optional KEV listing. */
export function riskLevelFromScore(baseScore: number | null | undefined, kevListed: boolean): RiskLevel {
  if (kevListed) return "critical";
  if (baseScore === null || baseScore === undefined || Number.isNaN(baseScore)) return "unknown";
  if (baseScore >= 9) return "critical";
  if (baseScore >= 7) return "high";
  if (baseScore >= 4) return "medium";
  return "low";
}

export const SOURCE_MODE_LABELS: Record<SourceMode, string> = {
  live: "Live",
  cached: "Cached",
  offline: "Offline",
};

/** Tailwind classes for the live/cached/offline source-mode badge. */
export function sourceModeClass(mode: string): string {
  switch (mode) {
    case "live":
      return "text-ok border-ok bg-green-50";
    case "cached":
      return "text-inferred border-inferred bg-amber-50";
    case "offline":
      return "text-template border-template bg-slate-100";
    default:
      return "text-template border-template bg-slate-100";
  }
}
