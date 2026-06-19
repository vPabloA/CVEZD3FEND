import type { BundleEdge, BundleNode } from "./types";

// Mirrors src/CVEzD3FEND/reasoning/models.py — stable contracts for the live
// enrichment + reasoning plane (`/api/enrich`, `/api/reason`, `/api/provenance`,
// `/api/evidence`). Field names are snake_case to match the JSON exactly.
//
// These are distinct from (and finer-grained than) the static bundle's
// canonical/inferred booleans (lib/types.ts, UIX_CONTRACT §4) — they describe
// how a *reasoning edge* was derived, not whether it has been promoted into
// the bundle.

export type ReasoningEdgeClassification =
  | "official_explicit"
  | "official_incomplete"
  | "dataset_derived"
  | "analytical_inferred"
  | "conditional"
  | "weak_fit"
  | "unverified";

export interface HumanReview {
  required: boolean;
  reason: string;
}

export interface RiskSummary {
  cvss: Record<string, unknown> | null;
  epss: Record<string, unknown> | null;
  kev: Record<string, unknown> | null;
  exploitability: Record<string, unknown> | null;
}

export interface ReasoningRouteContract {
  canonical_chain: string[];
  primary_nodes: string[];
  secondary_nodes: string[];
  conditional_nodes: string[];
  defensive_nodes: string[];
  weak_fit_nodes: string[];
}

export interface ReasoningEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  classification: ReasoningEdgeClassification;
  confidence: number;
  evidence: string[];
  source_refs: string[];
  source_url: string | null;
  note: string | null;
  deterministic: boolean;
  inferred: boolean;
  conditional: boolean;
  weak_fit: boolean;
}

export interface ReasoningNarrative {
  summary_es: string;
  executive_summary_es: string;
  decision_context_es: string;
  risk_rationale_es: string;
  tier1_conclusion_es: string;
}

export interface ReasoningSocActionPack {
  validations: string[];
  detections: string[];
  containment: string[];
  owners: string[];
  evidence_expected: string[];
}

export interface DetectionEngineering {
  hypotheses: string[];
  log_sources: string[];
  rule_ideas: string[];
  gaps: string[];
}

export interface ThreatHunting {
  hypotheses: string[];
  queries: string[];
  pivot_points: string[];
}

export interface Ctem {
  priority: string;
  remediation_actions: string[];
  validation_steps: string[];
  residual_risk: string;
}

export interface ReasoningExports {
  markdown: string;
  tree: string;
  mermaid: string;
  navigator_layer: string | null;
}

export interface EnrichmentProfile {
  description: string;
  cwes: string[];
  cvss: Record<string, unknown> | null;
  epss: Record<string, unknown> | null;
  kev: Record<string, unknown> | null;
  affected_products: string[];
  ecosystems: string[];
  semantic_tags: string[];
  source_notes: string[];
}

export type SourceMode = "live" | "cached" | "offline";

export interface EnrichmentResult {
  input: string;
  normalized_input: string;
  status: string;
  source_mode: string;
  baseline_provider: string;
  profile: EnrichmentProfile;
  evidence: Record<string, unknown>[];
  warnings: string[];
  errors: string[];
  provenance: Record<string, Record<string, unknown>[]>;
}

export interface ReasoningResult {
  input: string;
  normalized_input: string;
  status: string;
  source_mode: string;
  baseline_provider: string;
  reasoning_mode: string;
  human_review: HumanReview;
  risk: RiskSummary;
  route: ReasoningRouteContract;
  edges: ReasoningEdge[];
  provenance: Record<string, ReasoningEdge[]>;
  narrative: ReasoningNarrative;
  soc_action_pack: ReasoningSocActionPack;
  detection_engineering: DetectionEngineering;
  threat_hunting: ThreatHunting;
  ctem: Ctem;
  exports: ReasoningExports;
  warnings: string[];
  errors: string[];
}

// ---------------------------------------------------------------------------
// Contextual multi-CVE reasoning (`POST /api/reason/batch`)
// ---------------------------------------------------------------------------

export interface AnalysisContext {
  technologies: string[];
  exposure: string[];
  priorities: string[];
  audience: "SOC" | "Threat Hunting" | "Detection Engineering" | "CTEM" | "Executive";
}

export interface BatchAnalysisRequest {
  cve_ids: string[];
  context: AnalysisContext;
  top_k: number;
  include_all_candidates: boolean;
  use_ai: boolean;
}

export type SelectionBasis = "coverage_floor" | "contextual_utility" | "top_k_constraint" | "ai_rerank";
export type BatchSelectionMode = "deterministic" | "ai_reranked";

export interface RankedRoute {
  route_id: string;
  cve_id: string;
  cve_ids: string[];
  node_ids: string[];
  edge_ids: string[];
  attack_ids: string[];
  defend_ids: string[];
  confidence: number;
  completeness: number;
  score: number;
  selection_reasons: string[];
  provenance: string[];
  shared_cve_count: number;
  defensive_reuse_count: number;
  corroborated_nodes: string[];
  gaps: string[];
  selection_rank: number | null;
  selection_basis: SelectionBasis | null;
}

export interface BatchSelectionSummary {
  eligible_cves: number;
  represented_cves: string[];
  unrepresented_cves: string[];
  representation_policy: string;
  selection_mode: BatchSelectionMode;
  fallback_used: boolean;
}

export interface GraphSlice {
  nodes: BundleNode[];
  edges: BundleEdge[];
}

export interface BatchNarrative {
  executive_summary_es: string;
  operational_summary_es: string;
  technical_summary_es: string;
}

export interface BatchReasoningResult {
  status: string;
  requested_cves: string[];
  found_cves: string[];
  missing_cves: string[];
  invalid_inputs: string[];
  available_route_count: number;
  selected_route_count: number;
  candidate_routes: RankedRoute[];
  selected_routes: RankedRoute[];
  selected_graph: GraphSlice;
  candidate_graph?: GraphSlice;
  shared_attack_techniques_selected: string[];
  shared_attack_techniques_all_candidates: string[];
  shared_defenses_selected: string[];
  shared_defenses_all_candidates: string[];
  selection_summary: BatchSelectionSummary;
  narrative: BatchNarrative;
  provenance: Record<string, unknown>;
  warnings: string[];
  errors: string[];
  /** Temporary backend compatibility aliases. New UI code uses selected_graph. */
  nodes?: BundleNode[];
  edges?: BundleEdge[];
  shared_attack_techniques?: string[];
  shared_defenses?: string[];
}
