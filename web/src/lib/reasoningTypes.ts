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
