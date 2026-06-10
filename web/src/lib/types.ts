// Mirrors src/CVEzD3FEND/models/{graph,bundle,soc,ai}.py (BUNDLE_CONTRACT).
// Field names are snake_case to match the JSON exactly — no remapping.

export type NodeType =
  | "cve"
  | "cwe"
  | "capec"
  | "attack"
  | "defend"
  | "atlas"
  | "control"
  | "detection"
  | "evidence"
  | "gap"
  | "asset"
  | "product"
  | "vendor"
  | "kev"
  | "exploit"
  | "mitigation"
  | "playbook"
  | "soc_action"
  | "ctem_action"
  | "threat_hunt"
  | "data_source"
  | "log_source"
  | "rule"
  | "query"
  | "case"
  | "note";

export type EdgeType = string;

export type CoverageStatus = "covered" | "partial" | "gap" | "unknown" | "not_applicable";

export interface BundleNode {
  id: string;
  type: NodeType;
  name: string;
  title: string;
  description: string;
  aliases: string[];
  external_refs: string[];
  source_refs: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
  confidence: number;
  canonical: boolean;
  inferred: boolean;
  metadata: Record<string, unknown>;
}

export interface BundleEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  label: string;
  confidence: number;
  deterministic: boolean;
  inferred: boolean;
  source_ref: string | null;
  source_url: string | null;
  evidence: string[];
  created_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
}

export interface Route {
  route_id: string;
  start_node: string;
  end_node: string;
  path: string[];
  nodes: string[];
  edges: string[];
  confidence: number;
  canonical: boolean;
  inferred: boolean;
  coverage_status: CoverageStatus;
  recommended_actions: string[];
  evidence_required: string[];
  source_refs: string[];
}

export interface CoverageTechnique {
  attack_technique: string;
  defend_techniques: string[];
  controls: string[];
  detections: string[];
  evidence: string[];
  data_sources: string[];
  log_sources: string[];
  coverage_status: CoverageStatus;
  gap_reason: string | null;
  owner: string | null;
  last_validated_at: string | null;
  confidence: number;
}

export interface CoverageSummary {
  covered: number;
  partial: number;
  gap: number;
  unknown: number;
  not_applicable: number;
}

export interface Coverage {
  techniques: CoverageTechnique[];
  summary: CoverageSummary;
}

export interface Source {
  source_id: string;
  name: string;
  kind: string;
  url: string;
  fetched_at: string;
  version: string | null;
  sha256: string | null;
  record_count: number | null;
  status: "ok" | "fallback" | "unavailable" | "error";
  compressed: boolean;
  license: string | null;
  notes: string | null;
  metadata: Record<string, unknown>;
}

export interface QualityWarning {
  code: string;
  message: string;
  context: Record<string, unknown>;
}

export interface QualityReport {
  generated_at: string;
  bundle_version: string;
  node_counts: Record<string, number>;
  edge_counts: Record<string, number>;
  routes: {
    total: number;
    canonical: number;
    inferred: number;
    framework_total: number;
    framework_emitted: number;
  };
  gaps: Record<string, number>;
  warnings: QualityWarning[];
  sources: {
    ok: number;
    fallback: number;
    unavailable: number;
    error: number;
    details: unknown[];
  };
  edges_without_provenance: number;
  low_confidence_edges: number;
  orphan_nodes: { total: number; by_type: Record<string, number> };
  coverage_summary: CoverageSummary;
  ai_candidates: Record<string, number>;
  fatal_errors: string[];
}

export interface BundleIndexes {
  by_id: Record<string, number>;
  by_alias: Record<string, string[]>;
  by_text: Record<string, string[]>;
  cve_routes: Record<string, string[]>;
  cwe_to_capec: Record<string, string[]>;
  capec_to_attack: Record<string, string[]>;
  attack_to_defend: Record<string, string[]>;
  attack_to_atlas: Record<string, string[]>;
  defend_to_controls: Record<string, string[]>;
  attack_to_detections: Record<string, string[]>;
  gaps_by_technique: Record<string, string[]>;
  coverage_by_technique: Record<string, CoverageStatus>;
  sources_by_node: Record<string, string[]>;
  sources_by_edge: Record<string, string[]>;
}

export interface KnowledgeBundle {
  bundle_version: string;
  generated_at: string;
  schema_version: string;
  sources: Source[];
  nodes: BundleNode[];
  edges: BundleEdge[];
  indexes: BundleIndexes;
  routes: Route[];
  coverage: Coverage;
  quality: QualityReport;
  provenance: Record<string, Source>;
  warnings: QualityWarning[];
}

export interface SocActionPack {
  id: string;
  title: string;
  executive_summary: string;
  technical_summary: string;
  attack_path: string[];
  defensive_path: string[];
  recommended_actions: string[];
  hunting_hypotheses: string[];
  detection_opportunities: string[];
  required_logs: string[];
  required_evidence: string[];
  mitigations: string[];
  gaps: string[];
  priority: "Critical" | "High" | "Medium" | "Low" | "Info";
  confidence: number;
  source_refs: string[];
}

export type ValidationStatus = "pending" | "validated" | "rejected";
export type FinalStatus = "candidate" | "validated_candidate" | "rejected" | "canonical";

export interface AICandidate {
  candidate_id: string;
  created_at: string;
  provider: string;
  prompt_hash: string;
  input_refs: string[];
  proposed_nodes: Record<string, unknown>[];
  proposed_edges: Record<string, unknown>[];
  rationale: string;
  confidence: number;
  validation_status: ValidationStatus;
  policy_decision: string | null;
  reviewer: string | null;
  final_status: FinalStatus;
  validation_errors: string[];
}
