import type { BatchReasoningResult, GraphSlice, RankedRoute } from "@/lib/reasoningTypes";
import type { BundleEdge, BundleNode, NodeType } from "@/lib/types";

function node(id: string, type: NodeType, title = id): BundleNode {
  return {
    id,
    type,
    name: title,
    title,
    description: `${title} catalog node`,
    aliases: [],
    external_refs: [`https://example.test/${encodeURIComponent(id)}`],
    source_refs: ["catalog:test"],
    tags: [type],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    confidence: 0.9,
    canonical: true,
    inferred: false,
    metadata: {},
  };
}

function edge(id: string, source: string, target: string, type: string): BundleEdge {
  return {
    id,
    source,
    target,
    type,
    label: type.replace(/_/g, " "),
    confidence: 0.9,
    deterministic: true,
    inferred: false,
    resolution_state: "resolved",
    lifecycle_state: "active",
    scope_state: "global",
    assertion_type: "catalog_mapping",
    confidence_basis: "official_mapping",
    source_ref: "catalog:test",
    source_url: `https://example.test/evidence/${encodeURIComponent(id)}`,
    evidence: [`Catalog assertion ${source} to ${target}`],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    metadata: {},
  };
}

const selectedNodes = [
  node("CVE-2025-0168", "cve"),
  node("CVE-2026-0544", "cve"),
  node("CWE-74", "cwe"),
  node("CAPEC-13", "capec"),
  node("T1574.007", "attack"),
  node("D3-LFP", "defend"),
];
const selectedEdges = [
  edge("E-CVE1-CWE", "CVE-2025-0168", "CWE-74", "has_weakness"),
  edge("E-CVE2-CWE", "CVE-2026-0544", "CWE-74", "has_weakness"),
  edge("E-CWE-CAPEC", "CWE-74", "CAPEC-13", "exploited_by"),
  edge("E-CAPEC-ATTACK", "CAPEC-13", "T1574.007", "maps_to_attack"),
  edge("E-ATTACK-DEFEND", "T1574.007", "D3-LFP", "countered_by"),
];

const route1: RankedRoute = {
  route_id: "ROUTE-CVE1-LFP",
  cve_id: "CVE-2025-0168",
  cve_ids: ["CVE-2025-0168", "CVE-2026-0544"],
  node_ids: ["CVE-2025-0168", "CWE-74", "CAPEC-13", "T1574.007", "D3-LFP"],
  edge_ids: ["E-CVE1-CWE", "E-CWE-CAPEC", "E-CAPEC-ATTACK", "E-ATTACK-DEFEND"],
  attack_ids: ["T1574.007"],
  defend_ids: ["D3-LFP"],
  confidence: 0.9,
  completeness: 1,
  score: 0.686667,
  selection_reasons: ["Complete catalog-backed route", "ATT&CK convergence shared by 2 CVEs"],
  provenance: ["cve2capec:cve_2025", "cve2capec:cwe_db", "cve2capec:capec_db", "cve2capec:defend_db"],
  shared_cve_count: 2,
  defensive_reuse_count: 2,
  corroborated_nodes: ["CVE-2025-0168", "CWE-74", "CAPEC-13", "T1574.007"],
  gaps: [],
  selection_rank: 2,
  selection_basis: "coverage_floor",
};

const route2: RankedRoute = {
  ...route1,
  route_id: "ROUTE-CVE2-LFP",
  cve_id: "CVE-2026-0544",
  node_ids: ["CVE-2026-0544", "CWE-74", "CAPEC-13", "T1574.007", "D3-LFP"],
  edge_ids: ["E-CVE2-CWE", "E-CWE-CAPEC", "E-CAPEC-ATTACK", "E-ATTACK-DEFEND"],
  score: 0.716667,
  selection_reasons: ["Matches request context: windows", "D3FEND defense reusable across 2 CVEs"],
  provenance: ["cve2capec:cve_2026", "cve2capec:cwe_db", "cve2capec:capec_db", "cve2capec:defend_db"],
  selection_rank: 1,
};

const candidateNodes = [
  ...selectedNodes,
  node("CAPEC-267", "capec"),
  node("T1027", "attack"),
  node("D3-FA", "defend"),
];
const candidateEdges = [
  ...selectedEdges,
  edge("E-CWE-CAPEC267", "CWE-74", "CAPEC-267", "exploited_by"),
  edge("E-CAPEC267-T1027", "CAPEC-267", "T1027", "maps_to_attack"),
  edge("E-T1027-D3FA", "T1027", "D3-FA", "countered_by"),
];
const route3: RankedRoute = {
  ...route2,
  route_id: "ROUTE-CVE2-FA",
  node_ids: ["CVE-2026-0544", "CWE-74", "CAPEC-267", "T1027", "D3-FA"],
  edge_ids: ["E-CVE2-CWE", "E-CWE-CAPEC267", "E-CAPEC267-T1027", "E-T1027-D3FA"],
  attack_ids: ["T1027"],
  defend_ids: ["D3-FA"],
  score: 0.65,
  selection_rank: null,
  selection_basis: null,
  shared_cve_count: 1,
  defensive_reuse_count: 1,
};

export const selectedGraph: GraphSlice = { nodes: selectedNodes, edges: selectedEdges };
export const candidateGraph: GraphSlice = { nodes: candidateNodes, edges: candidateEdges };

export function makeBatchReasoningResult(
  overrides: Partial<BatchReasoningResult> = {},
  includeAll = false
): BatchReasoningResult {
  return {
    status: "partial",
    requested_cves: ["CVE-2025-0168", "CVE-2026-0544", "CVE-2025-99999999"],
    found_cves: ["CVE-2025-0168", "CVE-2026-0544"],
    missing_cves: ["CVE-2025-99999999"],
    invalid_inputs: ["INVALID"],
    available_route_count: 3,
    selected_route_count: 2,
    candidate_routes: includeAll ? [route1, route2, route3] : [],
    selected_routes: [route1, route2],
    selected_graph: selectedGraph,
    ...(includeAll ? { candidate_graph: candidateGraph } : {}),
    shared_attack_techniques_selected: ["T1574.007"],
    shared_attack_techniques_all_candidates: ["T1027", "T1574.007"],
    shared_defenses_selected: ["D3-LFP"],
    shared_defenses_all_candidates: ["D3-FA", "D3-LFP"],
    selection_summary: {
      eligible_cves: 2,
      represented_cves: ["CVE-2025-0168", "CVE-2026-0544"],
      unrepresented_cves: [],
      representation_policy: "coverage_floor_then_contextual_utility",
      selection_mode: "deterministic",
      fallback_used: false,
    },
    narrative: {
      executive_summary_es: "Se analizaron dos CVE y se priorizaron dos rutas.",
      operational_summary_es: "Validar T1574.007 y reutilizar D3-LFP.",
      technical_summary_es: "Universo=3; seleccionadas=2; modo=deterministic.",
    },
    provenance: {
      "cve2capec:cve_2025": { url: "https://example.test/cve-2025", sha256: "abc" },
      "cve2capec:cve_2026": { url: "https://example.test/cve-2026", sha256: "def" },
      selected_route_sources: {
        "ROUTE-CVE1-LFP": route1.provenance,
        "ROUTE-CVE2-LFP": route2.provenance,
      },
    },
    warnings: ["One CVE was not found."],
    errors: [],
    ...overrides,
  };
}
