import type { KnowledgeBundle } from "@/lib/types";

/** Minimal-but-valid KnowledgeBundle fixture for tests (test-only). */
export function makeBundle(): KnowledgeBundle {
  return {
    bundle_version: "test",
    generated_at: "2026-01-01T00:00:00Z",
    schema_version: "test",
    sources: [],
    nodes: [],
    edges: [],
    indexes: {
      by_id: {},
      by_alias: {},
      by_text: {},
      cve_routes: {},
      cwe_to_capec: {},
      capec_to_attack: {},
      attack_to_defend: {},
      attack_to_atlas: {},
      defend_to_controls: {},
      attack_to_detections: {},
      gaps_by_technique: {},
      coverage_by_technique: {},
      sources_by_node: {},
      sources_by_edge: {},
    },
    routes: [],
    coverage: { techniques: [], summary: { covered: 0, partial: 0, gap: 0, unknown: 0, not_applicable: 0 } },
    quality: {
      generated_at: "2026-01-01T00:00:00Z",
      bundle_version: "test",
      node_counts: {},
      edge_counts: {},
      routes: { total: 0, canonical: 0, inferred: 0, framework_total: 0, framework_emitted: 0 },
      gaps: {},
      warnings: [],
      sources: { ok: 0, fallback: 0, unavailable: 0, error: 0, details: [] },
      edges_without_provenance: 0,
      low_confidence_edges: 0,
      orphan_nodes: { total: 0, by_type: {} },
      coverage_summary: { covered: 0, partial: 0, gap: 0, unknown: 0, not_applicable: 0 },
      ai_candidates: {},
      fatal_errors: [],
    },
    provenance: {},
    warnings: [],
  };
}
