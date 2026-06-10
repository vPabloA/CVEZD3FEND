# VALIDATION_CONTRACT

Defines what `CVEzD3FEND validate` (and CI) must check, and the shape of
`data/dist/quality-report.json`.

## 1. Structural checks (fatal — exit code 1)

- [ ] `knowledge-bundle.json` matches the JSON Schema in
      `src/CVEzD3FEND/validation/schema.py` (bundle/node/edge/route shapes per
      BUNDLE_CONTRACT and GRAPH_CONTRACT).
- [ ] All node `id`s are unique.
- [ ] All edge `id`s are unique.
- [ ] Every edge `source` and `target` resolves to an existing node `id`.
- [ ] Every node `type` is in the closed set (GRAPH_CONTRACT §1).
- [ ] Every edge `type` is in the closed set (GRAPH_CONTRACT §3).
- [ ] No edge has `source_ref == null`.
- [ ] Every `source_ref` resolves to an entry in `bundle.sources[]`.
- [ ] No node has an empty `source_refs[]`.
- [ ] Every `route.nodes[]` / `route.edges[]` entry resolves to an existing
      node/edge id.
- [ ] No duplicate edges (same `(source, target, type)` appears once).
- [ ] No edge has `deterministic=true AND inferred=true`.

## 2. Quality checks (non-fatal — reported as warnings)

- [ ] Orphan nodes (no incoming or outgoing edges) — reported per type.
- [ ] CVEs without `cve_has_cwe` -> flagged as `gap(cve_without_cwe)`.
- [ ] CWEs without `cwe_maps_to_capec` -> `gap(cwe_without_capec)`.
- [ ] CAPECs without `capec_maps_to_attack` -> `gap(capec_without_attack)`.
- [ ] ATT&CK techniques without `attack_maps_to_defend` -> `gap(attack_without_defend)`.
- [ ] ATT&CK techniques without a Detect-tactic D3FEND -> `gap(attack_without_detection)`.
- [ ] Low-confidence edges (`confidence < 0.5`) counted per type.
- [ ] Sources with `status in {fallback, unavailable, error}`.

## 3. AI candidate checks

- [ ] Every line in `data/review/ai-candidates.jsonl` matches the
      AI_ASSISTANCE_CONTRACT shape.
- [ ] No candidate with `final_status == "canonical"` is missing
      `reviewer`.
- [ ] No proposed node/edge in a candidate uses an `id` colliding with an
      existing canonical node/edge unless it is an explicit overlay edge
      (`metadata.promoted_from_candidate` set).
- [ ] `data/dist/promoted-edges.json` (if present) contains only edges with
      `inferred=true` and a non-null `metadata.promoted_from_candidate.reviewer`.

## 4. UI budget checks (static analysis, run by `tests/e2e`)

- [ ] No component passes the full `bundle.nodes`/`bundle.edges` array
      directly into the graph renderer without going through
      `lib/graphWindow.ts` (which enforces the 40-node cap).
- [ ] Every page component under `web/src/pages/` renders one of
      `LoadingState`, `EmptyState`, or `ErrorState` for its async data.

## 5. `quality-report.json` shape

```json
{
  "generated_at": "ISO-8601",
  "bundle_version": "string",
  "node_counts": { "<type>": 0 },
  "edge_counts": { "<type>": 0 },
  "routes": { "total": 0, "canonical": 0, "inferred": 0, "framework_total": 0, "framework_emitted": 0 },
  "gaps": { "total": 0, "by_reason": { "<reason>": 0 }, "emitted": { "<reason>": 0 } },
  "warnings": [ { "code": "string", "message": "string" } ],
  "sources": { "ok": 0, "fallback": 0, "unavailable": 0, "error": 0, "details": [] },
  "edges_without_provenance": 0,
  "low_confidence_edges": { "<type>": 0 },
  "orphan_nodes": { "total": 0, "by_type": { "<type>": 0 } },
  "coverage_summary": { "covered": 0, "partial": 0, "gap": 0, "unknown": 0, "not_applicable": 0 },
  "ai_candidates": { "total": 0, "by_status": { "<status>": 0 } },
  "fatal_errors": []
}
```

`validate` exits non-zero iff `fatal_errors` is non-empty.
