# BUNDLE_CONTRACT

Defines the structure, versioning and compatibility rules for
`data/dist/knowledge-bundle.json`, the single canonical artifact consumed by
the frontend, CLI, API and MCP server.

## 1. Top-level shape

```json
{
  "bundle_version": "1.0.0",
  "generated_at": "2026-06-09T00:00:00Z",
  "schema_version": "1.0.0",
  "sources": [ { "...": "see PROVENANCE_CONTRACT" } ],
  "nodes": [ { "...": "see GRAPH_CONTRACT" } ],
  "edges": [ { "...": "see GRAPH_CONTRACT" } ],
  "indexes": {
    "by_id": { "<node_id>": <array index into nodes> },
    "by_alias": { "<alias>": ["<node_id>", "..."] },
    "by_text": { "<lowercased token>": ["<node_id>", "..."] },
    "cve_routes": { "<cve_id>": ["<route_id>", "..."] },
    "cwe_to_capec": { "<cwe_id>": ["<capec_id>", "..."] },
    "capec_to_attack": { "<capec_id>": ["<attack_id>", "..."] },
    "attack_to_defend": { "<attack_id>": ["<defend_id>", "..."] },
    "attack_to_atlas": { "<attack_id>": ["<atlas_id>", "..."] },
    "defend_to_controls": { "<defend_id>": ["<control_id>", "..."] },
    "attack_to_detections": { "<attack_id>": ["<detection_id>", "..."] },
    "gaps_by_technique": { "<attack_id>": ["<gap_id>", "..."] },
    "coverage_by_technique": { "<attack_id>": "covered|partial|gap|unknown|not_applicable" },
    "sources_by_node": { "<node_id>": ["<source_id>", "..."] },
    "sources_by_edge": { "<edge_id>": ["<source_id>", "..."] }
  },
  "routes": [ { "...": "see section 3" } ],
  "coverage": { "techniques": [ { "...": "see COVERAGE model in docs/ARCHITECTURE.md" } ], "summary": {} },
  "quality": { "...": "mirrors data/dist/quality-report.json (embedded subset)" },
  "provenance": { "<source_id>": { "...": "see PROVENANCE_CONTRACT" } },
  "warnings": [ { "code": "string", "message": "string", "context": {} } ]
}
```

## 2. Versioning

- `schema_version` follows semver. A breaking change to node/edge/route shape
  bumps the MAJOR version. Additive, optional fields bump MINOR.
- `bundle_version` is the build's own version (independent of schema), bumped
  on every `CVEzD3FEND build` run that changes content.
- Consumers (frontend, CLI, API, MCP) MUST check `schema_version` against the
  range they support and fail loudly (not silently degrade) on a MAJOR mismatch.

## 3. Routes

Each entry of `routes[]`:

```json
{
  "route_id": "string",
  "start_node": "CVE-2026-0544",
  "end_node": "D3-FA",
  "path": ["cve", "cwe", "capec", "attack", "defend"],
  "nodes": ["CVE-2026-0544", "CWE-707", "CAPEC-28", "T1027", "D3-FA"],
  "edges": ["<edge_id>", "..."],
  "confidence": 0.74,
  "canonical": true,
  "inferred": false,
  "coverage_status": "covered",
  "recommended_actions": ["string", "..."],
  "evidence_required": ["<evidence_node_id>", "..."],
  "source_refs": ["<source_id>", "..."]
}
```

- A route is canonical (`canonical=true`) only if every edge along `edges[]` is
  `deterministic=true`.
- `confidence` is the product of the confidences of the edges on the path,
  rounded to 2 decimals.
- `coverage_status` mirrors `coverage.techniques[].coverage_status` for the
  `attack` node on the path (or `unknown` if no `attack` node is present).
- Routes are capped: the build emits at most `top_routes_per_cve` (config,
  default 3) highest-confidence routes per CVE, plus all canonical
  framework-to-framework routes (CWE->D3FEND) used to populate the Coverage view.

## 4. Indexes

All indexes are precomputed at build time so the frontend and CLI never need
to traverse the full edge list for common operations. Indexes are derived
data — they MUST be regenerable purely from `nodes[]` and `edges[]`.

## 5. Quality & Warnings

- `quality` mirrors `data/dist/quality-report.json` (see VALIDATION_CONTRACT).
- `warnings[]` carries non-fatal build issues (e.g. a yearly CVE source that
  fell back from `.jsonl.gz` to `.jsonl`, or an optional source that was
  unavailable). Warnings never block `build`, but `validate` reports them.

## 6. Compatibility rules

- Removing a node/edge type from GRAPH_CONTRACT is a MAJOR change.
- Adding an optional field to a node/edge/route is a MINOR change.
- Renaming any existing field is a MAJOR change.
- The bundle MUST remain a single JSON file (optionally gzip-compressed as
  `knowledge-bundle.json.gz`, see PERFORMANCE notes in ARCHITECTURE.md).
