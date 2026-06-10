# Architecture

## Overview

```
                 ┌─────────────────────────────────────────────┐
                 │                  Sources                     │
                 │  CVE2CAPEC (techniques_association, CVE      │
                 │  year DBs, atlas_db, defend_db, capec_db,    │
                 │  cwe_db) + optional CISA KEV / NVD            │
                 └───────────────────┬───────────────────────────┘
                                      │  CVEzD3FEND build
                                      ▼
                 ┌─────────────────────────────────────────────┐
                 │   ETL (src/CVEzD3FEND/etl)                    │
                 │   fetch -> verify (sha256) -> normalize       │
                 └───────────────────┬───────────────────────────┘
                                      ▼
                 ┌─────────────────────────────────────────────┐
                 │   Graph builder (src/CVEzD3FEND/graph)        │
                 │   nodes, edges, dedup, derived catalogs       │
                 │   (control/detection/mitigation/gap/...)      │
                 └───────────────────┬───────────────────────────┘
                                      ▼
        ┌─────────────────────────────┬─────────────────────────────┐
        ▼                              ▼                              ▼
┌───────────────┐          ┌────────────────────┐         ┌──────────────────┐
│ Indexes        │          │ Routing             │         │ Coverage / Gaps   │
│ (graph/index)  │          │ (routing/)          │         │ (coverage/)       │
└───────┬────────┘          └──────────┬──────────┘         └─────────┬────────┘
        └──────────────┬────────────────┴─────────────┬────────────────┘
                        ▼                              ▼
              ┌────────────────────┐        ┌────────────────────────┐
              │ Validation          │        │ data/dist/              │
              │ (validation/)       │◄───────┤ knowledge-bundle.json   │
              │ -> quality-report   │        │ quality-report.json     │
              └────────────────────┘        └───────────┬─────────────┘
                                                          │
        ┌─────────────────┬────────────────┬─────────────┼───────────────┐
        ▼                 ▼                 ▼             ▼               ▼
 ┌────────────┐   ┌──────────────┐  ┌─────────────┐ ┌───────────┐ ┌─────────────┐
 │ web/ (Vite) │   │ CLI           │  │ API (FastAPI│ │ MCP server │ │ Exporters    │
 │ static SPA  │   │ CVEzD3FEND     │  │ optional)   │ │ optional   │ │ md/mermaid/  │
 │ reads bundle│   │                │  │ read-only   │ │ read-only  │ │ json/csv     │
 └────────────┘   └──────────────┘  └─────────────┘ └───────────┘ └─────────────┘
```

## Static-first

The frontend (`web/`) is a Vite/React/TypeScript SPA. At runtime it fetches
`knowledge-bundle.json` (placed at `web/public/data/knowledge-bundle.json` by
`make web-build`/`make build`) via a same-origin static request — **no calls
to GitHub, NVD, MITRE, or any LLM provider from the browser**. The optional API
and MCP server are read-only conveniences for integration, not requirements.

## ETL (`src/CVEzD3FEND/etl/`)

- `http.py` — bounded HTTP fetcher: timeout, max size, sha256, retries, writes
  to `data/raw/sources/<name>` with a `.meta.json` sidecar (PROVENANCE_CONTRACT
  source entry).
- `cve_years.py` — resolves which years to fetch (current + previous, derived
  from the build's reference time), tries `CVE-{year}.jsonl.gz`, falls back to
  `CVE-{year}.jsonl`, streams JSONL (gzip-aware), records per-year metadata.
- `frameworks.py` — fetchers for `techniques_association.json`, `atlas_db.json`,
  `defend_db.jsonl`, `capec_db.json`, `cwe_db.json`.
- `kev.py` — optional CISA KEV collector (tolerant of absence).

## Graph builder (`src/CVEzD3FEND/graph/`)

- `builder.py` — orchestrates node/edge construction per MAPPING_CONTRACT.
- `catalogs/` — canonical reference catalogs (data sources/log sources,
  playbook templates, SOC action templates, evidence-by-artifact templates,
  rule/query templates) used to populate the operational node types
  (`playbook`, `soc_action`, `ctem_action`, `data_source`, `log_source`,
  `rule`, `query`, `evidence`, `control`, `mitigation`).
- `index.py` — builds `bundle.indexes` per BUNDLE_CONTRACT §4.

## Routing (`src/CVEzD3FEND/routing/`)

- `routes.py` — for each `cve` node, walks `cve_has_cwe -> cwe_maps_to_capec ->
  capec_maps_to_attack -> attack_maps_to_defend` and emits up to
  `top_routes_per_cve` ranked Route objects (BUNDLE_CONTRACT §3). Also emits
  framework-to-framework canonical routes (CWE->D3FEND) used by the Coverage
  view.

## Coverage (`src/CVEzD3FEND/coverage/`)

- `model.py` — for every `attack` node, computes `coverage_status` from the
  presence of `defend`/`detection`/`control`/`evidence` neighbors, and emits
  `gap` nodes + `gap_blocks_coverage` edges per MAPPING_CONTRACT.

## Validation (`src/CVEzD3FEND/validation/`)

- `schema.py` — JSON Schema + structural checks (VALIDATION_CONTRACT §1).
- `quality.py` — quality checks + `quality-report.json` (VALIDATION_CONTRACT §2/§5).
- `ai_candidates.py` — checks over `data/review/ai-candidates.jsonl`
  (VALIDATION_CONTRACT §3).

## Actions (`src/CVEzD3FEND/actions/`)

- `soc_action_pack.py` — deterministic SOC Action Pack generator (section 14
  of the product spec).

## Export (`src/CVEzD3FEND/export/`)

- `markdown.py`, `mermaid.py`, `json_export.py`, `csv_export.py`, `stix.py`
  (stub) — see EXPORT_CONTRACT.

## Intelligence (`src/CVEzD3FEND/intelligence/`)

- `providers/` — `mock`, `anthropic`, `openai`, `gemini`, `local_openai`.
- `rag.py` — local retrieval over the bundle/contracts/docs.
- `candidates.py` — candidate generation/validation/promotion
  (AI_ASSISTANCE_CONTRACT).

## CLI (`src/CVEzD3FEND/cli.py`)

Typer-based CLI exposing `build`, `validate`, `serve`, `export`, `route`,
`search`, `ai generate-candidates|validate-candidates|promote-candidate`.

## API (`src/CVEzD3FEND/api/`) — optional

FastAPI app, read-only over the bundle, plus AI candidate endpoints that
write only to `data/review/ai-candidates.jsonl` (never the bundle).

## MCP (`src/CVEzD3FEND/mcp/`) — optional

`mcp` stdio server exposing the tools in MCP_CONTRACT, read-only over the
bundle.

## Performance notes

- CVE year ingestion is streaming (line-by-line, gzip-aware) — memory use is
  O(distinct entities), not O(raw file size).
- The default build caps CVE nodes per year
  (`CVEZD3FEND_MAX_CVES_PER_YEAR`, default 200) to keep
  `knowledge-bundle.json` in the low single-digit MB range, suitable for a
  static fetch. Framework reference data (CWE, CAPEC, ATT&CK, D3FEND, ATLAS) is
  always loaded in full regardless of the CVE cap, since these catalogs are
  bounded (hundreds, not tens of thousands, of entries). Raise or unset the cap
  for a full-scale internal build (see `.env.example`).
- The frontend never iterates the full `nodes`/`edges` arrays for rendering;
  it uses `bundle.indexes` and `lib/graphWindow.ts` (UIX_CONTRACT §1).
