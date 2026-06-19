# CVEzD3FEND

**Multi-CVE contextual defensive intelligence navigator.** CVEzD3FEND combines
Galeax/CVE2CAPEC breadth with deterministic contextual route selection, an
optional AI-assisted cherry-picker, and a reduced evidence-backed graph over the
semantic chain

```
CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND -> ATLAS -> Controls -> Detections
     -> Evidence -> Gaps -> SOC/CTEM Actions
```

into navigable, provenance-backed routes for SOC analysts, threat hunters,
detection engineers, CTEM leads, and executives. The static bundle remains the
canonical graph; the optional FastAPI sidecar performs request-scoped exact
Galeax lookups for arbitrary CVE years and serves the contextual multi-CVE
workbench.

## Principles

1. **Static-first** — `CVEzD3FEND build` produces `data/dist/knowledge-bundle.json`;
   the web UI, CLI, and optional API/MCP servers all read that one file.
2. **Determinism first, AI second** — the graph validates, AI proposes, a
   human promotes. Every AI-proposed node/edge is `canonical=false,
   inferred=true` until a reviewer runs `ai promote-candidate`.
3. **Provenance everywhere** — every node and edge traces back to an entry in
   `bundle.sources[]` with confidence, fetch time, and (when applicable) a
   sha256.
4. **The UI never floods** — bounded initial render (40-node cap), progressive
   expansion, canonical vs. inferred always visually distinct.
5. **Local, portable, auditable** — clone, build, open. No accounts, no
   telemetry, no cloud dependency.

See `docs/PRODUCT_VISION.md` for the full rationale and `contracts/` for the
nine formal contracts (bundle shape, graph model, mappings, AI governance,
provenance, validation, export, UI constraints, MCP surface) that this
implementation conforms to.

## Quick start

```bash
make install        # python venv (.venv) + pip install -e .[dev]
make build           # fetch sources, write data/dist/knowledge-bundle.json + quality-report.json
make validate        # structural + quality validation, exits non-zero on fatal errors
make test            # pytest (unit + integration)
make web-install     # npm install for web/
make web-build       # copy the bundle into web/public/data/, build the static SPA
make serve           # serve the built SPA + bundle locally
```

Then open http://127.0.0.1:8787.

## Multi-CVE contextual analysis

The primary product experience is the **Multi-CVE Contextual Analysis
Workbench** at `/#/analyze`:

1. Paste one or many CVE identifiers using lines, commas, or spreadsheet
   whitespace. Invalid and missing identifiers are reported without cancelling
   valid CVEs.
2. Declare technologies, exposure, operational priorities, audience, and a
   Top-K of 5, 10, or 20 routes.
3. Receive **Selected** by default: deterministic scoring, explicit coverage
   policy, ranked routes, an aggregated `selected_graph`, convergences,
   provenance, gaps, and backend-authored executive/operational/technical
   narrative.
4. Request **All candidates** explicitly when complete evidence exploration is
   needed. The browser consumes `candidate_graph` exactly as delivered; it never
   creates edges or resolves mappings.
5. Optionally enable AI-assisted reranking. AI can reorder only validated
   deterministic-shortlist route IDs. It cannot create nodes, mappings, or
   edges, and deterministic fallback remains available.

> Galeax shows everything related. CVEzD3FEND shows what matters most, explains
> why, and preserves access to the complete evidence.

### API example

```bash
curl -sS http://127.0.0.1:8000/api/reason/batch \
  -H 'Content-Type: application/json' \
  -d '{
    "cve_ids": ["CVE-2025-0168", "CVE-2026-0544", "CVE-2025-99999999", "invalid"],
    "context": {
      "technologies": ["Windows", "Active Directory"],
      "exposure": ["internet-facing", "production"],
      "priorities": ["initial access", "credential theft"],
      "audience": "SOC"
    },
    "top_k": 5,
    "include_all_candidates": false,
    "use_ai": false
  }'
```

Set `include_all_candidates` to `true` only for the on-demand All view. The
initial response intentionally omits `candidate_graph`; omission means “not
included,” not “no candidates.”

## CLI

```bash
CVEzD3FEND build                                  # full ETL + bundle + quality report
CVEzD3FEND validate                               # structural + quality validation
CVEzD3FEND serve                                  # serve web/dist + bundle statically
CVEzD3FEND serve --port 8788                      # choose a different static port
CVEzD3FEND search T1059                           # search nodes by id/alias/text
CVEzD3FEND route CVE-2026-0544                    # render the top route to the console
CVEzD3FEND export route CVE-2026-0544 --format md
CVEzD3FEND export coverage --format csv
CVEzD3FEND export soc-action-pack CVE-2026-0544 --format md
CVEzD3FEND ai generate-candidates --limit 10      # offline analogy-based candidates (mock provider)
CVEzD3FEND ai validate-candidates
CVEzD3FEND ai promote-candidate <candidate_id> --reviewer "<name>"
CVEzD3FEND api                                    # optional FastAPI sidecar (pip install .[api])
CVEzD3FEND mcp                                    # optional MCP stdio server (pip install .[mcp])
```

Full reference: `docs/OPERATIONS.md`.

## Repository layout

```
src/CVEzD3FEND/
  config.py            settings (env-driven, CVEZD3FEND_ prefix)
  models/              pydantic models: graph, bundle, soc action pack, AI candidates
  etl/                 bounded HTTP fetch + source normalization
  graph/               graph builder, derived catalogs, indexes
  routing/             CVE-anchored and framework routes
  coverage/            coverage model + gap/CTEM action generation
  validation/          structural validation + quality report
  export/              markdown, mermaid, json, csv (stix reserved)
  actions/             SOC Action Pack generator
  intelligence/        AI providers, RAG, candidate state machine
  pipeline.py          single build entry point
  cli.py               Typer CLI
  api/                 optional FastAPI sidecar
  mcp/                 optional MCP stdio server
web/                   Vite + React + TypeScript + Tailwind SPA
contracts/             9 formal contracts
docs/                  architecture, operations, AI governance, data sources, UI guide
data/                  raw/cache/dist/review (generated, gitignored except .gitkeep)
```

## AI assistance

AI is **offline by default** (`CVEZD3FEND_AI_ENABLED=false`, `mock` provider).
The multi-CVE workbench functions deterministically without AI. When enabled,
AI-assisted batch reranking is limited to the validated deterministic shortlist
and declares deterministic fallback. Existing AI candidate governance remains
unchanged. Enabling AI also affects:

- Optional narrative expansion of always-available, template-backed "context"
  outputs (`explain_route`, detection briefs, hunt hypotheses) — these never
  block and never fail, falling back to the deterministic template.
- The AI candidate queue (`ai generate-candidates` /
  `validate-candidates` / `promote-candidate` / `reject-candidate`), which
  proposes low-confidence ATT&CK→D3FEND mappings by analogy and writes them to
  `data/review/ai-candidates.jsonl`. Nothing reaches the canonical bundle
  without an explicit human promotion, which appends to
  `data/dist/promoted-edges.json` (an overlay, never merged into
  `bundle.edges`).

See `docs/AI_GOVERNANCE.md` and `contracts/AI_ASSISTANCE_CONTRACT.md`.

## License

Apache-2.0. See `docs/ATTRIBUTION.md` for upstream data source licenses
(CVE2CAPEC, MITRE ATT&CK/CAPEC/CWE/D3FEND/ATLAS, CISA KEV).
