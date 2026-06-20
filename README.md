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
   `bundle.sources[]` with confidence, fetch time, and, when applicable, a
   sha256.
4. **The UI never floods** — bounded initial render, progressive expansion,
   and an explicit distinction between selected and complete candidate views.
5. **Local, portable, auditable** — clone, build, run. No account or telemetry
   is required for deterministic analysis.

See `docs/PRODUCT_VISION.md` for the full rationale and `contracts/` for the
nine formal contracts covering bundle shape, graph model, mappings, AI
governance, provenance, validation, export, UI constraints, and MCP surface.

## Requirements

- Git
- Python 3.10 or newer
- Node.js 20 or newer
- npm
- GNU Make
- Internet access during the initial build to retrieve upstream Galeax and
  framework source files

Check the local toolchain:

```bash
git --version
python3 --version
node --version
npm --version
make --version
```

## Clone the current release

```bash
git clone https://github.com/vPabloA/CVEZD3FEND.git
cd CVEZD3FEND

git switch main
git pull --ff-only
git rev-parse HEAD
```

If the repository already exists locally:

```bash
cd CVEZD3FEND
git status --short
git switch main
git pull --ff-only
```

Protect uncommitted work before switching branches:

```bash
git stash push -u -m "wip before updating CVEzD3FEND"
```

## First-time installation and validation

Run these commands from the repository root:

```bash
make install        # create .venv and install Python + dev/API dependencies
make build          # fetch sources and build data/dist/knowledge-bundle.json
make validate       # validate bundle structure and quality
make test           # run backend unit and integration tests
make web-build      # install frontend dependencies, copy the bundle, build the SPA
```

Generated product data is written to:

```text
data/dist/knowledge-bundle.json
data/dist/quality-report.json
```

The web build copies the current bundle into `web/public/data/` before building
`web/dist/`.

## Run the complete product locally

The complete workbench requires two processes: the FastAPI sidecar and the web
application.

### Terminal 1 — API

```bash
cd CVEZD3FEND
.venv/bin/CVEzD3FEND api
```

The API listens by default on:

```text
http://127.0.0.1:8000
```

Verify health:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

Open the interactive API documentation at:

```text
http://127.0.0.1:8000/docs
```

### Terminal 2 — built UI

```bash
cd CVEZD3FEND
make serve
```

Open the Multi-CVE Contextual Analysis Workbench:

```text
http://127.0.0.1:8787/#/analyze
```

`make serve` serves the already-built SPA and bundle. Run `make web-build`
again after frontend changes or after rebuilding the knowledge bundle.

## Frontend development mode

Keep the API running in Terminal 1, then start Vite in another terminal:

```bash
cd CVEZD3FEND/web
npm run dev
```

Open:

```text
http://127.0.0.1:5173/#/analyze
```

The Vite development server provides hot reload. The browser continues to use
the API at `http://127.0.0.1:8000` unless frontend configuration overrides it.

## Daily start after installation

Once dependencies and bundles already exist, the normal startup is:

**Terminal 1**

```bash
cd CVEZD3FEND
.venv/bin/CVEzD3FEND api
```

**Terminal 2**

```bash
cd CVEZD3FEND
make serve
```

Then open:

```text
http://127.0.0.1:8787/#/analyze
```

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
   provenance, gaps, and backend-authored executive, operational, and technical
   narrative.
4. Request **All candidates** explicitly when complete evidence exploration is
   needed. The browser consumes `candidate_graph` exactly as delivered; it never
   creates edges or resolves mappings.
5. Optionally enable AI-assisted reranking. AI can reorder only validated
   deterministic-shortlist route IDs. It cannot create nodes, mappings, or
   edges, and deterministic fallback remains available.

> Galeax shows everything related. CVEzD3FEND shows what matters most, explains
> why, and preserves access to the complete evidence.

### Suggested UI test

Paste:

```text
CVE-2025-0168
CVE-2026-0544
CVE-2025-99999999
invalid
```

Use this context:

```text
Technologies: Windows, Active Directory
Exposure: internet-facing, production
Priorities: initial access, credential theft
Audience: SOC
Top-K: 5
AI-assisted reranking: Off
```

The result should distinguish found, missing, and invalid inputs; present
multiple ranked routes; load **Selected** first; expose **All candidates** only
on demand; and preserve evidence, provenance, gaps, narrative, and graph
relationships delivered by the backend.

Exact counts can change when upstream source data changes. Contract invariants
must remain stable.

### Batch API example

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
  }' | jq
```

Set `include_all_candidates` to `true` only for the on-demand All view. The
initial response intentionally omits `candidate_graph`; omission means “not
included,” not “no candidates.”

## Validation commands

Run the complete local validation before opening a pull request:

```bash
python3 -m compileall src tests
.venv/bin/pytest -q

cd web
npm run lint
npm run test
npm run build
cd ..

git diff --check
```

## CLI

```bash
.venv/bin/CVEzD3FEND build
.venv/bin/CVEzD3FEND validate
.venv/bin/CVEzD3FEND serve
.venv/bin/CVEzD3FEND serve --port 8788
.venv/bin/CVEzD3FEND search T1059
.venv/bin/CVEzD3FEND route CVE-2026-0544
.venv/bin/CVEzD3FEND export route CVE-2026-0544 --format md
.venv/bin/CVEzD3FEND export coverage --format csv
.venv/bin/CVEzD3FEND export soc-action-pack CVE-2026-0544 --format md
.venv/bin/CVEzD3FEND ai generate-candidates --limit 10
.venv/bin/CVEzD3FEND ai validate-candidates
.venv/bin/CVEzD3FEND ai promote-candidate <candidate_id> --reviewer "<name>"
.venv/bin/CVEzD3FEND api
.venv/bin/CVEzD3FEND mcp
```

Full reference: `docs/OPERATIONS.md`.

## Troubleshooting

### `CVEzD3FEND: command not found`

Use the executable inside the project virtual environment:

```bash
.venv/bin/CVEzD3FEND api
```

Alternatively, activate the environment:

```bash
source .venv/bin/activate
```

### The UI cannot reach the API

Check the API first:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

Restart it when necessary:

```bash
.venv/bin/CVEzD3FEND api
```

### The bundle does not exist

```bash
make build
make validate
make web-build
```

### A yearly Galeax CVE source is unavailable

Inspect:

```text
data/dist/quality-report.json
bundle.sources[].status
```

The build can continue using JSONL fallback or report the source as unavailable
without fabricating mappings.

### AI is not configured

No AI configuration is required for normal operation. Deterministic scoring and
selection are authoritative and remain fully operational. AI-assisted reranking
is off by default.

### Start from a clean local build

```bash
make clean
make install
make build
make validate
make test
make web-build
```

## Repository layout

```
src/CVEzD3FEND/
  config.py            settings (env-driven, CVEZD3FEND_ prefix)
  models/              pydantic models: graph, bundle, soc action pack, AI candidates
  etl/                 bounded HTTP fetch + source normalization
  graph/               graph builder, derived catalogs, indexes
  routing/             CVE-anchored and framework routes
  reasoning/           exact lookup, candidate pool, scoring, selection and narrative
  coverage/            coverage model + gap/CTEM action generation
  validation/          structural validation + quality report
  export/              markdown, mermaid, json, csv
  actions/             SOC Action Pack generator
  intelligence/        AI providers, RAG, candidate state machine
  pipeline.py          single build entry point
  cli.py               Typer CLI
  api/                 optional FastAPI sidecar
  mcp/                 optional MCP stdio server
web/                   Vite + React + TypeScript SPA
contracts/             formal contracts
docs/                  architecture, operations, AI governance, data sources, UI guide
data/                  raw/cache/dist/review generated locally
```

## AI assistance

AI is **offline by default** (`CVEZD3FEND_AI_ENABLED=false`, `mock` provider).
The multi-CVE workbench functions deterministically without AI. When enabled,
AI-assisted batch reranking is limited to the validated deterministic shortlist
and declares deterministic fallback. Existing AI candidate governance remains
unchanged.

AI may assist with:

- Optional narrative expansion of always-available, template-backed context
  outputs. These never block and fall back to deterministic templates.
- Reranking existing validated routes.
- The governed candidate queue, where low-confidence ATT&CK→D3FEND proposals
  remain outside the canonical bundle until explicit human promotion.

AI cannot create canonical CVE, CWE, CAPEC, ATT&CK, or D3FEND relationships.

See `docs/AI_GOVERNANCE.md` and `contracts/AI_ASSISTANCE_CONTRACT.md`.

## License

Apache-2.0. See `docs/ATTRIBUTION.md` for upstream data source licenses
(CVE2CAPEC, MITRE ATT&CK/CAPEC/CWE/D3FEND/ATLAS, CISA KEV).
