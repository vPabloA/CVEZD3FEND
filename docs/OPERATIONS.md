# Operations

## Quick start

```bash
make install        # python venv + pip install -e .[dev]
make build           # fetch sources, build knowledge-bundle.json + quality-report.json
make validate        # validate the bundle, exits non-zero on fatal errors
make test            # run pytest (unit + integration)
make web-install     # npm install for web/
make web-build       # copy bundle into web/, build static SPA
make serve           # serve the static SPA + bundle locally
```

## Configuration

All configuration is via environment variables (see `.env.example`), loaded by
`src/CVEzD3FEND/config.py` (pydantic-settings). Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `CVEZD3FEND_DATA_DIR` | `data` | root for raw/cache/dist/review |
| `CVEZD3FEND_REFERENCE_DATE` | system UTC date | drives CVE year selection |
| `CVEZD3FEND_MAX_CVES_PER_YEAR` | `200` | cap CVE records processed per year (`0` = unlimited) |
| `CVEZD3FEND_TOP_ROUTES_PER_CVE` | `3` | max ranked routes emitted per CVE |
| `CVEZD3FEND_HTTP_TIMEOUT_SECONDS` | `30` | per-request HTTP timeout |
| `CVEZD3FEND_HTTP_MAX_BYTES` | `26214400` (25MB) | max download size per source |
| `CVEZD3FEND_ENABLE_KEV` | `false` | enable optional CISA KEV collector |
| `CVEZD3FEND_ENABLE_EPSS` | `false` | enable optional EPSS scoring field |
| `CVEZD3FEND_AI_ENABLED` | `false` | enable AI candidate generation |
| `CVEZD3FEND_AI_PROVIDER` | `mock` | `mock\|anthropic\|openai\|gemini\|local-openai` |
| `CVEZD3FEND_RAG_VECTOR_STORE` | `false` | enable optional vector store for RAG |
| `CVEZD3FEND_API_HOST` / `_PORT` | `127.0.0.1` / `8000` | optional FastAPI sidecar |
| `CVEZD3FEND_SERVE_HOST` / `_PORT` | `127.0.0.1` / `8787` | static file server bind address (`CVEzD3FEND serve`) |

## CLI reference

```bash
CVEzD3FEND build                       # full ETL + bundle + quality report
CVEzD3FEND validate                    # structural + quality validation
CVEzD3FEND serve                       # serve web/dist + bundle statically
CVEzD3FEND serve --port 8788           # bind the static server to a different port
CVEzD3FEND enrich CVE-2025-0168 --format json
CVEzD3FEND reason CVE-2025-0168 --format tree
CVEzD3FEND explain CVE-2025-0168
CVEzD3FEND hunt CVE-2025-0168
CVEzD3FEND detect CVE-2025-0168
CVEzD3FEND ctem CVE-2025-0168
CVEzD3FEND route CVE-2026-0544         # print a route to console
CVEzD3FEND search T1059                # search nodes
CVEzD3FEND export route CVE-2026-0544 --format md
CVEzD3FEND export coverage --format csv
CVEzD3FEND export soc-action-pack CVE-2026-0544 --format md
CVEzD3FEND ai generate-candidates --target CVE-2026-0544
CVEzD3FEND ai validate-candidates
CVEzD3FEND ai promote-candidate <candidate_id> --reviewer "<name>"
CVEzD3FEND api                         # optional FastAPI sidecar
CVEzD3FEND mcp                         # optional MCP stdio server
```

## Build pipeline stages

1. Fetch sources (`etl/`) -> `data/raw/sources/*` + `.meta.json` (sha256,
   fetched_at, status).
2. Normalize + build graph (`graph/builder.py`) -> in-memory nodes/edges.
3. Build indexes (`graph/index.py`).
4. Build routes (`routing/routes.py`).
5. Build coverage + gaps (`coverage/model.py`).
6. Validate (`validation/`) -> `data/dist/quality-report.json`.
7. Write `data/dist/knowledge-bundle.json`.

`CVEzD3FEND build` always writes the bundle even if `validate`-level *quality*
warnings exist; it exits non-zero only on fatal *structural* errors so CI can
gate on `CVEzD3FEND validate` separately.

## Troubleshooting

- **A yearly CVE source 404s**: check `data/dist/quality-report.json ->
  warnings` and `bundle.sources[].status`. The build continues with
  `status=fallback` (tried `.jsonl`) or `status=unavailable` (neither worked).
- **Bundle too large for the frontend**: lower `CVEZD3FEND_MAX_CVES_PER_YEAR`
  or `CVEZD3FEND_TOP_ROUTES_PER_CVE`.
- **AI commands fail**: confirm `CVEZD3FEND_AI_ENABLED=true` and a valid
  `CVEZD3FEND_AI_PROVIDER` + API key env var; `mock` always works offline.
- **Reasoning commands are degraded**: the new `enrich`/`reason`/`explain`
  flow is designed to keep running with cache or static fallback. Check
  warnings in the JSON output and the API sidecar at `CVEzD3FEND api`.

## Security

- No secrets in the repo; `.env` is gitignored, `.env.example` documents
  required variable *names* only.
- Downloads are size- and time-bounded, sha256-recorded.
- The frontend makes zero third-party network calls at runtime.
