# MCP_CONTRACT

`src/CVEzD3FEND/mcp/server.py` exposes a read-mostly Model Context Protocol
server over the local knowledge bundle, for use by AI agents (Claude, etc.).

## 1. Principles

- Reads `data/dist/knowledge-bundle.json` (and `data/review/ai-candidates.jsonl`
  for queue-inspection tools) from local disk. No network calls.
- Never mutates `knowledge-bundle.json`.
- Obeys AI_ASSISTANCE_CONTRACT: any tool that "generates" content
  (`generate_hunt_hypothesis`, `generate_detection_brief`, `explain_route`)
  returns `inferred=true` content with citations, and — if it proposes
  nodes/edges — appends to `data/review/ai-candidates.jsonl` rather than the
  bundle.

## 2. Tools

| tool | input | output |
|---|---|---|
| `search_CVEzD3FEND` | `{query: string, types?: string[], limit?: number}` | matching nodes (id, type, name, confidence, canonical) |
| `get_node` | `{id: string}` | full node + incoming/outgoing edges (paginated, default 20) |
| `get_route` | `{id?: string, cve?: string}` | route object (BUNDLE_CONTRACT §3) |
| `get_soc_action_pack` | `{cve_or_technique: string, asset?: string}` | SOC Action Pack object |
| `get_defensive_coverage` | `{technique?: string}` | coverage entries (one technique or full summary) |
| `list_gaps` | `{technique?: string, reason?: string, limit?: number}` | gap nodes |
| `explain_route` | `{route_id: string}` | `{text, citations[]}` (inferred=true, RAG-grounded) |
| `generate_hunt_hypothesis` | `{technique: string}` | `{hypothesis, queries[], citations[]}` (also appended to ai-candidates.jsonl as `note`/`threat_hunt` candidates) |
| `generate_detection_brief` | `{technique: string}` | `{brief, citations[]}` |
| `export_route_markdown` | `{route_id: string}` | markdown string (EXPORT_CONTRACT §1) |

## 3. Error handling

- Unknown id -> `{error: "not_found", id: "..."}`, never an exception leak.
- Bundle missing/unreadable -> server starts but every tool returns
  `{error: "bundle_unavailable", hint: "run `CVEzD3FEND build`"}`.

## 4. Transport

Implemented with the official `mcp` Python SDK using stdio transport
(`CVEzD3FEND mcp` launches it). Configuration (bundle path, AI flags) via the
same `.env`/config as the rest of the CLI (`src/CVEzD3FEND/config.py`).
