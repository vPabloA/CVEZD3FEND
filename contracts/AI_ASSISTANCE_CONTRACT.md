# AI_ASSISTANCE_CONTRACT

> The graph validates. The AI proposes. The human promotes.

## 1. Scope

The AI/Intelligence layer (`src/CVEzD3FEND/intelligence/`) is **optional**,
**offline-by-default**, and **build-time / sidecar only**. It is gated by
`CVEZD3FEND_AI_ENABLED=true` (see `.env.example`). With it disabled (default),
the entire product is fully functional using only the deterministic bundle.

## 2. Hard restrictions

The AI layer MUST NOT:

1. Invent node or edge ids that do not already exist in the canonical bundle
   for the *referencing* side of a candidate (a candidate may *propose* a new
   node, but its id must follow the deterministic id scheme for its type).
2. Write directly to `data/dist/knowledge-bundle.json`.
3. Run inside the browser. The frontend never holds or sends provider API
   keys and never calls an LLM provider directly.
4. Be required for normal operation — `build`, `validate`, `serve`, `route`,
   `search`, `export` all work with AI fully disabled.
5. Hide uncertainty — every AI output carries a `confidence` and a
   `validation_status`.
6. Mix candidate content with canonical content in the same array/list without
   an explicit `canonical`/`inferred` discriminator.

## 3. Output classification (state machine)

Every AI output is one of:

```
context            -- retrieved/explanatory text grounded in bundle citations,
                       not a proposal (e.g. "explain this route")
candidate          -- a proposed node/edge/route, freshly generated
validated_candidate-- passed deterministic validation (schema, id-scheme,
                       no dangling refs, no duplicate of existing edge)
rejected           -- failed validation OR a human reviewer rejected it
canonical          -- promoted into the bundle by a human-run promotion step
```

Transitions:

```
generate -> candidate
candidate --(CVEzD3FEND ai validate-candidates)--> validated_candidate | rejected
validated_candidate --(CVEzD3FEND ai promote-candidate, human-invoked)--> canonical
validated_candidate --(reviewer rejects)--> rejected
```

Only `CVEzD3FEND ai promote-candidate` (a human-invoked CLI command) can move a
record to `canonical`, and doing so:
- Re-runs the full deterministic validator against the bundle-with-candidate.
- Requires `--reviewer <name>` to be supplied (recorded in
  `metadata.promoted_from_candidate.reviewer`).
- Sets the resulting edge's `inferred=false`? **No** — promoted edges keep
  `inferred=true` permanently (their origin is AI), but gain
  `deterministic=true` is **not** set either. Instead they are written to a
  separate `data/dist/promoted-edges.json` overlay that the bundle loader
  merges, rendered by the UI under a distinct "AI-promoted" visual style
  (purple, see UIX_CONTRACT). They are never indistinguishable from
  framework-asserted edges.

## 4. Candidate queue

`data/review/ai-candidates.jsonl`, one JSON object per line:

```json
{
  "candidate_id": "string",
  "created_at": "ISO-8601",
  "provider": "mock|anthropic|openai|gemini|local-openai-compatible",
  "prompt_hash": "sha256 of the rendered prompt",
  "input_refs": ["<node_id|edge_id|route_id>", "..."],
  "proposed_nodes": [ "...GRAPH_CONTRACT node shape, canonical=false, inferred=true" ],
  "proposed_edges": [ "...GRAPH_CONTRACT edge shape, deterministic=false, inferred=true" ],
  "rationale": "string",
  "confidence": 0.0,
  "validation_status": "pending|validated|rejected",
  "policy_decision": "string|null",
  "reviewer": "string|null",
  "final_status": "candidate|validated_candidate|rejected|canonical"
}
```

## 5. Providers

`src/CVEzD3FEND/intelligence/providers/` ships adapters:

- `mock.py` — deterministic, offline, used by default and in tests.
- `anthropic.py`, `openai.py`, `gemini.py`, `local_openai.py` — thin adapters,
  all behind `CVEZD3FEND_AI_PROVIDER` and requiring an API key env var (never
  committed, never embedded in the bundle). Network calls only happen when the
  user explicitly runs `CVEzD3FEND ai generate-candidates`.

## 6. RAG

`src/CVEzD3FEND/intelligence/rag.py` retrieves **only** from:
- `data/dist/knowledge-bundle.json` (nodes, edges, routes, indexes)
- `data/raw/**` (versioned raw sources)
- `contracts/**`, `docs/**`
- `data/dist/quality-report.json`

Every RAG result returns `citations: [{node_id|edge_id|route_id|source_ref, source_url, confidence}]`.
A vector store is optional, feature-flagged
(`CVEZD3FEND_RAG_VECTOR_STORE=true`), and — if enabled — is built from the same
local corpus only (no external embedding APIs unless a provider is configured,
in which case the same offline-by-default rule applies).

## 7. SOC Action Packs and explanations

`generate_hunt_hypothesis`, `generate_detection_brief`,
`explain_route` and the SOC Action Pack "AI narrative" fields are always
generated from the deterministic SOC Action Pack object (section 14 of the
product spec / `src/CVEzD3FEND/actions/soc_action_pack.py`) plus RAG citations.
If AI is disabled, these surfaces fall back to deterministic templated text —
never empty, never blocked.
