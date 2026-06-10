# AI Governance

This document explains, for operators and reviewers, how AI is used in
CVEzD3FEND. The binding rules live in `contracts/AI_ASSISTANCE_CONTRACT.md`;
this is the narrative companion.

## Determinism first

Every canonical fact in `knowledge-bundle.json` — every node, every edge —
traces to a versioned source via `source_ref` (PROVENANCE_CONTRACT). The build
(`CVEzD3FEND build`) runs with **zero** AI involvement by default
(`CVEZD3FEND_AI_ENABLED=false`). You can `build`, `validate`, `route`,
`search`, `serve`, and `export` entirely offline.

## AI as candidate generator

When enabled, the AI layer:

1. **Generates** — `CVEzD3FEND ai generate-candidates` prompts a provider
   (default: `mock`, fully offline and deterministic) to propose additional
   nodes/edges (e.g. a possible CWE for a CVE missing one, or a hunting
   hypothesis). Output is appended to `data/review/ai-candidates.jsonl` with
   `final_status="candidate"`.

2. **Validates** — `CVEzD3FEND ai validate-candidates` runs each pending
   candidate's proposed nodes/edges through the same structural validator used
   for the bundle (id-scheme conformance, no dangling refs, no duplicate of an
   existing edge, schema match). Result: `validated_candidate` or `rejected`,
   recorded in `validation_status`.

3. **Reviews** — a human inspects `validated_candidate` entries, either via the
   AI Review Queue UI (if the optional API is running) or directly in
   `data/review/ai-candidates.jsonl`.

4. **Promotes or rejects** — `CVEzD3FEND ai promote-candidate <id> --reviewer
   <name>` writes the candidate's nodes/edges to
   `data/dist/promoted-edges.json` (an overlay, never the canonical bundle
   file) and sets `final_status="canonical"`, `reviewer=<name>`. Rejection sets
   `final_status="rejected"`.

## What "promoted" means in the UI

Promoted edges/nodes are loaded by the frontend as a **separate overlay** and
rendered with a distinct dashed/amber "AI-promoted" style (UIX_CONTRACT §4).
They are never merged into `bundle.edges`/`bundle.nodes` such that they become
indistinguishable from framework-asserted content. This preserves the
auditability promise: "is this fact MITRE/CVE2CAPEC-asserted or AI-assisted?"
is always answerable at a glance.

## Limits

- AI never runs in the browser and never receives or stores provider API keys
  client-side.
- AI never writes to `knowledge-bundle.json`.
- AI output always carries `confidence` and a `validation_status` —
  uncertainty is never hidden.
- If a provider is unavailable/misconfigured, `generate-candidates` fails
  loudly with a clear error; it never silently falls back to fabricating data
  without marking it as such.

## Providers

`src/CVEzD3FEND/intelligence/providers/` ships five adapters:

- `mock` (default) — deterministic, offline, no API key. Used in tests and
  whenever `CVEZD3FEND_AI_PROVIDER` is unset.
- `anthropic`, `openai`, `gemini`, `local-openai-compatible` — thin `httpx`
  adapters calling each provider's REST API directly (Anthropic Messages,
  OpenAI/local Chat Completions, Gemini `generateContent`). They deliberately
  do **not** depend on the `anthropic`/`openai`/`google-generativeai` SDKs:
  CVEzD3FEND's core dependency set (`pydantic`, `pydantic-settings`, `httpx`,
  `typer`, `rich`, `PyYAML`) already covers everything needed for a single
  JSON request/response, and keeping the AI layer dependency-free means
  `pip install CVEzD3FEND` (no extras) is sufficient to use any provider.

Each adapter raises `ProviderError` if its API key/base URL env var
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`,
`LOCAL_OPENAI_BASE_URL`) is missing, or if the HTTP call fails — per the
"fails loudly" rule above, `ai generate-candidates` does not catch this and
silently fall back to `mock`.

## Traceability

Every candidate records `prompt_hash` (sha256 of the rendered prompt) and
`input_refs` (the bundle node/edge/route ids it was grounded on), so any
promoted fact can be traced back to (a) the exact prompt, (b) the exact bundle
state it was generated against, and (c) the human reviewer who promoted it.
