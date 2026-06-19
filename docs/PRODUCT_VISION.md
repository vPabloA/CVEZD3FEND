# Product Vision — CVEzD3FEND

## Vision

CVEzD3FEND is a **multi-CVE contextual defensive intelligence navigator** and a
static-first knowledge product. Its primary experience is **Multi-CVE contextual
analysis with deterministic and optional AI-assisted route cherry-picking.** It converts
the semantic chain

```
CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND -> ATLAS -> Controls -> Detections
     -> Evidence -> Gaps -> SOC/CTEM Actions
```

into navigable, verifiable, operable routes for security teams. It positions
itself as **Defensive Intelligence Navigator / SOC Action Graph**: a knowledge
graph that turns "what can attack us" into "how do we validate, detect,
mitigate, evidence and govern it."

## Problem

Security teams routinely face a CVE or an ATT&CK technique and must manually
chase down: which weakness class it belongs to, which attack patterns realize
it, which D3FEND techniques counter it, whether a control/detection exists,
what evidence proves it works, and what's missing. This chase happens across
disconnected sites (NVD, MITRE ATT&CK, CAPEC, CWE, D3FEND, ATLAS), with no
shared provenance, no governance over AI-assisted shortcuts, and usually ends
in either analysis paralysis or an ungoverned spreadsheet.

`CVE2CAPEC` solved the *data production* half (CVE -> CWE/CAPEC/ATT&CK/D3FEND
mapping). `NSFW` solved the *navigation* half (visual, bidirectional,
multi-framework pivoting). Neither solves **governance, provenance,
operability, or AI safety** — the parts that make this usable inside a real
SOC/CTEM program.

## Users

- **SOC Tier 1 analyst** — needs a fast, trustworthy answer: "what does this
  CVE mean for us, right now?"
- **Threat Hunter** — needs hunting hypotheses and queries grounded in
  ATT&CK/D3FEND, with source provenance.
- **Detection Engineer** — needs detection opportunities, required data
  sources, and rule drafts tied to specific techniques.
- **SOC Manager / CTEM lead** — needs coverage views, gaps, and prioritized
  CTEM actions.
- **CISO / Committee** — needs exportable executive summaries with confidence
  and sourcing.

## Differentiators

1. **Static-first**: works fully offline from a single `knowledge-bundle.json`.
2. **Determinism first, AI second**: the graph validates; AI proposes; humans
   promote (AI_ASSISTANCE_CONTRACT).
3. **Provenance on every edge**: source, URL, confidence, deterministic flag,
   evidence.
4. **Operational, not just informational**: SOC Action Packs, coverage model,
   gaps as first-class objects, exporters for SIEM/SOAR/Markdown/Mermaid.
5. **Disciplined UI**: never floods the screen — bounded initial render,
   progressive expansion, canonical vs inferred always visually distinct.
6. **Extensible by contract**: nine formal contracts define the bundle,
   mappings, AI behavior, UI constraints, provenance, validation, graph model,
   export formats, and MCP surface.

## Non-goals (this iteration)

- Not a general-purpose graph database UI.
- Not a vulnerability scanner or asset inventory system (it models *generic*
  asset/product/vendor classes for SOC Action Packs, not a live CMDB).
- Not a chatbot — AI is grounding/assistive, gated, and never the source of
  canonical mappings.
- Not a full STIX/TAXII exchange platform (export hooks reserved, not
  implemented).
- Not a real-time feed — the bundle is rebuilt on demand (`CVEzD3FEND build`),
  not streamed.

## Multi-CVE Contextual Analysis Workbench

The frontend (`web/`) exposes `POST /api/reason/batch` as the primary product
experience at `/analyze`. A user can paste one CVE or a batch copied from a
spreadsheet, ticket, or email; declare technologies, exposure, priorities,
audience, Top-K, and optional AI-assisted reranking; and receive a reduced,
explainable and navigable decision surface.

The mandatory flow is:

```
Multiple CVEs
  -> exact request-scoped Galeax lookup
  -> catalog-demonstrated routes
  -> consolidation and canonical-ID deduplication
  -> user context
  -> deterministic scoring
  -> optional validated AI cherry-picker
  -> multi-route Top-K
  -> aggregated graph
  -> selection explanation
  -> executive, operational and technical narrative
```

**Selected is the default product.** The first request returns ranked
`selected_routes`, a complete server-authored `selected_graph`, selected
ATT&CK/D3FEND convergences, provenance, gaps, warnings, and backend-authored
narrative. **All candidates is opt-in.** It reuses the same request signature
with `include_all_candidates=true`, preserves Selected, consumes the complete
`candidate_graph`, and does not recalculate or infer relations in React.

The workbench reuses the existing **Threat-Defense Knowledge Graph Navigator**
(`components/reasoning/graph/ThreatDefenseGraphNavigator.tsx`) and its trace/force
layouts, inspector, filters, density controls, fullscreen and progressive
disclosure. The batch adapter is a visual projection only: it deduplicates
canonical IDs and associates delivered nodes/edges with CVEs and routes, but it
never creates an edge, resolves a mapping, or mutates provenance.

The ranked-route list exposes `selection_rank`, score, `selection_basis`, CWE,
CAPEC, ATT&CK, D3FEND, convergence/reuse counts, completeness, gaps and
backend-provided selection reasons. The UI presents no hidden chain-of-thought.
Narrative is rendered as safe text and `audience` changes presentation only,
never deterministic scoring. AI can select or reorder only route IDs from the
deterministic shortlist; catalogs remain the sole proof of every edge.

The original single-CVE endpoint remains available for compatibility, but the
primary Analyze experience is multi-CVE. If the API is unavailable, Galeax is
unavailable, a response is partial, All fails, or zero routes exist, the UI
shows an explicit degraded state and preserves any valid Selected result.

## Roadmap (indicative)

- **Now / delivered FastTrack product**: multi-CVE contextual analysis, deterministic and optional AI-assisted route cherry-picking, Selected-by-default and All-on-demand aggregated graphs, ranked explanations, convergences, narrative, provenance and partial-state handling; plus the CVE2CAPEC-derived bundle (techniques_association, CVE year DBs,
  ATLAS, D3FEND, CAPEC, CWE), deterministic graph, routes, coverage, gaps, SOC
  Action Packs, static frontend, CLI, optional API/MCP, governed AI candidate
  queue with mock provider, the Reasoning Workbench (`/analyze`) exposing the
  live enrichment/reasoning/provenance/AI-assist plane as a single pane of
  glass, and the **Threat-Defense Knowledge Graph Navigator** — an interactive
  graph view of a CVE's classified reasoning route (canonical chain,
  primary/secondary/conditional/defensive/weak-fit nodes, provenance per edge,
  mitigation-path highlighting, official-source links) at the heart of that
  workbench.
- **Next**: CISA KEV + NVD 2.0 enrichment (kev/exploit/product/vendor nodes),
  EPSS scoring field, official MITRE ATT&CK/CWE/CAPEC STIX name/description
  enrichment collector (currently IDs-only for CWE; names degrade to
  `CWE-<id>` — see DATA_SOURCES.md).
- **Later**: vector-store-backed RAG, additional LLM provider adapters wired
  to live keys, SIEM/SOAR push connectors, STIX export.
