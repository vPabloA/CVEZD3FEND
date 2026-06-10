# Product Vision — CVEzD3FEND

## Vision

CVEzD3FEND is a **static-first defensive intelligence navigator**. It converts
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

## Roadmap (indicative)

- **Now**: CVE2CAPEC-derived bundle (techniques_association, CVE year DBs,
  ATLAS, D3FEND, CAPEC, CWE), deterministic graph, routes, coverage, gaps, SOC
  Action Packs, static frontend, CLI, optional API/MCP, governed AI candidate
  queue with mock provider.
- **Next**: CISA KEV + NVD 2.0 enrichment (kev/exploit/product/vendor nodes),
  EPSS scoring field, official MITRE ATT&CK/CWE/CAPEC STIX name/description
  enrichment collector (currently IDs-only for CWE; names degrade to
  `CWE-<id>` — see DATA_SOURCES.md).
- **Later**: vector-store-backed RAG, additional LLM provider adapters wired
  to live keys, SIEM/SOAR push connectors, STIX export.
