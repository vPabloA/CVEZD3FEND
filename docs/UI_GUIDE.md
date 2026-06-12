# UI Guide

`web/` is a Vite + React + TypeScript SPA. It is built statically
(`make web-build`) and reads `data/knowledge-bundle.json` (copied from
`data/dist/knowledge-bundle.json` at build time) via a same-origin fetch.

## Running locally

```bash
make web-install   # npm install in web/
make build         # generate data/dist/knowledge-bundle.json
make web-build      # copies bundle into web/public/data/ and builds the SPA
make serve          # serve web/dist + bundle on http://localhost:8787
```

For development with hot reload:

```bash
cd web && npm run dev
```

(the dev server proxies `/data/knowledge-bundle.json` to `../data/dist/`).

## Pages

- `/` — Launch surface and bundle search (`pages/HomePage.tsx`)
- `/route/:routeId` — Route Navigator (`pages/RoutePage.tsx`)
- `/node/:nodeId` — Node Detail (`pages/NodeDetailPage.tsx`)
- `/coverage` — Defensive Coverage (`pages/CoveragePage.tsx`)
- `/soc-action-pack/:id` — SOC Action Pack (`pages/SocActionPackPage.tsx`)
- `/ai-review` — AI Review Queue (`pages/AiReviewPage.tsx`)
- `/analyze` — Reasoning Workbench (`pages/AnalyzePage.tsx`) — see
  [Reasoning Workbench](#reasoning-workbench) below.

The primary header now keeps only the product identity and one main action
(`Analizar CVE` or `Inicio`). Secondary surfaces like coverage and AI review
remain reachable, but they are no longer framed as competing top-level modules.

## Key library modules

- `lib/bundle.ts` — loads & caches `knowledge-bundle.json`, exposes typed
  accessors (`getNode`, `getEdgesFor`, `getRoute`, `search`).
- `lib/graphWindow.ts` — enforces the 40-node initial render cap and
  "expand"/"show more" increments (UIX_CONTRACT §1).
- `lib/colors.ts` — canonical/inferred/gap/evidence/offense/defense/template
  color tokens (UIX_CONTRACT §4), plus the reasoning-classification, risk-level
  and source-mode tokens used by the Reasoning Workbench (UIX_CONTRACT §4a).
- `lib/url.ts` — syncs search/filter/route state to the URL query string.
- `lib/reasoningTypes.ts` — TypeScript types mirroring the reasoning engine's
  Python models (`ReasoningResult`, `ReasoningEdge`, `RiskSummary`,
  `ReasoningRouteContract`, `ReasoningNarrative`, SOC/Detection/Hunting/CTEM,
  `ReasoningExports`, `EnrichmentResult`, `HumanReview`, etc).
- `lib/api.ts` — optional FastAPI sidecar client (`CVEzD3FEND api`); every
  call is best-effort and callers must handle rejection (no dead buttons).
  Includes the reasoning-plane endpoints: `getMeta`, `enrichCve`, `reasonCve`,
  `getProvenance`, `getEvidence`, `proposeRoute`, `validateRoute`,
  `promoteEdge`.
- `hooks/useReasoning.ts` — `useApiAvailability()` (health/meta polling with
  honest degraded state) and `useReasoning(cveId, enabled)` (loading/error/
  result for `/api/reason/:cveId`).

## Components

- `SearchBar`, `FilterPanel`, `ResultList` (virtualized)
- `RouteGraph` (bounded graph renderer), `RouteSteps`
- `NodeCard`, `RelationList` (paginated)
- `CoverageTable` (virtualized)
- `SocActionPackView`
- `AiCandidateCard`
- `LoadingState`, `EmptyState`, `ErrorState`
- `components/reasoning/*` — see
  [Reasoning Workbench](#reasoning-workbench) below.

## Conventions

- Every page composes `LoadingState | ErrorState | EmptyState | <content>` —
  never a bare blank/crash.
- Every scrollable list/panel sets `max-h-*` + `overflow-y-auto`.
- Color usage follows `lib/colors.ts` exclusively — no inline hex outside that
  module.

## Reasoning Workbench

`/analyze` (`pages/AnalyzePage.tsx`) is the CVEzD3FEND Single Pane of Glass
for attack surface reasoning and graph navigation. It still runs the live
enrichment + reasoning engine for a single CVE, but the hierarchy is now
operational instead of contract-first:

- Default state: one CVE input, explanatory copy, and optional advanced access.
- Top command bar: CVE input, Analyze/Refresh, reviewer identity, source/state
  indicators.
- Left rail: route entities, node-type counts, evidence classification counts,
  selected-node focus.
- Center: the Threat-Defense Knowledge Graph Navigator, with the
  canonical/partial path, classified edges, selected-node/edge highlighting,
  mitigation emphasis, graph modes, and focused context.
- Right rail: analyst-readable narrative, Tier 1 action, review/uncertainty,
  compact risk signal, and governed AI review controls.
- Bottom drawer: provenance, evidence, reasoning trace, SOC/Detection/Hunting/
  CTEM, exports, and raw details behind intentional disclosure.

The first viewport should answer what CVE is being analyzed, what route is
highlighted, what the reasoning engine concludes, what Tier 1 should do now,
what requires human review, and what evidence supports or weakens the route.
Full reviewer/engineering detail remains available without dominating the
default experience.

### API availability & degraded state

The page depends on the optional API sidecar (`CVEzD3FEND api`,
`src/CVEzD3FEND/api/app.py`). `useApiAvailability()` checks `/api/health` and
`/api/meta`:

- **Unreachable** — shows a degraded banner with the exact CLI command to
  start the sidecar and a "Check again" retry. No reasoning request is
  attempted, and nothing is faked.
- **Reachable but `reasoning_available: false`** — shows a warning banner;
  the page still renders whatever the API can provide, honestly labeled.
- **Available** — normal workbench renders.

### Components (`components/reasoning/`)

- `CveAnalyzeForm` — CVE id input + Analyze submit, synced to `?cve=` in the
  URL (UIX_CONTRACT §5).
- `SourceModeBadge` — shows whether enrichment data is `live`, `cached`, or
  `offline` (`SOURCE_MODE_LABELS`/`sourceModeClass`).
- `HumanReviewBanner` — `role="alert"` banner shown only when
  `human_review.required` is true, with the reason from the engine.
- `EdgeClassificationBadge` — renders one of the 7
  `ReasoningEdgeClassification` levels (UIX_CONTRACT §4a).
- `ReasoningRouteGraph` — central graph surface built from
  `ReasoningResult.route` and `ReasoningResult.edges`; it now delegates to the
  Threat-Defense Knowledge Graph Navigator and preserves the focused
  CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND route or an honest partial route
  when the canonical chain is incomplete.
- `EntityNavigationPanel` — left-side graph navigation and filter context:
  route chips, node-type counts, classification counts, selected-node actions.
- `ThreatDefenseGraphNavigator` — premium semantic graph surface inside
  Analyze. It supports focused route / reasoning neighborhood / mitigation
  path / full traceability / evidence modes, zoom and pan, fit/reset controls,
  compact classification filters, hover tooltips, node and edge selection, a
  right-hand inspector, and official-source navigation when a stable URL can
  be derived safely. Graph-level notices explain empty, edge-less, partial,
  unavailable, or filter-hidden selection states without falling back to a raw
  contract dump.
- `graph/*` — product-owned adapters, URL builders, path highlighting, and
  graph-mode controls for the navigator.
- `AdvancedEvidenceDrawer` — bottom evidence drawer for provenance summary,
  evidence reasoning, trace, SOC/Detection/Hunting/CTEM detail, exports, and
  raw payload. Raw JSON is not mounted until the "Raw details" disclosure is
  opened.
- `ReasoningEdgesList` — bounded (40 + "Show 20 more") list of classified
  edges. It can still render per-edge promotion in isolated reviewer contexts,
  but `/analyze` uses the governed single-promotion control in `AiReasoningActions`
  to avoid repeated action buttons.
- `ProvenancePanel` — groups the reasoning result's `provenance` map by
  source into collapsible sections, each rendered via `ReasoningEdgesList`.
- `RiskSummaryPanel`, `NarrativePanel`, `RouteContractPanel` — risk facts
  (CVSS/EPSS/KEV/exploitability), the engine's Spanish narrative in product
  language ("Narrativa", "Ruta", "Por qué importa", "Confianza y riesgo"),
  and the six route-contract buckets (canonical/primary/secondary/conditional/
  defensive/weak-fit) as links into the knowledge bundle.
- `ActionListPanel` — generic renderer reused for the SOC Action Pack,
  Detection Engineering, and Threat Hunting panels.
- `CtemPanel` — CTEM plan (priority, remediation actions, validation steps,
  residual risk).
- `ExportsPanel` — markdown/tree/mermaid export previews with copy/download.
- `AiReasoningActions` — "Propose route (AI)" / "Validate route" buttons
  (AI_ASSISTANCE_CONTRACT: AI proposes, the engine validates
  deterministically); disabled with an inline "API offline" message when the
  sidecar is unavailable. In the Single Pane of Glass it also owns the one
  governed "Promote selected edge" action, gated on reviewer identity and only
  shown when there is actually a reviewable edge. Results render as visible
  facts via `KeyFacts`, never as hidden reasoning or raw model dumps.
- `KeyFacts` — generic, depth-limited renderer for heterogeneous
  `Record<string, unknown>` facts (CVSS/EPSS/KEV shapes, AI responses).
- `ThreatDefenseGraphNavigator` uses compact canvas labels by default and
  pushes detail into the inspector to keep the first viewport readable.

### Human review & promotion

If `human_review.required` is true, `HumanReviewBanner` surfaces the reason
as a `role="alert"` using the product label "Requiere revisión". Edges
classified as needing review can be promoted to canonical via
`POST /api/review/promote-edge`, but `/analyze` presents this as one governed
review action in the AI Review panel. The action stays disabled until the
operator enters their name in the "Reviewer name" field (persisted to
`localStorage` under `cvezd3fend:reviewer`). This mirrors the AI Review
Queue's promote/reject flow and the AI_ASSISTANCE_CONTRACT while avoiding a
repeated "Promote" button under every edge.

### Graph behavior

- Default graph mode: `Focused Route`.
- The graph exposes hover tooltips, selection focus, fit/reset, and a small
  classification filter set rather than a long control wall.
- Empty/degraded states are graph-level and product-worded: no graphable route,
  no relationships, partial route, graph data unavailable, or selected node/
  edge hidden by active filters.
- `Mitigation Path` mode makes the attack-to-defense route explicit by
  strengthening defensive edges, adding defensive glow, dimming unrelated
  context, and adding inspector language that explains the route from offensive
  reasoning toward D3FEND/defensive action.
- Official-source links open NVD, MITRE CWE, MITRE CAPEC, MITRE ATT&CK or
  MITRE D3FEND when the identifier can be mapped safely. D3FEND links are not
  invented from uncertain abbreviations such as `D3-EFA`; they render only for
  trusted provided URLs, explicit local mappings, or already-resolvable
  `d3f:*` identifiers.
- The graph runtime normalizes `source`/`target` through helper functions
  because `react-force-graph-2d` mutates link endpoints from string ids into
  node objects after simulation starts. Edge selection, inspector focus, path
  highlighting, and mitigation detection must read IDs through those helpers.
- Reduced-motion users still get a readable node/edge canvas because the
  inspector and tooltips carry the semantic detail.

## Testing

The web app uses Vitest + jsdom + `@testing-library/react`
(`vite.config.ts` `test` block, `src/test/setup.ts`). Run the suite with:

```bash
cd web && npm run test
```

Fixtures for reasoning/bundle data live in `src/test/fixtures/` and are
**test-only** — production components never hardcode CVEs, narratives,
edges, findings, graph examples, or AI responses (see
`src/test/AnalyzePage.test.tsx` and `src/test/reasoningComponents.test.tsx`
for coverage of loading/error/degraded/success states, the graph-centered
single pane, evidence drawer, human-review banner, provenance visibility,
SOC/Detection/Hunting/CTEM panels, the AI-disabled state, and the governed
reviewer-name requirement for promotion).
