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

- `/` — Home / Search (`pages/HomePage.tsx`)
- `/route/:routeId` — Route Navigator (`pages/RoutePage.tsx`)
- `/node/:nodeId` — Node Detail (`pages/NodeDetailPage.tsx`)
- `/coverage` — Defensive Coverage (`pages/CoveragePage.tsx`)
- `/soc-action-pack/:id` — SOC Action Pack (`pages/SocActionPackPage.tsx`)
- `/ai-review` — AI Review Queue (`pages/AiReviewPage.tsx`)
- `/analyze` — Reasoning Workbench (`pages/AnalyzePage.tsx`) — see
  [Reasoning Workbench](#reasoning-workbench) below.

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

`/analyze` (`pages/AnalyzePage.tsx`) is the "Threat-Defense Reasoning
Workbench": it runs the live enrichment + reasoning engine for a single CVE
and surfaces the full reasoning plane — risk, classified route, narrative,
provenance, SOC/Detection/Hunting/CTEM outputs, exports, and AI-assisted
review. It is reachable from the main nav ("Analyze"), from any CVE node's
"Analyze →" link (`NodeCard`, `NodeDetailPage`), and from the Home empty
state.

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
- `ReasoningEdgesList` — bounded (40 + "Show 20 more") list of classified
  edges; optionally renders a "Promote to canonical" action per edge that
  needs review, gated on `apiAvailable && reviewer.trim()`.
- `ProvenancePanel` — groups the reasoning result's `provenance` map by
  source into collapsible sections, each rendered via `ReasoningEdgesList`.
- `RiskSummaryPanel`, `NarrativePanel`, `RouteContractPanel` — risk facts
  (CVSS/EPSS/KEV/exploitability), the engine's Spanish narrative sections, and
  the six route-contract buckets (canonical/primary/secondary/conditional/
  defensive/weak-fit) as links into the knowledge bundle.
- `ActionListPanel` — generic renderer reused for the SOC Action Pack,
  Detection Engineering, and Threat Hunting panels.
- `CtemPanel` — CTEM plan (priority, remediation actions, validation steps,
  residual risk).
- `ExportsPanel` — markdown/tree/mermaid export previews with copy/download.
- `AiReasoningActions` — "Propose route (AI)" / "Validate route" buttons
  (AI_ASSISTANCE_CONTRACT: AI proposes, the engine validates
  deterministically); disabled with an inline "API offline" message when the
  sidecar is unavailable. Results render as visible facts via `KeyFacts`,
  never as hidden reasoning.
- `KeyFacts` — generic, depth-limited renderer for heterogeneous
  `Record<string, unknown>` facts (CVSS/EPSS/KEV shapes, AI responses).
- `GraphNavigatorPlaceholder` — reserved slot for the next iteration's
  "Threat-Defense Knowledge Graph Navigator" (UIX_CONTRACT §10). Not empty:
  explains what's coming and exposes `exports.navigator_layer` for download
  if the engine already produced one.

### Human review & promotion

If `human_review.required` is true, `HumanReviewBanner` surfaces the reason
as a `role="alert"`. Any edge classified as needing review can be promoted to
canonical via `POST /api/review/promote-edge`, but the action stays disabled
— with an inline explanation — until the operator enters their name in the
"Reviewer name" field (persisted to `localStorage` under
`cvezd3fend:reviewer`). This mirrors the AI Review Queue's promote/reject
flow and the AI_ASSISTANCE_CONTRACT.

## Testing

The web app uses Vitest + jsdom + `@testing-library/react`
(`vite.config.ts` `test` block, `src/test/setup.ts`). Run the suite with:

```bash
cd web && npm run test
```

Fixtures for reasoning/bundle data live in `src/test/fixtures/` and are
**test-only** — production components never hardcode CVEs, narratives,
edges, findings, or AI responses (see `src/test/AnalyzePage.test.tsx` and
`src/test/reasoningComponents.test.tsx` for coverage of loading/error/
degraded/success states, the human-review banner, provenance visibility,
SOC/Detection/Hunting/CTEM panels, the AI-disabled state, and the
reviewer-name requirement for promotion).
