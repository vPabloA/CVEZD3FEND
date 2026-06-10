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

## Key library modules

- `lib/bundle.ts` — loads & caches `knowledge-bundle.json`, exposes typed
  accessors (`getNode`, `getEdgesFor`, `getRoute`, `search`).
- `lib/graphWindow.ts` — enforces the 40-node initial render cap and
  "expand"/"show more" increments (UIX_CONTRACT §1).
- `lib/colors.ts` — canonical/inferred/gap/evidence/offense/defense/template
  color tokens (UIX_CONTRACT §4).
- `lib/url.ts` — syncs search/filter/route state to the URL query string.

## Components

- `SearchBar`, `FilterPanel`, `ResultList` (virtualized)
- `RouteGraph` (bounded graph renderer), `RouteSteps`
- `NodeCard`, `RelationList` (paginated)
- `CoverageTable` (virtualized)
- `SocActionPackView`
- `AiCandidateCard`
- `LoadingState`, `EmptyState`, `ErrorState`

## Conventions

- Every page composes `LoadingState | ErrorState | EmptyState | <content>` —
  never a bare blank/crash.
- Every scrollable list/panel sets `max-h-*` + `overflow-y-auto`.
- Color usage follows `lib/colors.ts` exclusively — no inline hex outside that
  module.
