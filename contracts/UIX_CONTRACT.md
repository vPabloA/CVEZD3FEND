# UIX_CONTRACT

Binding constraints for `web/`. A PR that violates any "MUST NOT" below is a
regression, regardless of how the rest of the feature looks.

## 1. Initial render budget

- The graph view MUST NOT render more than **40 nodes** on initial load of any
  route/page.
- Initial content for a route is the route's own `nodes[]`/`edges[]` (typically
  5-8 nodes for a CVE->D3FEND chain) plus, if space allows, sibling
  alternatives up to the 40-node cap.
- Expansion beyond the cap requires an explicit user action: a visible
  **"Expand route"** or **"Show more"** button. Each click reveals one
  additional bounded increment (default 20 nodes), never "all".

## 2. Layout

- Three-pane responsive layout: left sidebar (search/filters, collapsible on
  narrow viewports), center pane (graph/route/list), right pane (node detail,
  collapsible).
- Every pane with potentially long content (search results, relation lists,
  candidate queues) has **internal scroll** (`overflow-y: auto` with a bounded
  `max-height`), never page-level infinite growth.
- Lists longer than ~50 items use windowing/virtualization
  (`web/src/components/VirtualList.tsx`) or pagination (page size 20).

## 3. State handling

- **Loading**: every async data fetch (bundle load, candidate queue) shows a
  skeleton/spinner — never a blank screen.
- **Empty**: every list/search/detail view has a defined empty state with
  guidance (e.g. "No results for '...' — try a CVE id, CWE-XXX, T1059, D3-FA").
- **Error**: bundle-load or fetch errors render a readable error panel with
  the underlying message and a retry action — never a silent failure or raw
  stack trace.

## 4. Visual semantics (canonical vs inferred vs gap)

| concept | color token | usage |
|---|---|---|
| Canonical / framework-asserted edge or node | `--ok` (sober green/blue, `#1f6feb` / `#1a7f37`) | default for `cve, cwe, capec, attack, defend, atlas, control, detection` when `canonical=true` |
| Inferred / AI-origin (validated or promoted) | `--inferred` (amber/orange, `#d97706`) | any node/edge with `inferred=true` |
| Gap | `--gap` (red/amber, `#b91c1c`) | `gap` nodes and `gap_blocks_coverage` edges, and `coverage_status in {gap, partial}` |
| Evidence | `--evidence` (purple, `#7c3aed`) | `evidence` nodes |
| ATT&CK / CAPEC (offensive) | `--offense` (red/orange, `#c2410c`) | `attack`, `capec`, `atlas` nodes |
| D3FEND / control / mitigation (defensive) | `--defense` (green, `#15803d`) | `defend`, `control`, `mitigation` nodes |
| Template / catalog (operational scaffolding) | dashed border + `--template` (gray, `#6b7280`) | `playbook`, `soc_action`, `ctem_action`, `rule`, `query`, `data_source`, `log_source` |

Canonical and inferred content are never visually identical. AI-promoted
overlay edges always render with a dashed stroke + `--inferred` color +
"AI-promoted" badge, regardless of the node types they connect.

### 4a. Reasoning edge classification (Reasoning Workbench extension)

The live reasoning plane (`/api/reason/{cve_id}`) classifies every edge into
one of seven `ReasoningEdgeClassification` levels, finer-grained than the
bundle's canonical/inferred booleans. Each level maps onto an existing color
token plus a distinct icon/label (`lib/colors.ts`:
`REASONING_CLASSIFICATION_LABELS`/`_ICONS`), so color is never the only
signal:

| classification | label | icon | color token |
|---|---|---|---|
| `official_explicit` | Official | ✓ | `--ok` |
| `official_incomplete` | Official (partial) | ✓~ | `--ok` (lighter) |
| `dataset_derived` | Dataset-derived | ◆ | `--link` |
| `analytical_inferred` | Analytical (AI) | ✦ | `--inferred` |
| `conditional` | Conditional | ◐ | `--conditional` (new, `#0e7490`) |
| `weak_fit` | Weak fit | ┄ | `--template` (dashed border) |
| `unverified` | Unverified | ? | `--gap` (dashed border) |

Edges in the last five categories are flagged `classificationNeedsReview`
and may expose a "Promote to canonical" action — gated on a named reviewer
(see §9).

## 5. Filters & state

- Search query, active filters (node type, framework, coverage status,
  canonical/inferred toggle) and the currently focused route id are encoded in
  the URL query string (`?q=...&types=attack,defend&route=...`), so views are
  shareable/bookmarkable and survive a refresh.

## 6. Required views

1. **Home / Search** — search across CVE/CWE/CAPEC/ATT&CK/D3FEND/ATLAS/
   control/detection/gap; recent/example searches when query is empty.
2. **Route Navigator** — CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND, graph + step
   list, confidence per edge, source per edge, recommended actions, gaps,
   coverage badge.
3. **Node Detail** — description, type, aliases, incoming/outgoing relations
   (paginated), source_refs, confidence, canonical/inferred badge, related
   actions, export buttons.
4. **Defensive Coverage** — covered/partial/gap/unknown techniques, filterable
   table (virtualized), drill-down to Route Navigator.
5. **SOC Action Pack** — for a selected CVE/technique: executive summary,
   technical summary, attack/defensive path, recommended actions, hunting
   hypotheses, detection opportunities, required logs/evidence, mitigations,
   gaps, priority, export.
6. **AI Review Queue** — only shown if `CVEZD3FEND_AI_ENABLED=true` (or bundle
   reports candidates present); lists `data/review/ai-candidates.jsonl`
   entries with diff-vs-bundle, promote/reject actions (calls API if running;
   otherwise read-only with CLI instructions).
7. **Reasoning Workbench** (`/analyze`, `pages/AnalyzePage.tsx`) — runs the
   live enrichment + reasoning engine for a CVE: risk summary (CVSS/EPSS/KEV/
   exploitability), Spanish narrative ("Reasoning summary"), classified route
   contract (§4a), bounded reasoning trace and per-source provenance ledger,
   SOC Action Pack / Detection Engineering / Threat Hunting / CTEM panels,
   exports (markdown/tree/mermaid), and AI-assisted propose/validate route
   actions. Requires the optional API sidecar (`CVEzD3FEND api`) — if it is
   unreachable or `/api/meta` reports `reasoning_available: false`, the page
   shows an honest degraded banner with CLI start instructions and a "Check
   again" retry, and never simulates a result (§3, §9).

## 9. AI/reasoning honesty & human review

- AI-derived content (proposed routes, validation results, `analytical_inferred`
  / `conditional` / `weak_fit` / `unverified` edges) is always shown as a
  visible, labeled fact ("AI proposal (not canonical)", "Validation result")
  — never as hidden chain-of-thought or a fabricated "thinking" animation.
- If `human_review.required` is true on a reasoning result, a visible
  `role="alert"` banner states this and the reason; it is not dismissible by
  AI action.
- Promotion of any non-official edge to canonical (`POST
  /api/review/promote-edge`) requires a non-empty, user-entered reviewer name
  (AI_ASSISTANCE_CONTRACT: AI proposes, determinism validates, humans
  promote). The action is disabled — with an explanatory inline message,
  never silently — until both the API is reachable and a reviewer name is
  entered.
- If the API sidecar is disabled, degraded, or offline, every dependent
  control (AI propose/validate, promote) is disabled with an inline
  explanation. No view fakes a success state.

## 10. Threat-Defense Knowledge Graph Navigator

`components/reasoning/graph/ThreatDefenseGraphNavigator.tsx` is the central
graph surface of the Reasoning Workbench (`/analyze`), rendering the
classified reasoning route (`ReasoningResult.route` + `ReasoningResult.edges`)
as an interactive graph. It is bound by the following, in addition to §1's
40-node render cap:

- Five graph modes are required: **Focused Route**, **Reasoning Neighborhood**,
  **Mitigation Path**, **Full Traceability**, **Evidence View**
  (`graph/GraphModeSelector.tsx`, `GraphMode` in `graph/graphTypes.ts`).
  Default mode is **Focused Route**.
- Selecting a node or edge MUST populate a right-hand inspector
  (`graph/GraphInspector.tsx`) with its classification, confidence, evidence,
  source refs, and (when safely derivable) an official-source link — never a
  raw contract dump as the primary interaction.
- Official-source links (NVD, MITRE CWE/CAPEC/ATT&CK/D3FEND) MUST only be
  built from trusted provided URLs, explicit local mappings, or
  already-resolvable `d3f:*` identifiers (`graph/officialUrlBuilder.ts`). MUST
  NOT invent links from uncertain abbreviations (e.g. `D3-EFA`).
- `Mitigation Path` mode MUST make the attack-to-defense route explicit:
  strengthen/highlight defensive edges, dim unrelated context, and add
  inspector language explaining the path from offensive reasoning toward
  D3FEND/defensive action (`graph/pathHighlighting.ts`).
- Empty/degraded graph states (no graphable route, no relationships, partial
  route, graph data unavailable, selection hidden by active filters) MUST be
  graph-level, product-worded notices — never a silent blank canvas (§3).
- Because `react-force-graph-2d` mutates link `source`/`target` from string
  ids into node objects after simulation starts, all selection, path
  highlighting, and mitigation-detection logic MUST read endpoint ids through
  the normalization helpers in `graph/graphAdapter.ts` /
  `graph/graphRuntime.ts` — never assume `link.source`/`link.target` remain
  strings.
- Compact classification filters and hover tooltips are required
  (`graph/GraphLegend.tsx`, `graph/GraphControls.tsx`); canvas labels stay
  compact by default, with detail pushed into the inspector so the first
  viewport stays readable for reduced-motion users.
- When the reasoning result includes `exports.navigator_layer`, it remains
  available as a download from the Exports panel (`ExportsPanel.tsx`).

## 7. Accessibility minimums

- All interactive elements reachable via Tab, with visible focus rings.
- Color is never the *only* signal (icons/labels accompany the canonical/
  inferred/gap color coding).
- Minimum text contrast ratio 4.5:1 for body text.
- Images/icons used for status carry `aria-label`.

## 8. Hard "no" list (validated by `tests/e2e` + manual checklist)

- No view renders the entire `nodes[]`/`edges[]` array on mount.
- No `fetch()`/`XMLHttpRequest` to a public API origin from `web/src/**`
  (bundle and same-origin API/MCP only).
- No unbounded list without scroll container or virtualization.
- No route/page with zero loading/empty/error handling.
