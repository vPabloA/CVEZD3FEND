# Graph Navigator → Trace Explorer iteration

Pre-implementation findings required by the iteration brief. Attack2Defend
(`~/attack2defend/app/navigator-ui`), CVE2CAPEC, and grafos_CTI were explored
as **references only**; no code was copied, no backend contract was touched,
and CVEzD3FEND remains the target project.

## Reference Read

### 1. What Attack2Defend does well in graphs

Observed in `RouteGraph.tsx`, `MappingGraph2D.tsx`,
`graph/graphRenderPlan.ts`, `graph/graphModel.ts`:

- **Semantic layer columns with left→right reading.** Fixed x-columns per
  taxonomy (CVE → CWE → CAPEC → ATT&CK), with column labels drawn on the
  canvas (`CCG_MAIN_COLS`, `TYPE_LAYER`). The progression
  vulnerability → weakness → pattern → technique → defense is legible at a glance.
- **D3FEND as a distinguished defensive destination**, not one more node type:
  a separated band with its own label ("D3FEND — CONTRAMEDIDAS DEFENSIVAS"),
  its own node styling, and a "top defensive countermeasures" summary card.
- **Provenance encoded with more than color**: per-basis color + dash pattern
  + stroke width (`EDGE_COLOR`/`EDGE_DASH`/`EDGE_WIDTHS`) and a persistent
  edge-provenance legend.
- **Anti-hairball discipline**: canonical vs alternative buckets, an
  alternative cap per stage (`GRAPH_ALTERNATIVE_LIMIT = 3`) with explicit
  hidden-alternative counts, and node/link caps in the view model
  (`DEFAULT_MAX_NODES/LINKS`).
- **Selection dimming**: selecting a node drops unconnected nodes/edges to
  near-zero opacity instead of hiding them — focus without losing context.
- **Analyst-language side panel**: role, provenance badge, rationale, sources,
  "connects with →" — never raw JSON.

### 2. What CVE2CAPEC contributes

- **Trace and cherry-picker mental model.** The useful pattern is not the
  visual skin; it is the analyst feeling of selecting a precise sub-route
  through many possible CVE/CWE/CAPEC/ATT&CK/D3FEND relationships.
- **Layered route reading.** Wide context is available, but the route remains
  directionally readable from vulnerability to defense.
- **Selective expansion.** Branches can be explored surgically without turning
  the first view into a hairball.

Transferred only as behavior: selectable trace steps, selected-route emphasis,
and context parking. The external UI is not copied.

### 3. What grafos_CTI contributes

Observed in `CoverageMapInteractive.jsx` and the public hierarchical graph
CSV artifacts:

- **Layer labels are persistent.** Nodes are interpretable because layers are
  named directly on the graph surface, not only in a legend.
- **Bidirectional focus.** Its "spider" focus gathers ancestors, descendants,
  direct neighbors, and equivalent labels around a selected entity. For
  CVEzD3FEND, the transferable part is neighborhood focus around a selected
  route node/edge.
- **Context must be bounded.** The project uses explicit render modes and node
  counts, which reinforces the need for off-stage counts and progressive
  reveal in CVEzD3FEND.

Rejected for this product: radial multi-ring layout as the primary view,
console-debug workflows, synthetic inventory expansion, and "LemonGraph
preview" affordances. They add CTI exploration texture but weaken
CVE→D3FEND route clarity.

## Transfer Decisions

### 4. Patterns transferred to CVEzD3FEND

- Deterministic **trace layout**: semantic columns CVE / CWE / CAPEC / ATT&CK /
  D3FEND (+ a context/evidence lane), canonical spine pinned to the top row,
  alternatives stacked below — implemented by pinning `fx`/`fy` inside the
  existing react-force-graph runtime (no new dependency, no SVG rewrite).
- Contract-level defensive nodes (`routeRole: defensive`) are also staged in
  the D3FEND/Defense lane even when their operational label is not a MITRE
  D3FEND identifier.
- Layer labels + defensive band painted via `onRenderFramePre`.
- Edge classification encoded with **dash pattern + width**, on top of the
  existing color tokens (color is no longer the only signal).
- Stronger **selection dimming** in all modes (previously only mitigation mode).
- **Route cherry picking**: clickable trace-spine chips, primary-route
  emphasis toggle, context show/hide, trace/force layout toggle — framed as
  command controls, not generic filters.
- Inspector upgraded with "role in route / why it matters / relation to the
  CVE" analyst language.
- The inspector is no longer open by default in Analyze; details stay on
  demand until an analyst selects a node, route step, or edge.

### 5. Patterns NOT transferred (would break CVEzD3FEND identity)

- **The SVG `RouteGraph` component itself** and its fixed 1300×830 canvas —
  CVEzD3FEND keeps its interactive force-graph runtime, modes, and SPOG shell.
- A2D's **provenance vocabulary** (`official_explicit/official_related/...`).
  CVEzD3FEND already has its own 7-level `ReasoningEdgeClassification` wired
  to UIX_CONTRACT color tokens; we map dash/width onto that, we do not rename.
- A2D's Spanish-only labels, export toolbar, AI context packet, coherence
  panels — out of scope; CVEzD3FEND has its own briefing/evidence/governance.
- A2D's separate Neo4j/CSV graph data plane — no data contract changes.
- CVE2CAPEC's external page structure and matrix-first interactions — only the
  trace/cherry-picker behavior is relevant.
- grafos_CTI's radial rings, free/lemon mode switch, synthetic graph expansion,
  and console diagnostics — useful for CTI exploration, noisy for this
  decision-first CVE→D3FEND workbench.

## Implementation Scope

### 6. CVEzD3FEND files touched

- `web/src/components/reasoning/graph/traceLayout.ts` (new — pure layout fn)
- `web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx`
- `web/src/components/reasoning/graph/GraphControls.tsx`
- `web/src/components/reasoning/graph/GraphInspector.tsx`
- `web/src/components/reasoning/graph/GraphLegend.tsx`
- `web/src/components/reasoning/graph/graphTypes.ts`
- `web/src/pages/AnalyzePage.tsx` (clear selection now genuinely clears)
- `web/src/test/graphNavigator.test.tsx` (extended)

Not touched: backend, API payloads, `graphAdapter.ts` contract mapping,
`pathHighlighting.ts` semantics, AnalyzePage layout, Tier1BriefingCard,
ReasoningSkillsPanel, AdvancedEvidenceDrawer, HumanReviewBanner.

### 7. Risks

- **Force-graph endpoint mutation**: react-force-graph rewrites link
  source/target to node objects; all new logic keeps using
  `graphLinkSourceId/TargetId` normalizers.
- **Pinned nodes vs drag**: `fx/fy` pinning ends the simulation instantly;
  dragging still works (it updates `fx/fy`). Force layout remains available
  as an escape hatch.
- **Test selector collisions**: the vitest mock renders node ids as buttons;
  new clickable spine chips use distinct `aria-label`s ("Trace step N: <id>")
  to avoid duplicate accessible names.
- **`linkLineDash`/`onRenderFramePre` availability**: verified present in the
  installed react-force-graph-2d typings before use.
- **Cherry-picker hiding selected evidence**: selection notices stay visible
  when filters/context parking hide the selected item.
- **D3FEND over-emphasis**: the defensive band is strongest in Mitigation Path
  mode and muted otherwise so normal route reading still works.

### 8. Validation that the workbench is not broken

- `npm run lint`, `npm run build`, `npm run test` must pass.
- Existing graphNavigator + AnalyzePage tests untouched in their assertions
  (mode tabs, Fit view / Reset route focus / Clear selection, inspector
  texts, empty/partial/degraded states, hidden-selection notices).
- New tests: trace layout column assignment + canonical spine ordering,
  primary-route emphasis, context visibility toggle, and true clear-selection
  behavior. Defensive route-role nodes without D3 ids are protected in the
  defense lane and are not hidden by context parking.
- Manual pass on `/analyze`, `/analyze?cve=...` for full, partial,
  conditional/weak-fit and human-review routes (graph-first, no raw JSON,
  briefing and evidence drawer intact).

## Manual Screenshot Plan

- Local dev URLs use `HashRouter`: `http://127.0.0.1:5174/#/analyze...`.
- Screenshot environment used for this iteration:
  - API: `CVEZD3FEND_API_PORT=8001 PYTHONPATH=src python3 -m CVEzD3FEND.cli api`
  - Web: `VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev -- --host 127.0.0.1 --port 5174`
- Captures saved under `web/docs/screenshots/`:
  - `trace-graph-01-idle-analyze.png`
  - `trace-graph-02-cve-2025-0168-complete-route.png`
  - `trace-graph-03-mitigation-path.png`
  - `trace-graph-04-selected-node.png`
  - `trace-graph-05-selected-edge.png`
  - `trace-graph-06-evidence-drawer-open.png`
  - `trace-graph-07-cve-2026-20975-partial-conditional.png`
  - `trace-graph-08-primary-route-cherry-picker.png`
