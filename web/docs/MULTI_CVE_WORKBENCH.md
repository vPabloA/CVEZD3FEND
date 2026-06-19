# Multi-CVE Contextual Analysis Workbench

The Analyze page is the primary CVEzD3FEND product surface.

## Product contract

- Selected is loaded first with `include_all_candidates=false`.
- All candidates is loaded only after explicit user action and is cached for the
  deterministic request signature during the browser session.
- `selected_graph` and `candidate_graph` are consumed exactly as delivered.
- `graphAdapter.ts` performs visual projection and canonical-ID deduplication
  only; it never creates edges or resolves mappings.
- Ranking follows backend `selection_rank`; labels explain
  `selection_basis`.
- Executive, operational and technical narratives are backend-authored and
  rendered as text.
- Missing, invalid, partial, zero-route, API failure, All failure and AI
  fallback states remain visible.

## Screenshot evidence

The following screenshots are generated without secrets from the real
multi-CVE demonstration request:

- `screenshots/multi-cve-01-input-context.png` — batch input and context.
- `screenshots/multi-cve-02-selected-graph-ranking.png` — Selected graph and
  ranked routes.
- `screenshots/multi-cve-03-all-candidates.png` — explicit All universe and
  progressive-disclosure warning.
- `screenshots/multi-cve-04-partial-success.png` — found, missing and invalid
  result.
- `screenshots/multi-cve-05-route-evidence.png` — focused route inspector and
  catalog evidence.
- `screenshots/multi-cve-06-narrative.png` — executive, operational and
  technical narrative.

## Security boundary

The browser accepts only HTTP(S) external evidence links, validates graph and
route response shape, never renders remote HTML, never receives provider keys,
and never trusts client or AI identifiers to assert graph semantics.
