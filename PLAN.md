# PLAN.md — Final Phase: Semantic Integrity, Operability, Accessibility and Release Hardening

This file is the living tracker for the Final Phase closure of CVEzD3FEND.
It did not exist before this phase; it is created here as the single record
of gate status, evidence, decisions, and accepted debt. Update it in place as
gates close — do not create parallel planning documents.

Principle (non-negotiable, unchanged from the project brief):

> CVEzD3FEND does not draw associations: it materializes traceable assertions.

## How to read this file

- **Status** is one of: `Done`, `Partial`, `Not started`, `Accepted debt`.
- A gate is `Done` only when code + tests demonstrate it, never because
  "existing tests still pass."
- Every `Partial`/`Not started` row names the concrete next action.

## Gate 0 — Repository Truth and Baseline

Verified 2026-06-18, branch `ux/trace-graph-navigator-polish` (up to date with
`origin`), PR #6 (`OPEN`, `draft`, base `main`, mergeable).

| Check | Result |
|---|---|
| `python3 -m compileall src tests` | exit 0 |
| `.venv/bin/pytest -q` | 115 passed, 1 warning (baseline) → **116 passed, 1 warning** after Gate 1 fix |
| Warning | `starlette.testclient` `httpx` deprecation notice — pre-existing, unrelated to Phase 2B, not release-blocking on its own (tracked below) |
| Python lint/type-check | **not configured** — no `ruff`/`mypy` in the venv or `pyproject.toml` dev deps |
| Frontend lint/type-check/test/build | configured (`eslint`, `tsc -b`, `vitest`, `vite build`) — **not yet run in this phase** |
| `CLAUDE.md` | does not exist |
| `PLAN.md` | did not exist before this phase (this file) |
| `data/dist/knowledge-bundle.json` | present on disk (40.6MB, gitignored as of `0e94bcb`), parses and structurally validates against the post-Gate-1 `Edge` model with zero changes needed |
| Working tree (uncommitted, pre-existing, unrelated) | `.gitignore`, `README.md`, `docs/OPERATIONS.md`, `src/CVEzD3FEND/cli.py`, `src/CVEzD3FEND/config.py`, `tests/e2e/test_cli.py` — in-progress `serve --host/--port` work, continues `0e94bcb`. Out of this phase's scope per "no modifiques componentes no relacionados"; left untouched and uncommitted by this phase's commits. |

Architecture found (not invented, not changed):

- Static-first pipeline: `src/CVEzD3FEND/{etl,graph,routing,coverage,validation,export,actions,intelligence}` → `pipeline.py` → `data/dist/knowledge-bundle.json` + `quality-report.json`.
- 9 formal contracts in `contracts/`. `GRAPH_CONTRACT.md` already documents the Phase 2B edge-state dimensions table in full (the contract was ahead of the code — see Gate 1).
- A real (if minimal) trace/coverage layer already exists: `routing/routes.py` (200 lines), `coverage/model.py` (187 lines) — these are the seed for Gates 2-4, not a blank slate.
- Frontend `ThreatDefenseGraphNavigator.tsx` + `graph/` already implements 5 graph modes, an inspector, mitigation-path highlighting, official-source-link safety rules, and degraded-state notices (`contracts/UIX_CONTRACT.md` §10). This is the seed for Gates 6-11, not a blank slate.
- No bundle digest, no trace artifact split (`trace-index.json`/`coverage-summary.json`/`traces/<CVE>.json`), no projection layer, no `ruff`/`mypy`, no dependency-audit step in CI yet.

## Gate 1 — Semantic Closure of Phase 2B

**Verdict: PASS WITH NON-BLOCKING FINDINGS → fixed to PASS.**

Audited `src/CVEzD3FEND/graph/resolution.py`, `graph/builder.py` (`add_capec_db`,
`build_attack_universe`), `models/graph.py`, `graph/context.py`, and
`tests/unit/test_graph_resolution.py` against the 15 invariants and the
required scenario list.

### Findings and fixes (this session, commit-scoped)

1. **Closed-set contract not enforced in code (fixed).** `Edge.resolution_state`,
   `lifecycle_state`, `scope_state`, `assertion_type`, `confidence_basis` were
   plain `str` — the `GRAPH_CONTRACT.md` vocabulary table existed but nothing
   validated against it, contradicting this repo's own stated convention in
   `models/graph.py` ("adding a value here without updating the contract is a
   bug," already applied to `NodeType`/`EdgeType`). Fixed: promoted all five to
   `str, Enum` in `models/graph.py`; `graph/resolution.py` now imports
   `ResolutionState`/`LifecycleState`/`ConfidenceBasis` from there instead of
   maintaining a second, divergent definition (mandate: no duplicate contracts
   without parity proof — there is now exactly one definition).
2. **`resolution_state` conflated "invalid" and "unresolved" (fixed).** A
   well-formed ATT&CK id absent from the registry (`absent_from_registry`) was
   classified `invalid`, the same bucket as structurally malformed ids — the
   contract table already distinguishes `invalid` from `unresolved`. Fixed:
   that path now returns `unresolved`. Added
   `test_well_formed_id_absent_from_registry_is_unresolved_not_invalid`
   (no prior test covered this path).
3. **Backward compatibility verified, not assumed.** The existing 40.6MB
   production `knowledge-bundle.json` (built before this fix) still parses and
   passes `validate_structure` unchanged under the new enum-typed model —
   proof, not assertion, that the contract tightening is non-breaking.
4. **No frontend coupling.** Grepped `web/src` and `web/src/**/*.ts(x)` — zero
   references to `resolution_state`/`lifecycle_state`/`scope_state`/
   `assertion_type`/`confidence_basis`. This fix is backend-only.

Evidence: `python3 -m compileall src tests` exit 0; `.venv/bin/pytest -q` →
**116 passed, 1 warning** (was 115); `.venv/bin/CVEzD3FEND validate` against
the on-disk bundle → "Bundle is structurally valid," same 4 pre-existing
quality warnings (route/gap truncation, expected and budget-driven, unrelated
to this fix).

### Accepted non-blocking debt (recorded in ADR 0001 addendum, not blocking)

| Debt | Severity | Why accepted now | Revisit trigger |
|---|---|---|---|
| `lifecycle_state` `deprecated`/`revoked` never populated from real data — `build_attack_universe` doesn't pass `deprecated=`/`revoked=` | Medium | No current upstream source (`techniques_db.json`, `defend_db.jsonl`, `atlas_db.json`, `techniques_association.json`) carries a lifecycle/revocation signal; the field exists for when one does | A source with lifecycle data is added, or a CAPEC maps to a known-revoked technique and the gap is silently reported as `active` |
| `resolution_state=ambiguous` structurally unreachable | Low | Resolver produces exactly one normalized candidate per raw id by design (ADR 0001 decision); no second disagreeing source exists yet to create ambiguity | A second ATT&CK-id-bearing source is added that can disagree with the primary registry |
| `confidence_basis=official_mapping` declared, unused | Low | `add_defend_db`/`add_atlas_db`/`add_cwe_db` are direct, non-resolved mappings; wiring this is a same-shape, low-risk follow-up but out of this ADR's literal scope | Before Gate 4 (assertion reconciliation) needs to distinguish official-direct vs. resolved-via-resolver provenance |
| No ATT&CK domain (enterprise/mobile/ics) field; cross-domain id collisions undetected | Medium | Out of ADR 0001's stated scope (CAPEC→ATT&CK resolution only); `techniques_association` mobile/ics ids are stored as aliases, not unioned as colliding primary ids, so today's risk is latent, not active | Before Gate 2/3 (Trace Engine) defines profile-scoped domain filtering |
| Duplicate taxonomy entries resolving to the same `(capec, attack)` pair are silently deduped (deterministic edge id), no integrity finding recorded | Low | Functionally correct — no duplicate canonical edge is ever written | Gate 3 (integrity findings) needs a `duplicate_mapping` finding type for observability |
| `starlette.testclient`/`httpx` deprecation warning in test output | Low | Pre-existing, unrelated to Phase 2B, cosmetic | Before adopting a `httpx` major version that removes the shim |

## Gates 2-24 — Status

Not started in this session by explicit user scoping decision (this session's
mandate was: create `PLAN.md` + close Gate 1, document the rest as backlog —
not simulate a 24-gate closure in one pass). Each row below is grounded in
what Gate 0 actually found, not assumed.

| Gate | Title | Status | Grounding / next concrete action |
|---|---|---|---|
| 2 | Canonical Trace Contract | Not started | Seed exists: `routing/routes.py`, `coverage/model.py`. Next: define `TraceReport`-equivalent dataclass/pydantic model in `src/CVEzD3FEND/routing/` or a new `src/CVEzD3FEND/trace/` module, profiles (defensive/offensive/cross-framework), path classification, termination reasons. |
| 3 | Deterministic Trace Engine | Not started | Depends on Gate 2's contract. Build `trace_summary`/`trace_paths` over `routing/routes.py`'s existing traversal, add cycle-guard/depth/path limits, gap records, integrity findings. |
| 4 | Coverage and Assertion Reconciliation | Not started | `coverage/model.py` (187 lines) is a single-metric model today; needs splitting into the 7 named coverage policies with explicit numerator/denominator/scope, plus assertion evaluation states. |
| 5 | Artifact Architecture | Not started | No `trace-index.json`/`coverage-summary.json`/`traces/<CVE>.json` split exists; no bundle digest exists anywhere in the codebase (`grep digest` found nothing). Reproducibility is also blocked today by `now_iso()` wall-clock timestamps embedded in every node/edge `created_at`/`updated_at` — full bundle is not byte-identical across builds. This is pre-existing, not introduced by Phase 2B, but is a hard prerequisite for Gate 5's "deterministic build comparison." |
| 6 | Graph-Safety Projection Layer | Not started | Depends on Gate 2/3 contracts existing first. |
| 7 | Truth-Preserving Trace Explorer | Partial (seed) | `ThreatDefenseGraphNavigator.tsx` already has modes/inspector/mitigation-path/degraded states per `UIX_CONTRACT.md` §10. Needs gap-visibility-by-default, coverage-per-link, and the 5 named views (Trace Graph/Path/Coverage/Assertion Comparison/Sankey) layered on top — not a rewrite. |
| 8 | Visual Semantics | Not started | No semantic-token system audited yet; current legend (`GraphLegend.tsx`) not yet checked against the 12 required states. |
| 9 | Inspector and Explainability | Partial (seed) | `GraphInspector.tsx` (68 lines changed in this branch) exists; not yet audited against the full node/edge/gap/assertion inspector field lists. |
| 10 | Semantic Controls and Progressive Disclosure | Not started | `GraphControls.tsx`/`GraphModeSelector.tsx` exist; not yet audited against the full filter/disclosure list. |
| 11 | Interaction Design | Not started | Not yet audited (focus, breadcrumbs, deep links, layout stability). |
| 12 | Responsive and Fullscreen Hardening | Not started | Not yet audited. |
| 13 | Accessibility Hardening | Not started | No accessibility test tooling found yet in `web/package.json` devDependencies (no `axe`/`jest-axe`/equivalent). Needs a tooling decision before this gate can produce automated evidence. |
| 14 | Performance and Scale | Not started | No baseline measured yet (bundle size, render time, node/edge counts at scale). |
| 15 | Reliability and Degraded States | Partial (seed) | `UIX_CONTRACT.md` §3 already mandates non-silent empty/degraded states; not yet audited against the full state list (corrupt artifact, digest mismatch, schema-unsupported, etc. — most of which don't exist as concepts yet, see Gate 5). |
| 16 | Application Security | Not started | Not yet audited (innerHTML usage, URL building, deep-link parsing). |
| 17 | Software Supply Chain | Not started | No dependency audit step found in CI; `npm audit`/`pip-audit` not yet run in this phase. |
| 18 | Comprehensive Testing | Partial | 116 Python unit/integration/e2e tests pass; frontend test suite (`vitest`) not yet run in this phase; no property tests, no golden-trace fixtures yet (Gate 2/3 prerequisite). |
| 19 | CI Quality Gates | Not started | CI configuration not yet inventoried in this session. |
| 20 | Knowledge Quality Operations | Not started | `intelligence/` AI candidate queue already exists and is read-only/proposal-first per `AI_GOVERNANCE.md`/`AI_ASSISTANCE_CONTRACT.md` (not audited line-by-line yet, but the architecture already matches this gate's "permitted" list by design). |
| 21 | Product and UX Acceptance | Not started | Requires Gates 6-13 first. |
| 22 | Documentation and Developer Experience | Partial | This file + ADR 0001 addendum are the first concrete deliverable. `docs/ARCHITECTURE.md`, runbooks not yet audited/updated. |
| 23 | Build and Release Hardening | Not started | Depends on Gate 5 (no digest/reproducibility mechanism exists yet to harden). |
| 24 | Git and Delivery Discipline | Partial | PR #6 confirmed open/draft/mergeable; this session's commits follow the capability-slice convention (this slice: "semantic closure"). |

## Definition of Done — tracked, not yet met

None of the four DoD sections (Semantic, UX, Accessibility, Operability) from
the phase brief are met yet — Gate 1 alone does not close any of them; each
requires Gates 2-24. This file will be updated, gate by gate, as each is
actually closed with evidence, in separate commits/sessions.

## Commits this session

| Commit | Scope | Validation |
|---|---|---|
| (pending) | Gate 1: enum-close edge-state contract fields, fix `unresolved` vs `invalid` conflation, add regression test, accept ADR 0001, create this file | `compileall` exit 0; pytest 116 passed (was 115); `CVEzD3FEND validate` against real 40.6MB bundle unchanged |
