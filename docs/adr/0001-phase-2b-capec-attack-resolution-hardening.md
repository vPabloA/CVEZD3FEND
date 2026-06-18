# ADR 0001 - Phase 2B: CAPEC -> ATT&CK Mapping Resolution Hardening

- Status: Accepted
- Date: 2026-06-17
- Accepted: 2026-06-18 (Final Phase, Gate 1 semantic audit)
- Scope: `capec_maps_to_attack` resolution and edge-state modeling

## Context

The CAPEC -> ATT&CK mapping path was the weakest link in the canonical graph.
Before this change, the builder normalized every parsed ATT&CK taxonomy entry
with blind `T{raw}` padding, which could create phantom nodes for malformed ids
such as `34` or `18`.

## Decision

Introduce a deterministic resolver over a union ATT&CK universe built from
`techniques_db.json`, `defend_db.jsonl`, `atlas_db.json`, and
`techniques_association.json`, with parent-family folding for under-enumerated
sub-techniques.

Model edge resolution with separate dimensions:
`resolution_state`, `lifecycle_state`, `scope_state`, `assertion_type`, and
`confidence_basis`.

## Consequences

- Malformed legacy ids are rejected instead of being promoted to nodes.
- Real sub-techniques omitted by one registry source can still resolve via their
  parent family.
- Unresolved entries are recorded on the CAPEC node and surfaced as warnings.
- The bundle format remains backward-compatible because the new edge fields have
  defaults.

## Gate 1 hardening addendum (Final Phase, 2026-06-18)

Audit against the closed-set invariants in `contracts/GRAPH_CONTRACT.md`
found that `resolution_state`, `lifecycle_state`, `scope_state`,
`assertion_type`, and `confidence_basis` were typed as plain `str` on the
`Edge` model — the contract's closed vocabularies were documented but not
enforced, against this repo's own stated convention (`models/graph.py`:
"adding a value here without updating the contract is a bug"). Fixed by
promoting all five to `str, Enum` types in `models/graph.py` (the single
source of truth `graph/resolution.py` now imports from), matching the
contract's vocabulary exactly. Pydantic enforces the closed set at parse
time; the existing 40MB production bundle still parses unchanged, proving
backward compatibility.

Also found: a well-formed ATT&CK id absent from the registry
(`absent_from_registry`) was classified `resolution_state=invalid`,
conflating "malformed id" with "well-formed but unresolved" — the contract
table distinguishes these. Fixed: that path now returns `unresolved`. No
prior test exercised this path; one was added
(`test_well_formed_id_absent_from_registry_is_unresolved_not_invalid`).

**Accepted non-blocking debt** (tracked in `PLAN.md`, not blocking this ADR):

- `lifecycle_state` values `deprecated`/`revoked` are modeled but never
  populated — `build_attack_universe` does not pass `deprecated=`/`revoked=`
  to `AttackUniverse.from_techniques_db` because no upstream source
  (`techniques_db.json`, `defend_db.jsonl`, `atlas_db.json`,
  `techniques_association.json`) currently carries that signal. Revisit if a
  source with lifecycle data is added.
- `resolution_state=ambiguous` is declared but structurally unreachable: the
  resolver produces exactly one normalized candidate per raw id, so there is
  no code path that detects multiple plausible interpretations. Revisit if a
  second disagreeing registry source is introduced.
- `confidence_basis=official_mapping` is declared but unused — no edge
  creator (`add_defend_db`, `add_atlas_db`, `add_cwe_db`) currently sets
  `confidence_basis` on directly-sourced, non-resolved edges. Candidate for a
  follow-up slice, not required for this ADR's scope.
- No ATT&CK domain (enterprise/mobile/ics) field exists on `attack` nodes;
  `build_attack_universe` unions ids from all sources into one flat set, so
  cross-domain id collisions are not detected. Out of this ADR's scope
  (CAPEC -> ATT&CK resolution only); candidate for the Trace Engine gate.
- Duplicate taxonomy entries that resolve to the same `(capec, attack)` pair
  are silently deduplicated by deterministic edge id, with no integrity
  finding recorded. Functionally correct (no duplicate canonical edge) but
  not observable; candidate for the integrity-findings gate.
