# ADR 0001 - Phase 2B: CAPEC -> ATT&CK Mapping Resolution Hardening

- Status: Proposed
- Date: 2026-06-17
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
