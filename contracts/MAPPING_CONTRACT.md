# MAPPING_CONTRACT

Defines exactly how each edge type is derived from raw sources. This is the
authoritative spec for `src/CVEzD3FEND/etl/*` and `src/CVEzD3FEND/graph/builder.py`.

## Golden rules

1. **No invented IDs.** Every node id referenced by an edge must come from a
   raw source field (a CVE id, CWE id, CAPEC id, ATT&CK technique id, D3FEND
   id, ATLAS id) or from a deterministic, documented derivation (e.g.
   `CTRL-<defend_id>` for control nodes). Derived ids are documented per edge
   type below.
2. **No edge without `source_ref`.** If a mapping cannot be traced to a
   versioned source, it is not written as a canonical edge — it becomes a
   `gap` node or an AI candidate instead.
3. **No silent promotion.** AI-proposed mappings never appear as
   `deterministic=true` edges. See AI_ASSISTANCE_CONTRACT.
4. **Cross-validation increases confidence, it never creates new edges by
   itself.** When a CVE record's own `CAPEC`/`TECHNIQUES`/`DEFEND` fields agree
   with a CWE/CAPEC-chain-derived mapping, the corresponding edge's
   `metadata.cross_validated = true` and `evidence[]` gains an entry; the edge
   itself must already exist via rule below.

## Edge derivation rules

### `cve_has_cwe`
- Source: `database/CVE-{year}.jsonl.gz` (or `.jsonl` fallback), field `CWE[]`.
- `source_ref`: `cve2capec:cve_{year}`.
- `confidence`: 1.00, `deterministic`: true.

### `cwe_maps_to_capec`
- Source: `resources/cwe_db.json`, field `RelatedAttackPatterns[]`.
- `source_ref`: `cve2capec:cwe_db`.
- `confidence`: 1.00, `deterministic`: true.
- `metadata.cross_validated = true` when the same CAPEC id also appears in the
  `CAPEC[]` field of a CVE that has this CWE.

### `capec_maps_to_attack`
- Source: `resources/capec_db.json`, field `techniques` (semi-structured
  taxonomy string). Parsed via regex
  `TAXONOMY NAME:ATTACK:ENTRY ID:([\w.]+)`.
- `source_ref`: `cve2capec:capec_db`.
- `confidence`: 0.85, `deterministic`: true.
- **Resolution (Phase 2B).** Each parsed taxonomy entry is resolved rather than
  blindly padded to `T<raw>`. The resolver runs against the ATT&CK universe
  built from `techniques_db.json`, `defend_db.jsonl`, `atlas_db.json`, and
  `techniques_association.json` (with implied parents folded in).
  - Structural rule: ids that are not `T` + 4 digits, optionally `.3 digits`,
    are `invalid` and never promoted.
  - Exact match: a valid id present in the universe resolves as `resolved`.
  - Parent match: a valid sub-technique absent from the registry but whose
    parent family exists resolves as `resolved` with parent-based confidence.
  - Registry unavailable: the resolver degrades gracefully for valid ids, but
    still rejects malformed legacy numerics such as `34` and `18`.
- Only resolved entries become canonical `attack` nodes + edges. Unresolved
  entries are recorded on the CAPEC node as `metadata.unresolved_attack_refs`.
- If a CAPEC has no resolved `ATTACK` taxonomy entry, no edge is created — this
  contributes to a `gap` node (`capec_without_attack`).

### `attack_maps_to_defend`
- Source: `resources/defend_db.jsonl`, top-level keys are ATT&CK technique ids,
  values are arrays of D3FEND technique objects `{id, tactic, technique, artifact}`.
- `source_ref`: `cve2capec:defend_db`.
- `confidence`: 1.00, `deterministic`: true.
- D3FEND techniques whose `tactic == "Detect"` additionally generate
  `detection` nodes + `detection_detects_attack` edges (see below). All other
  tactics (`Harden`, `Isolate`, `Evict`, `Restore`, `Deceive`, `Model`)
  generate `mitigation` nodes + `defend_mitigates_attack` edges.

### `attack_maps_to_atlas`
- Source: `resources/atlas_db.json`, top-level keys are ATT&CK technique ids,
  values are arrays of `{id, name, tactics, url}`.
- `source_ref`: `cve2capec:atlas_db`.
- `confidence`: 1.00, `deterministic`: true.
- Optional source: if absent or empty, no `atlas` nodes/edges are produced and
  a warning (not an error) is recorded.

### `defend_mitigates_attack`
- Derived alongside `attack_maps_to_defend` for D3FEND techniques whose
  `tactic != "Detect"`. Target `mitigation` node id: `MIT-<defend_id>`.
- `source_ref`: `cve2capec:defend_db`. `confidence`: 1.00, `deterministic`: true.

### `control_implements_defend`
- Derived 1:1 for every `defend` node: `control` node id `CTRL-<defend_id>`.
- `source_ref`: `cve2capec:defend_db` (the control is a direct operational
  framing of the D3FEND technique, not a new mapping).
- `confidence`: 1.00, `deterministic`: true.
- `metadata.derivation = "one_per_defend_technique"`.

### `detection_detects_attack`
- Derived for every `(attack, defend)` pair where `defend.tactic == "Detect"`.
  `detection` node id: `DET-<attack_id>-<defend_id>` (slashes/dots in
  `attack_id` replaced with `_`).
- `source_ref`: `cve2capec:defend_db`. `confidence`: 1.00, `deterministic`: true.

### `evidence_supports_detection`
- Derived 1:1 per `detection` node from a canonical evidence-template keyed by
  the D3FEND `artifact` field (e.g. artifact `"File"` -> evidence
  `EVID-ARTIFACT-FILE`). `evidence` node id: `EVID-<detection_id>`.
- `source_ref`: `cve2capec:defend_db` (artifact field).
- `confidence`: 0.85, `deterministic`: true.

### `gap_blocks_coverage`
- Generated by the coverage engine (`src/CVEzD3FEND/coverage/`) for:
  - `cve_without_cwe` — a CVE with empty `CWE[]`.
  - `cwe_without_capec` — a CWE with empty `RelatedAttackPatterns[]`.
  - `capec_without_attack` — a CAPEC with no parsed ATT&CK taxonomy entry.
  - `attack_without_defend` — an ATT&CK technique with no `defend` mapping.
  - `attack_without_detection` — an ATT&CK technique whose D3FEND mappings
    contain no `Detect`-tactic technique.
- `source_ref`: `CVEzD3FEND:coverage_engine` (an internal pseudo-source
  documenting the deterministic rule that produced the gap; see
  `bundle.sources[]` entry with `kind="derived_rule"`).
- `confidence`: 1.00 (the *absence* is verifiable), `deterministic`: true.

### `kev_prioritizes_cve` / `exploit_targets_cve`
- Source: CISA KEV catalog (`resources` collector, optional). If unavailable,
  no nodes/edges of type `kev`/`exploit` are produced (warning only).
- `source_ref`: `cisa:kev`. `confidence`: 1.00, `deterministic`: true.

### `playbook_responds_to_attack`, `soc_action_operationalizes_defend`,
### `ctem_action_prioritizes_gap`, `data_source_enables_detection`,
### `rule_implements_detection`, `query_supports_hunt`
- Generated from **canonical reference catalogs** shipped in
  `src/CVEzD3FEND/graph/catalogs/` (playbook templates per D3FEND tactic, SOC
  action templates per D3FEND tactic, data/log source catalog keyed by D3FEND
  `artifact`, rule/query draft templates per detection/technique).
- `source_ref`: `CVEzD3FEND:catalog_<name>` (`kind="derived_rule"`,
  `metadata.derivation = "canonical_reference_catalog"`).
- `confidence`: 0.30 (templates are operational scaffolding, not asserted
  factual mappings — analysts must validate before use). `deterministic`: true.
- These nodes/edges are clearly marked `metadata.template = true` and the UI
  renders them as "draft / template" content, distinct from
  framework-asserted mappings.

## What is explicitly NOT mapped without validation

- AI is never the `source_ref` of a canonical edge.
- `techniques_db.json` is a supporting ATT&CK registry used to build the
  resolver universe for `capec_maps_to_attack`; it creates no edges of its own.
- `techniques_association.json` does **not** create new edge types. It
  populates `aliases`/`external_refs` on `attack` nodes (cross-matrix
  technique ids for mobile/ICS), with `source_ref = cve2capec:techniques_association`.
