# GRAPH_CONTRACT

Defines the canonical graph model for CVEzD3FEND: node types, edge types, and
their semantics. This contract is the source of truth for `src/CVEzD3FEND/models/graph.py`
and for every validator in `src/CVEzD3FEND/validation/`.

## 1. Node types (closed set)

| type | meaning | typical id pattern |
|---|---|---|
| `cve` | A CVE record | `CVE-YYYY-NNNNN` |
| `cwe` | A weakness class | `CWE-NNN` |
| `capec` | An attack pattern | `CAPEC-NNN` |
| `attack` | A MITRE ATT&CK technique/sub-technique | `T1059`, `T1059.001` |
| `defend` | A MITRE D3FEND defensive technique | `D3-FA` |
| `atlas` | A MITRE ATLAS technique (AI/ML threats) | `AML.T0090` |
| `control` | A defensive control implementing one or more D3FEND techniques | `CTRL-D3-FA` |
| `detection` | A detection opportunity for an ATT&CK technique | `DET-T1059-D3-PSA` |
| `evidence` | Evidence artifact required to validate a detection | `EVID-DET-...` |
| `gap` | A first-class coverage gap | `GAP-<context>-<reason>` |
| `asset` | A generic asset class (workstation, server, identity provider, ...) | `ASSET-<slug>` |
| `product` | A vendor product (from KEV/NVD enrichment) | `PRODUCT-<slug>` |
| `vendor` | A vendor (from KEV/NVD enrichment) | `VENDOR-<slug>` |
| `kev` | A CISA Known Exploited Vulnerabilities entry | `KEV-CVE-YYYY-NNNNN` |
| `exploit` | An exploit-availability signal | `EXPLOIT-CVE-YYYY-NNNNN` |
| `mitigation` | A D3FEND-derived mitigation (non-Detect tactics) | `MIT-D3-FE` |
| `playbook` | A response playbook template | `PB-<TACTIC>` |
| `soc_action` | A SOC operational action template | `SOC-ACT-<TACTIC>` |
| `ctem_action` | A CTEM prioritization action tied to a gap | `CTEM-<gap-id>` |
| `threat_hunt` | A hunting hypothesis for an ATT&CK technique | `HUNT-<technique>` |
| `data_source` | A canonical telemetry/data source class | `DS-<slug>` |
| `log_source` | A canonical log source class (subset of data_source granularity) | `LOG-<slug>` |
| `rule` | A detection rule draft implementing a `detection` node | `RULE-<detection-id>` |
| `query` | A hunting query draft supporting a `threat_hunt` node | `QUERY-<technique>` |
| `case` | A SOC case template (reserved for future runtime integration) | `CASE-<slug>` |
| `note` | A free-form annotation node (used by AI candidates / reviewers) | `NOTE-<slug>` |

No other node `type` values are valid. Adding a type requires updating this
contract, `models/graph.py`, and `validation/schema.py` together.

## 2. Node fields (required on every node)

```
id, type, name, title, description, aliases[], external_refs[],
source_refs[], tags[], created_at, updated_at, confidence,
canonical, inferred, metadata{}
```

- `id` is globally unique and stable across builds (deterministic from source data).
- `aliases` holds cross-matrix / cross-framework identifiers (e.g. ATLAS techniques
  associated to an ATT&CK technique via `techniques_association.json`).
- `external_refs` holds outbound URLs to authoritative sources (attack.mitre.org,
  cwe.mitre.org, capec.mitre.org, d3f3nd.mitre.org, atlas.mitre.org, nvd.nist.gov, ...).
- `source_refs` holds internal references into `bundle.sources[]` (see PROVENANCE_CONTRACT).
- `canonical=true` means the node was produced deterministically from an
  authoritative source. `canonical=false` (with `inferred=true`) marks AI- or
  heuristic-derived nodes that have **not** been promoted (see AI_ASSISTANCE_CONTRACT).
- `confidence` is a float in `[0,1]`.

## 3. Edge types (closed set)

| type | source -> target | meaning |
|---|---|---|
| `cve_has_cwe` | cve -> cwe | The CVE is classified under this weakness |
| `cwe_maps_to_capec` | cwe -> capec | The weakness enables this attack pattern |
| `capec_maps_to_attack` | capec -> attack | The attack pattern realizes this ATT&CK technique |
| `attack_maps_to_defend` | attack -> defend | This D3FEND technique is relevant to the ATT&CK technique |
| `attack_maps_to_atlas` | attack -> atlas | This ATT&CK technique has an AI/ML (ATLAS) analogue |
| `defend_mitigates_attack` | defend -> attack | A non-Detect D3FEND technique mitigates the ATT&CK technique |
| `control_implements_defend` | control -> defend | A control operationalizes a D3FEND technique |
| `detection_detects_attack` | detection -> attack | A detection opportunity covers the ATT&CK technique |
| `evidence_supports_detection` | evidence -> detection | Evidence required to validate/operate the detection |
| `gap_blocks_coverage` | gap -> (attack\|cwe\|capec\|defend) | The gap blocks coverage of the target node |
| `kev_prioritizes_cve` | kev -> cve | CISA KEV listing raises priority of the CVE |
| `exploit_targets_cve` | exploit -> cve | Known exploit targets the CVE |
| `playbook_responds_to_attack` | playbook -> attack | Playbook applicable to the ATT&CK technique |
| `soc_action_operationalizes_defend` | soc_action -> defend | SOC action operationalizes a D3FEND technique |
| `ctem_action_prioritizes_gap` | ctem_action -> gap | CTEM action remediates the gap |
| `data_source_enables_detection` | data_source -> detection | Data source required for the detection |
| `rule_implements_detection` | rule -> detection | Rule draft implements the detection |
| `query_supports_hunt` | query -> threat_hunt | Query draft supports the hunting hypothesis |

No other edge `type` values are valid.

## 4. Edge fields (required on every edge)

```
id, source, target, type, label, confidence, deterministic, inferred,
source_ref, source_url, evidence[],
resolution_state, lifecycle_state, scope_state, assertion_type, confidence_basis,
created_at, updated_at, metadata{}
```

### Edge-state dimensions (Phase 2B)

`confidence` answers how strongly an edge is asserted, not whether the id is
real or how it was resolved. These state dimensions are orthogonal:

| field | allowed values | default | meaning |
|---|---|---|---|
| `resolution_state` | `resolved` \| `unresolved` \| `ambiguous` \| `invalid` | `resolved` | Whether the referenced id could be resolved to a usable canonical id |
| `lifecycle_state` | `active` \| `deprecated` \| `revoked` \| `unknown` | `active` | Lifecycle of the referenced id in its source framework |
| `scope_state` | `included` \| `excluded` \| `contextual` | `included` | Whether the edge is in scope for the active profile |
| `assertion_type` | `canonical` \| `source_derived` \| `curated` \| `inferred` | `canonical` | Provenance class of the assertion |
| `confidence_basis` | `exact_id` \| `numeric_padding` \| `parent_in_registry` \| `official_mapping` \| `unverified` \| `unresolved` \| `null` | `null` | Why the confidence value holds |

Only `resolved` entries are written as canonical edges. Structurally invalid or
absent ids MUST NOT be promoted to nodes/edges; they are recorded on the CAPEC
node as `metadata.unresolved_attack_refs` and surfaced as warnings.

- `id` is deterministic: `sha1(f"{type}:{source}->{target}")[:16]`.
- `deterministic=true` means the edge was produced by a pure function over
  versioned source data (no AI involved). All edges shipped in
  `knowledge-bundle.json` MUST have `deterministic=true` OR
  `inferred=true AND canonical=false` (see AI_ASSISTANCE_CONTRACT — inferred
  edges only ship if explicitly promoted, which sets `deterministic=true`
  retroactively with a human `reviewer` recorded in metadata).
- Every edge MUST resolve `source` and `target` to existing node ids
  (see VALIDATION_CONTRACT).

## 5. Routes and Coverage

Routes (`bundle.routes[]`) and coverage entries (`bundle.coverage`) are derived,
read-only projections over nodes/edges. They MUST NOT introduce information that
is not traceable to an existing node/edge. See ROUTING and COVERAGE sections of
BUNDLE_CONTRACT.
