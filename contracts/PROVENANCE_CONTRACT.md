# PROVENANCE_CONTRACT

Every node and every edge in `knowledge-bundle.json` MUST be traceable to one
or more entries in `bundle.sources[]` / `bundle.provenance{}`.

## 1. Source entry shape

```json
{
  "source_id": "cve2capec:cwe_db",
  "name": "CVE2CAPEC CWE Database",
  "kind": "cwe_db",
  "url": "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/cwe_db.json",
  "fetched_at": "2026-06-09T00:00:00Z",
  "version": "main",
  "sha256": "<hex digest of fetched payload>",
  "record_count": 969,
  "status": "ok",
  "compressed": false,
  "license": "See docs/ATTRIBUTION.md",
  "notes": "string|null"
}
```

- `status` is one of `ok`, `fallback`, `unavailable`, `error`.
- `sha256` is computed over the raw bytes as fetched (before decompression),
  enabling reproducibility checks and tamper detection.
- For yearly CVE sources, `kind="cve_year_db"` and `metadata.year` records the
  year; `compressed` reflects whether `.jsonl.gz` was used or the pipeline
  fell back to `.jsonl`.

## 2. Per-node provenance

Every node carries:

- `source_refs: ["<source_id>", ...]` — at least one entry, always.
- `metadata.provenance`: optional structured detail (e.g. which year-files a
  `cve` node appeared in).

## 3. Per-edge provenance (mandatory fields)

Every edge carries, in addition to `source_refs`-equivalent:

- `source_ref`: the **primary** `source_id` that justifies this edge
  (REQUIRED, non-null).
- `source_url`: direct URL to the authoritative artifact backing the edge
  (REQUIRED when the source has a URL; null only for purely internal/derived
  reference data such as canonical `data_source` catalogs, which instead set
  `metadata.derivation = "canonical_reference_catalog"`).
- `evidence[]`: free-form supporting strings (e.g. the raw taxonomy fragment
  from `capec_db.json` that produced a `capec_maps_to_attack` edge).
- `confidence`: float in `[0,1]`.
- `deterministic`: boolean — `true` if produced by a pure function over a
  versioned source.
- `inferred`: boolean — `true` if produced or suggested by the AI layer.
  `inferred=true` and `deterministic=true` are mutually exclusive on edges
  shipped in the canonical bundle (an inferred edge becomes deterministic only
  through promotion, see AI_ASSISTANCE_CONTRACT, at which point
  `metadata.promoted_from_candidate` records the candidate id and reviewer).

## 4. Confidence scale (deterministic edges)

| confidence | meaning |
|---|---|
| 1.00 | Direct 1:1 mapping explicitly present in an authoritative source (e.g. `cwe_db.RelatedAttackPatterns`, `defend_db.jsonl`, `atlas_db.json`) |
| 0.85 | Mapping derived by parsing a structured-but-textual field (e.g. `capec_db.techniques` taxonomy string) |
| 0.60 | Cross-validated mapping (e.g. CVE-reported CAPEC/TECHNIQUES/DEFEND lists used to corroborate a CWE/CAPEC-derived chain) |
| 0.30 | Heuristic/derived reference catalog entries (canonical data_source/log_source/control catalogs) |
| <0.30 | Reserved for AI-origin candidates only; never shipped canonical |

## 5. Validation

`CVEzD3FEND validate` MUST fail (exit non-zero) if:
- Any edge has `source_ref == null`.
- Any `source_ref` does not resolve to an entry in `bundle.sources[]`.
- Any node has an empty `source_refs[]`.

See VALIDATION_CONTRACT for the full rule list.
