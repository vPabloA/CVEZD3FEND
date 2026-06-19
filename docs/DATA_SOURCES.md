# Data Sources

| Source | URL | Format | Frequency | Used for | Fallback |
|---|---|---|---|---|---|
| ATT&CK techniques association | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/techniques_association.json` | JSON object, `{enterprise_tech_id: {mobile, ics}}` | per build | `attack` node `aliases`/`external_refs` (cross-matrix ids) | none — optional, warning if missing |
| ATT&CK techniques DB | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/techniques_db.json` | JSON object, `{attack_tech_id: [...tactics]}` | per build | Resolver universe for `capec_maps_to_attack` | optional — if missing, resolver degrades to structural-only, warning |
| CVE year databases | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/database/CVE-{year}.jsonl.gz` | gzip JSONL, one `{CVE-ID: {CWE[], CAPEC[], TECHNIQUES[], DEFEND[]}}` per line | per build, current + previous year | `cve` nodes, `cve_has_cwe` edges, cross-validation of CWE/CAPEC/ATT&CK/D3FEND chains | `CVE-{year}.jsonl` (uncompressed) if `.jsonl.gz` 404s/fails; if both fail, recorded as `status=unavailable` warning, build continues |
| ATLAS DB | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/atlas_db.json` | JSON object, `{attack_tech_id: [{id, name, tactics, url}]}` | per build | `atlas` nodes, `attack_maps_to_atlas` edges | optional — if missing/empty, no ATLAS content, warning only |
| D3FEND DB | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/defend_db.jsonl` | JSONL, one `{attack_tech_id: [{id, tactic, technique, artifact}]}` per line | per build | `defend`/`control`/`mitigation`/`detection`/`evidence` nodes, `attack_maps_to_defend`, `defend_mitigates_attack`, `control_implements_defend`, `detection_detects_attack`, `evidence_supports_detection` | required — fatal if unavailable |
| CAPEC DB | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/capec_db.json` | JSON object, `{capec_id: {name, techniques}}` | per build | `capec` nodes, `capec_maps_to_attack` edges (parsed from `techniques` taxonomy string) | required — fatal if unavailable |
| CWE DB | `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/cwe_db.json` | JSON object, `{cwe_id: {ChildOf[], RelatedAttackPatterns[]}}` | per build | `cwe` nodes, `cwe_maps_to_capec` edges | required — fatal if unavailable |
| CISA KEV (optional) | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON | per build, opt-in via `CVEZD3FEND_ENABLE_KEV=true` | `kev`, `vendor`, `product` nodes, `kev_prioritizes_cve` edges | optional — tolerant of absence, warning only |

## Year selection logic

`src/CVEzD3FEND/etl/cve_years.py` computes `years = [current_year, current_year - 1]`
from `CVEZD3FEND_REFERENCE_DATE` (defaults to system UTC date at build time).
For example, a build run in 2026 fetches `CVE-2026.jsonl.gz` and
`CVE-2025.jsonl.gz`.

## Per-year metadata recorded

```json
{
  "year": 2026,
  "url": "https://raw.githubusercontent.com/.../CVE-2026.jsonl.gz",
  "compressed": true,
  "record_count": 23862,
  "records_processed": 200,
  "sha256": "<hex>",
  "fetched_at": "2026-06-09T00:00:00Z",
  "status": "ok"
}
```

`record_count` is the total number of lines in the source file;
`records_processed` reflects `CVEZD3FEND_MAX_CVES_PER_YEAR` (default 200) — see
ARCHITECTURE.md "Performance notes". Set `CVEZD3FEND_MAX_CVES_PER_YEAR=0` for
unlimited (full ingest) — recommended only for non-interactive/internal builds
given resulting bundle size.

## Known gaps / honest degradations

- **CWE names/descriptions**: `cwe_db.json` provides only `ChildOf` and
  `RelatedAttackPatterns` — no human-readable name. CWE nodes are named
  `CWE-<id>` with `external_refs` pointing to
  `https://cwe.mitre.org/data/definitions/<id>.html`. A future collector
  (`etl/frameworks.py::fetch_cwe_catalog`, currently a documented stub) can
  enrich names from the official MITRE CWE catalog.
- **ATT&CK technique names**: similarly not present in any CVE2CAPEC resource
  used here. ATT&CK nodes are named by their technique id with
  `external_refs` to `https://attack.mitre.org/techniques/<Txxxx>/` (or
  `/<Txxxx>/<sub>/` for sub-techniques). A future collector can enrich from the
  MITRE ATT&CK Enterprise STIX bundle.
- **EPSS / exploit prediction**: reserved field
  `node.metadata.epss_score` on `cve` nodes, populated only if
  `CVEZD3FEND_ENABLE_EPSS=true` and the EPSS API is reachable; otherwise absent
  (not fabricated).

## Licensing / Attribution

See `docs/ATTRIBUTION.md`. All MITRE framework content (ATT&CK, CAPEC, CWE,
D3FEND, ATLAS) is used under MITRE's respective terms; CVE2CAPEC-derived
mapping data is used as an upstream data source with attribution.
