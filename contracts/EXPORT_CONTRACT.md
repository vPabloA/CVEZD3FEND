# EXPORT_CONTRACT

Defines the four required export formats, all driven from the same
deterministic objects (Route, SOC Action Pack, Coverage entry, Node).

## 1. Markdown (`src/CVEzD3FEND/export/markdown.py`)

For a Route or SOC Action Pack, produces a report with sections, in order:

```
# <title>
## Summary
## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)
## Recommended Actions
## Hunting Hypotheses          (SOC Action Pack only)
## Detection Opportunities
## Required Evidence / Logs
## Mitigations
## Gaps
## Sources
```

Each step in "Path" is rendered as `**<id>** — <name> _(confidence: X.XX,
source: <source_id>)_`. Sources section lists `source_id`, `name`, `url`,
`fetched_at`.

## 2. Mermaid (`src/CVEzD3FEND/export/mermaid.py`)

Produces a `graph LR` diagram of a route:

```mermaid
graph LR
  CVE_2026_0544["CVE-2026-0544"] --> CWE_707["CWE-707"]
  CWE_707 --> CAPEC_28["CAPEC-28"]
  CAPEC_28 --> T1027["T1027"]
  T1027 --> D3_FA["D3-FA"]
```

- Node ids are sanitized (`-`, `.` -> `_`) for Mermaid compatibility, original
  id kept as the label.
- Inferred/AI-promoted edges render with a dotted arrow (`-.->`).
- Gap edges render with a `-->|gap|` label.

## 3. JSON (`src/CVEzD3FEND/export/json_export.py`)

Direct serialization of the Route / SOC Action Pack / Coverage entry / Node
object as defined in BUNDLE_CONTRACT — suitable for SIEM/SOAR ingestion.
Always includes `schema_version` and `exported_at`.

## 4. CSV (`src/CVEzD3FEND/export/csv_export.py`)

Tabular export for two shapes:
- **Routes table**: one row per route — `route_id, start_node, end_node, path,
  confidence, coverage_status, canonical, inferred, source_refs`.
- **Coverage table**: one row per ATT&CK technique — `attack_technique,
  defend_techniques, controls, detections, coverage_status, gap_reason,
  confidence`.

## 5. CLI surface

```
CVEzD3FEND export route <ROUTE_ID|CVE_ID> --format md|mermaid|json|csv [-o FILE]
CVEzD3FEND export coverage --format json|csv [-o FILE]
CVEzD3FEND export soc-action-pack <ID> --format md|json [-o FILE]
```

Without `-o`, output is written to stdout (enabling shell pipelines).

## 6. Future / optional

- STIX-like export (`export/stix.py`) is a stub raising
  `NotImplementedError("STIX export is on the roadmap — see docs/PRODUCT_VISION.md")`,
  wired into the CLI behind `--format stix` so the surface area is reserved
  without shipping an unvalidated, half-finished mapping.
