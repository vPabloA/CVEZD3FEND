# Attribution

CVEzD3FEND is a clean-room implementation: no source code from the projects
below is copied. They are credited as conceptual/functional references and, in
the case of CVE2CAPEC, as an upstream **data** source.

## CVE2CAPEC

https://github.com/Galeax/CVE2CAPEC

CVEzD3FEND consumes the following CVE2CAPEC-published data artifacts as raw
sources (see `docs/DATA_SOURCES.md` for exact URLs and usage):

- `resources/techniques_association.json`
- `database/CVE-{year}.jsonl.gz` (and `.jsonl` fallback)
- `resources/atlas_db.json`
- `resources/defend_db.jsonl`
- `resources/capec_db.json`
- `resources/cwe_db.json`

CVE2CAPEC is credited as the upstream that pioneered automated CVE -> CWE ->
CAPEC -> ATT&CK -> D3FEND mapping at the scale this project relies on.

## NSFW

https://github.com/frncscrlnd/nsfw

Credited as the conceptual reference for visual, bidirectional, multi-framework
graph navigation and pivoting UX. No code reused.

## MITRE ATT&CK®

https://attack.mitre.org — © The MITRE Corporation. ATT&CK technique
identifiers and structure referenced under MITRE's ATT&CK terms of use.

## MITRE CAPEC™

https://capec.mitre.org — © The MITRE Corporation. CAPEC identifiers and
attack pattern names referenced under MITRE's CAPEC terms of use.

## MITRE CWE™

https://cwe.mitre.org — © The MITRE Corporation. CWE identifiers referenced
under MITRE's CWE terms of use.

## MITRE D3FEND™

https://d3fend.mitre.org — © The MITRE Corporation. D3FEND technique
identifiers, tactics, and artifacts referenced under MITRE's D3FEND terms of
use.

## MITRE ATLAS™

https://atlas.mitre.org — © The MITRE Corporation / MITRE ATLAS. ATLAS
technique identifiers referenced under MITRE ATLAS terms of use.

## NVD / CISA KEV (optional sources)

- NVD 2.0 API: https://nvd.nist.gov/developers — U.S. government work,
  generally public domain, subject to NVD terms of use.
- CISA Known Exploited Vulnerabilities Catalog:
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog — U.S.
  government work.

## License of this project

See `pyproject.toml` / repository root for this project's own license terms.
Use of the above frameworks' identifiers and structure for defensive,
educational, and security-research purposes is consistent with each
framework's stated terms; this project does not redistribute MITRE's full
corpora, only identifiers/relationships obtained via the CVE2CAPEC derivative
datasets and direct framework references (URLs).
