"""Source URLs and ids — see docs/DATA_SOURCES.md."""

CVE2CAPEC_RAW = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main"

TECHNIQUES_ASSOCIATION_URL = f"{CVE2CAPEC_RAW}/resources/techniques_association.json"
ATLAS_DB_URL = f"{CVE2CAPEC_RAW}/resources/atlas_db.json"
DEFEND_DB_URL = f"{CVE2CAPEC_RAW}/resources/defend_db.jsonl"
CAPEC_DB_URL = f"{CVE2CAPEC_RAW}/resources/capec_db.json"
CWE_DB_URL = f"{CVE2CAPEC_RAW}/resources/cwe_db.json"

CVE_YEAR_GZ_URL = CVE2CAPEC_RAW + "/database/CVE-{year}.jsonl.gz"
CVE_YEAR_JSONL_URL = CVE2CAPEC_RAW + "/database/CVE-{year}.jsonl"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SOURCE_ID_TECHNIQUES_ASSOCIATION = "cve2capec:techniques_association"
SOURCE_ID_ATLAS_DB = "cve2capec:atlas_db"
SOURCE_ID_DEFEND_DB = "cve2capec:defend_db"
SOURCE_ID_CAPEC_DB = "cve2capec:capec_db"
SOURCE_ID_CWE_DB = "cve2capec:cwe_db"
SOURCE_ID_CVE_YEAR = "cve2capec:cve_{year}"
SOURCE_ID_KEV = "cisa:kev"
SOURCE_ID_COVERAGE_ENGINE = "CVEzD3FEND:coverage_engine"

# Canonical reference catalogs used for the operational node types
# (playbook, soc_action, ctem_action, data_source, log_source, rule, query,
# evidence, control, mitigation). See contracts/MAPPING_CONTRACT.md.
SOURCE_ID_CATALOG_PREFIX = "CVEzD3FEND:catalog_"
