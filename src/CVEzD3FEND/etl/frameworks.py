"""Collectors for the CVE2CAPEC framework reference resources.

Each function returns ``(data, source_model, warning_or_none)``. ``data`` is
``None`` only for sources that are documented as optional/tolerant-of-absence
(ATLAS DB); CAPEC/CWE/D3FEND DBs are required and a fetch failure is surfaced
via ``status="error"`` on the returned Source (the build records this as a
fatal error in validation).
"""

from __future__ import annotations

import json

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.etl import constants as C
from CVEzD3FEND.etl.http import cache_raw, fetch_url
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.util import now_iso


def _source_from_fetch(
    source_id: str,
    name: str,
    kind: str,
    url: str,
    result,
    record_count: int | None = None,
    notes: str | None = None,
) -> Source:
    return Source(
        source_id=source_id,
        name=name,
        kind=kind,
        url=url,
        fetched_at=result.fetched_at if result.ok else now_iso(),
        version="main",
        sha256=result.sha256 or None,
        record_count=record_count,
        status="ok" if result.ok else "error",
        compressed=False,
        notes=notes if notes else result.error,
    )


def fetch_techniques_association(client: httpx.Client, settings: Settings):
    result = fetch_url(client, C.TECHNIQUES_ASSOCIATION_URL, settings)
    cache_raw(settings, "techniques_association.json", result)
    if not result.ok:
        return (
            {},
            _source_from_fetch(
                C.SOURCE_ID_TECHNIQUES_ASSOCIATION,
                "CVE2CAPEC Techniques Association",
                "techniques_association",
                C.TECHNIQUES_ASSOCIATION_URL,
                result,
            ),
            f"techniques_association.json unavailable: {result.error}",
        )
    data = json.loads(result.content)
    source = _source_from_fetch(
        C.SOURCE_ID_TECHNIQUES_ASSOCIATION,
        "CVE2CAPEC Techniques Association",
        "techniques_association",
        C.TECHNIQUES_ASSOCIATION_URL,
        result,
        record_count=len(data),
    )
    return data, source, None


def fetch_atlas_db(client: httpx.Client, settings: Settings):
    result = fetch_url(client, C.ATLAS_DB_URL, settings)
    cache_raw(settings, "atlas_db.json", result)
    if not result.ok:
        source = _source_from_fetch(
            C.SOURCE_ID_ATLAS_DB,
            "CVE2CAPEC ATLAS DB",
            "atlas_db",
            C.ATLAS_DB_URL,
            result,
        )
        source.status = "unavailable"
        return {}, source, f"atlas_db.json unavailable (optional): {result.error}"
    data = json.loads(result.content)
    source = _source_from_fetch(
        C.SOURCE_ID_ATLAS_DB,
        "CVE2CAPEC ATLAS DB",
        "atlas_db",
        C.ATLAS_DB_URL,
        result,
        record_count=len(data),
    )
    return data, source, None


def fetch_defend_db(client: httpx.Client, settings: Settings):
    result = fetch_url(client, C.DEFEND_DB_URL, settings)
    cache_raw(settings, "defend_db.jsonl", result)
    if not result.ok:
        source = _source_from_fetch(
            C.SOURCE_ID_DEFEND_DB,
            "CVE2CAPEC D3FEND DB",
            "defend_db",
            C.DEFEND_DB_URL,
            result,
        )
        return [], source, f"defend_db.jsonl unavailable (required): {result.error}"
    records = []
    for line in result.content.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    source = _source_from_fetch(
        C.SOURCE_ID_DEFEND_DB,
        "CVE2CAPEC D3FEND DB",
        "defend_db",
        C.DEFEND_DB_URL,
        result,
        record_count=len(records),
    )
    return records, source, None


def fetch_capec_db(client: httpx.Client, settings: Settings):
    result = fetch_url(client, C.CAPEC_DB_URL, settings)
    cache_raw(settings, "capec_db.json", result)
    if not result.ok:
        source = _source_from_fetch(
            C.SOURCE_ID_CAPEC_DB, "CVE2CAPEC CAPEC DB", "capec_db", C.CAPEC_DB_URL, result
        )
        return {}, source, f"capec_db.json unavailable (required): {result.error}"
    data = json.loads(result.content)
    source = _source_from_fetch(
        C.SOURCE_ID_CAPEC_DB,
        "CVE2CAPEC CAPEC DB",
        "capec_db",
        C.CAPEC_DB_URL,
        result,
        record_count=len(data),
    )
    return data, source, None


def fetch_cwe_db(client: httpx.Client, settings: Settings):
    result = fetch_url(client, C.CWE_DB_URL, settings)
    cache_raw(settings, "cwe_db.json", result)
    if not result.ok:
        source = _source_from_fetch(
            C.SOURCE_ID_CWE_DB, "CVE2CAPEC CWE DB", "cwe_db", C.CWE_DB_URL, result
        )
        return {}, source, f"cwe_db.json unavailable (required): {result.error}"
    data = json.loads(result.content)
    source = _source_from_fetch(
        C.SOURCE_ID_CWE_DB,
        "CVE2CAPEC CWE DB",
        "cwe_db",
        C.CWE_DB_URL,
        result,
        record_count=len(data),
    )
    return data, source, None
