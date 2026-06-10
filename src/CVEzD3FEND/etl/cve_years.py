"""CVE year database collector with gzip/jsonl fallback.

See contracts/MAPPING_CONTRACT.md (cve_has_cwe) and docs/DATA_SOURCES.md.
"""

from __future__ import annotations

import gzip
import json

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.etl import constants as C
from CVEzD3FEND.etl.http import cache_raw, fetch_url
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.util import now_iso


def resolve_years(settings: Settings) -> list[int]:
    """Current year and previous year, per docs/DATA_SOURCES.md."""
    ref = settings.reference_datetime()
    return [ref.year, ref.year - 1]


def fetch_cve_year(
    client: httpx.Client, settings: Settings, year: int
) -> tuple[list[tuple[str, dict]], Source, str | None]:
    """Returns ``(records, source, warning)``.

    ``records`` is a list of ``(cve_id, payload)`` tuples, where ``payload``
    has the shape ``{"CWE": [...], "CAPEC": [...], "TECHNIQUES": [...], "DEFEND": [...]}``.
    """
    gz_url = C.CVE_YEAR_GZ_URL.format(year=year)
    jsonl_url = C.CVE_YEAR_JSONL_URL.format(year=year)
    source_id = C.SOURCE_ID_CVE_YEAR.format(year=year)

    gz_result = fetch_url(client, gz_url, settings)
    if gz_result.ok:
        cache_raw(settings, f"CVE-{year}.jsonl.gz", gz_result, extra_meta={"year": year})
        try:
            raw_text = gzip.decompress(gz_result.content).decode("utf-8")
        except OSError as exc:
            gz_result.ok = False
            gz_result.error = f"gzip decode failed: {exc}"
        else:
            return _build_records(
                raw_text, source_id, gz_url, gz_result, year, settings,
                compressed=True, fallback=False,
            )

    # Fallback: uncompressed .jsonl
    jsonl_result = fetch_url(client, jsonl_url, settings)
    if jsonl_result.ok:
        cache_raw(settings, f"CVE-{year}.jsonl", jsonl_result, extra_meta={"year": year})
        raw_text = jsonl_result.content.decode("utf-8")
        return _build_records(
            raw_text, source_id, jsonl_url, jsonl_result, year, settings,
            compressed=False, fallback=True,
        )

    # Both failed.
    cache_raw(settings, f"CVE-{year}.jsonl.gz", gz_result, extra_meta={"year": year})
    source = Source(
        source_id=source_id,
        name=f"CVE2CAPEC CVE-{year} database",
        kind="cve_year_db",
        url=gz_url,
        fetched_at=now_iso(),
        version="main",
        sha256=None,
        record_count=0,
        status="unavailable",
        compressed=False,
        metadata={"year": year, "records_processed": 0},
        notes=f".jsonl.gz error: {gz_result.error}; .jsonl error: {jsonl_result.error}",
    )
    return (
        [],
        source,
        f"CVE-{year}: both .jsonl.gz and .jsonl are unavailable "
        f"(.gz: {gz_result.error}; .jsonl: {jsonl_result.error})",
    )


def _build_records(
    raw_text: str,
    source_id: str,
    url: str,
    result,
    year: int,
    settings: Settings,
    *,
    compressed: bool,
    fallback: bool,
) -> tuple[list[tuple[str, dict]], Source, str | None]:
    lines = [line for line in raw_text.splitlines() if line.strip()]
    total = len(lines)
    cap = None if settings.max_cves_per_year == 0 else min(settings.max_cves_per_year, total)
    process_lines = lines if cap is None else lines[:cap]

    records: list[tuple[str, dict]] = []
    for line in process_lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for cve_id, payload in obj.items():
            records.append((cve_id, payload))

    source = Source(
        source_id=source_id,
        name=f"CVE2CAPEC CVE-{year} database",
        kind="cve_year_db",
        url=url,
        fetched_at=result.fetched_at,
        version="main",
        sha256=result.sha256,
        record_count=total,
        status="fallback" if fallback else "ok",
        compressed=compressed,
        metadata={"year": year, "records_processed": len(process_lines)},
    )
    warning = f"CVE-{year}: used uncompressed .jsonl fallback" if fallback else None
    return records, source, warning
