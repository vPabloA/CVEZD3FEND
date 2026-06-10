"""Optional CISA KEV collector. Tolerant of absence (gated by config flag)."""

from __future__ import annotations

import json

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.etl import constants as C
from CVEzD3FEND.etl.http import cache_raw, fetch_url
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.util import now_iso


def fetch_kev(client: httpx.Client, settings: Settings):
    """Returns ``(vulnerabilities, source, warning)``.

    ``vulnerabilities`` is ``[]`` if the collector is disabled or the source
    is unavailable -- never fatal.
    """
    if not settings.enable_kev:
        return [], None, None

    result = fetch_url(client, C.CISA_KEV_URL, settings)
    cache_raw(settings, "cisa_kev.json", result)
    if not result.ok:
        source = Source(
            source_id=C.SOURCE_ID_KEV,
            name="CISA Known Exploited Vulnerabilities Catalog",
            kind="kev",
            url=C.CISA_KEV_URL,
            fetched_at=now_iso(),
            status="unavailable",
            notes=result.error,
        )
        return [], source, f"CISA KEV unavailable (optional): {result.error}"

    data = json.loads(result.content)
    vulns = data.get("vulnerabilities", [])
    source = Source(
        source_id=C.SOURCE_ID_KEV,
        name="CISA Known Exploited Vulnerabilities Catalog",
        kind="kev",
        url=C.CISA_KEV_URL,
        fetched_at=result.fetched_at,
        sha256=result.sha256,
        record_count=len(vulns),
        status="ok",
        metadata={"catalog_version": data.get("catalogVersion")},
    )
    return vulns, source, None
