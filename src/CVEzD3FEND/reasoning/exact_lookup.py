"""Request-scoped exact CVE lookup over Galeax/CVE2CAPEC year files.

The build pipeline intentionally samples current/previous-year records. This
module is different: it resolves only the CVEs explicitly requested by a user,
for any year encoded in the CVE id, without mutating the canonical bundle.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.etl import constants as C
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.util import now_iso


@dataclass
class ExactLookupResult:
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    sources: list[Source] = field(default_factory=list)
    missing_cves: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class _DownloadResult:
    ok: bool
    path: Path
    url: str
    sha256: str | None = None
    fetched_at: str = field(default_factory=now_iso)
    status_code: int | None = None
    error: str | None = None
    cache_hit: bool = False


class ExactGaleaxLookup:
    """Resolve exact CVE records with bounded, cache-aware streaming I/O."""

    def __init__(
        self,
        settings: Settings,
        client: httpx.Client | None = None,
    ) -> None:
        self.settings = settings
        self._own_client = client is None
        self.client = client or httpx.Client(headers={"User-Agent": "CVEzD3FEND-batch/1.0"})

    def close(self) -> None:
        if self._own_client:
            self.client.close()

    def lookup(self, cve_ids: list[str]) -> ExactLookupResult:
        requested = list(dict.fromkeys(cve_ids))
        by_year: dict[int, list[str]] = {}
        for cve_id in requested:
            year = int(cve_id.split("-", 2)[1])
            by_year.setdefault(year, []).append(cve_id)

        result = ExactLookupResult()
        for year in sorted(by_year):
            year_result = self._lookup_year(year, by_year[year])
            result.records.update(year_result.records)
            result.sources.extend(year_result.sources)
            result.warnings.extend(year_result.warnings)
            result.errors.extend(year_result.errors)

        result.missing_cves = [cve_id for cve_id in requested if cve_id not in result.records]
        return result

    def _lookup_year(self, year: int, requested: list[str]) -> ExactLookupResult:
        wanted = set(requested)
        gz_name = f"CVE-{year}.jsonl.gz"
        jsonl_name = f"CVE-{year}.jsonl"
        gz_url = C.CVE_YEAR_GZ_URL.format(year=year)
        jsonl_url = C.CVE_YEAR_JSONL_URL.format(year=year)

        gz = self._cached_or_download(gz_name, gz_url, year)
        if gz.ok:
            try:
                return self._scan_path(year, wanted, gz, compressed=True, fallback=False)
            except (OSError, EOFError, UnicodeDecodeError) as exc:
                gz.error = f"gzip scan failed: {exc}"

        plain = self._cached_or_download(jsonl_name, jsonl_url, year)
        if plain.ok:
            scanned = self._scan_path(year, wanted, plain, compressed=False, fallback=True)
            if gz.error:
                scanned.warnings.insert(0, f"CVE-{year}: gzip unavailable; used JSONL fallback ({gz.error})")
            return scanned

        error = (
            f"CVE-{year}: exact Galeax lookup unavailable "
            f"(.jsonl.gz: {gz.error or 'unavailable'}; .jsonl: {plain.error or 'unavailable'})"
        )
        source = Source(
            source_id=C.SOURCE_ID_CVE_YEAR.format(year=year),
            name=f"CVE2CAPEC CVE-{year} database",
            kind="cve_year_db_exact_lookup",
            url=gz_url,
            fetched_at=now_iso(),
            version="main",
            sha256=None,
            record_count=0,
            status="unavailable",
            compressed=False,
            metadata={
                "year": year,
                "requested_cves": requested,
                "found_cves": [],
                "records_scanned": 0,
                "request_scoped": True,
            },
            notes=error,
        )
        return ExactLookupResult(sources=[source], missing_cves=requested, errors=[error])

    def _cached_or_download(self, name: str, url: str, year: int) -> _DownloadResult:
        self.settings.sources_dir.mkdir(parents=True, exist_ok=True)
        path = self.settings.sources_dir / name
        if path.is_file():
            meta = self._read_meta(path)
            digest = meta.get("sha256") or self._sha256_path(path)
            return _DownloadResult(
                ok=True,
                path=path,
                url=str(meta.get("url") or url),
                sha256=str(digest),
                fetched_at=str(meta.get("fetched_at") or now_iso()),
                status_code=meta.get("status_code"),
                cache_hit=True,
            )

        temp_path = path.with_suffix(path.suffix + ".tmp")
        digest = hashlib.sha256()
        total = 0
        fetched_at = now_iso()
        try:
            with self.client.stream("GET", url, timeout=self.settings.http_timeout_seconds) as response:
                if response.status_code >= 400:
                    return _DownloadResult(
                        ok=False,
                        path=path,
                        url=url,
                        status_code=response.status_code,
                        fetched_at=fetched_at,
                        error=f"HTTP {response.status_code}",
                    )
                with temp_path.open("wb") as handle:
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > self.settings.http_max_bytes:
                            raise ValueError(f"exceeded max size {self.settings.http_max_bytes} bytes")
                        digest.update(chunk)
                        handle.write(chunk)
            os.replace(temp_path, path)
            sha256 = digest.hexdigest()
            self._write_meta(
                path,
                {
                    "name": name,
                    "url": url,
                    "ok": True,
                    "status_code": 200,
                    "sha256": sha256,
                    "fetched_at": fetched_at,
                    "bytes": total,
                    "year": year,
                    "request_scoped": True,
                },
            )
            return _DownloadResult(
                ok=True,
                path=path,
                url=url,
                sha256=sha256,
                fetched_at=fetched_at,
                status_code=200,
                cache_hit=False,
            )
        except (httpx.HTTPError, OSError, ValueError) as exc:
            temp_path.unlink(missing_ok=True)
            return _DownloadResult(
                ok=False,
                path=path,
                url=url,
                fetched_at=fetched_at,
                error=str(exc),
            )

    def _scan_path(
        self,
        year: int,
        wanted: set[str],
        download: _DownloadResult,
        *,
        compressed: bool,
        fallback: bool,
    ) -> ExactLookupResult:
        found: dict[str, dict[str, Any]] = {}
        records_scanned = 0
        parse_warnings: list[str] = []

        opener = gzip.open if compressed else open
        with opener(download.path, "rt", encoding="utf-8") as handle:  # type: ignore[arg-type]
            records_scanned, found, parse_warnings = self._scan_lines(handle, wanted)

        found_ids = [cve_id for cve_id in wanted if cve_id in found]
        source = Source(
            source_id=C.SOURCE_ID_CVE_YEAR.format(year=year),
            name=f"CVE2CAPEC CVE-{year} database",
            kind="cve_year_db_exact_lookup",
            url=download.url,
            fetched_at=download.fetched_at,
            version="main",
            sha256=download.sha256,
            record_count=records_scanned,
            status="fallback" if fallback else "ok",
            compressed=compressed,
            metadata={
                "year": year,
                "requested_cves": sorted(wanted),
                "found_cves": sorted(found_ids),
                "records_scanned": records_scanned,
                "cache_hit": download.cache_hit,
                "request_scoped": True,
                "stopped_early": len(found) == len(wanted),
            },
        )
        warnings = list(parse_warnings)
        if fallback:
            warnings.append(f"CVE-{year}: used uncompressed JSONL fallback")
        return ExactLookupResult(
            records=found,
            sources=[source],
            missing_cves=[cve_id for cve_id in sorted(wanted) if cve_id not in found],
            warnings=warnings,
        )

    @staticmethod
    def _scan_lines(
        handle: TextIO,
        wanted: set[str],
    ) -> tuple[int, dict[str, dict[str, Any]], list[str]]:
        found: dict[str, dict[str, Any]] = {}
        warnings: list[str] = []
        scanned = 0
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            scanned += 1
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(f"Skipped malformed JSONL line {line_number}: {exc.msg}")
                continue
            if not isinstance(item, dict):
                continue
            for cve_id, payload in item.items():
                normalized = str(cve_id).upper()
                if normalized in wanted and isinstance(payload, dict):
                    found[normalized] = payload
            if len(found) == len(wanted):
                break
        return scanned, found, warnings

    @staticmethod
    def _meta_path(path: Path) -> Path:
        return path.parent / f"{path.name}.meta.json"

    def _read_meta(self, path: Path) -> dict[str, Any]:
        meta_path = self._meta_path(path)
        if not meta_path.is_file():
            return {}
        try:
            value = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write_meta(self, path: Path, value: dict[str, Any]) -> None:
        self._meta_path(path).write_text(json.dumps(value, indent=2), encoding="utf-8")

    @staticmethod
    def _sha256_path(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
