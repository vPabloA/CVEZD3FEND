from __future__ import annotations

import gzip
import json
from pathlib import Path

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.reasoning.exact_lookup import ExactGaleaxLookup


def _write_gzip(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_exact_lookup_supports_arbitrary_years_and_stops_when_found(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    _write_gzip(
        settings.sources_dir / "CVE-2019.jsonl.gz",
        [
            {"CVE-2019-0001": {"CWE": ["79"]}},
            {"CVE-2019-9999": {"CWE": ["89"]}},
        ],
    )
    _write_gzip(
        settings.sources_dir / "CVE-2023.jsonl.gz",
        [{"CVE-2023-9999": {"CWE": ["79"]}}],
    )
    _write_gzip(
        settings.sources_dir / "CVE-2026.jsonl.gz",
        [
            {"CVE-2026-0002": {"CWE": ["20"]}},
            {"CVE-2026-9999": {"CWE": ["22"]}},
        ],
    )

    lookup = ExactGaleaxLookup(settings)
    result = lookup.lookup(["CVE-2019-0001", "CVE-2026-0002", "CVE-2023-4040"])
    lookup.close()

    assert set(result.records) == {"CVE-2019-0001", "CVE-2026-0002"}
    assert result.missing_cves == ["CVE-2023-4040"]
    cached_sources = [source for source in result.sources if source.status == "ok"]
    assert {source.metadata["year"] for source in cached_sources} == {2019, 2023, 2026}
    assert all(source.metadata["cache_hit"] is True for source in cached_sources)
    assert all(source.metadata["records_scanned"] == 1 for source in cached_sources)
    assert result.errors == []
    source_2023 = next(source for source in result.sources if source.metadata["year"] == 2023)
    assert source_2023.metadata["records_scanned"] == 1


def test_exact_lookup_downloads_requested_old_year_and_caches_stream(tmp_path):
    payload = gzip.compress(
        (json.dumps({"CVE-2017-1234": {"CWE": ["79"]}}) + "\n").encode("utf-8")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/database/CVE-2017.jsonl.gz")
        return httpx.Response(200, content=payload)

    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    lookup = ExactGaleaxLookup(settings, client=client)
    result = lookup.lookup(["CVE-2017-1234"])
    lookup.close()
    client.close()

    assert result.records["CVE-2017-1234"]["CWE"] == ["79"]
    source = result.sources[0]
    assert source.metadata["year"] == 2017
    assert source.metadata["cache_hit"] is False
    assert source.sha256
    assert (settings.sources_dir / "CVE-2017.jsonl.gz").is_file()
    assert (settings.sources_dir / "CVE-2017.jsonl.gz.meta.json").is_file()


def test_exact_lookup_enforces_download_size_limit(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 64)

    settings = Settings(data_dir=tmp_path, http_max_bytes=16)
    settings.ensure_dirs()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    lookup = ExactGaleaxLookup(settings, client=client)
    result = lookup.lookup(["CVE-2018-1234"])
    lookup.close()
    client.close()

    assert result.records == {}
    assert result.missing_cves == ["CVE-2018-1234"]
    assert any("exceeded max size" in error for error in result.errors)
    assert not (settings.sources_dir / "CVE-2018.jsonl.gz").exists()


def test_exact_lookup_uses_plain_jsonl_fallback_for_corrupt_gzip(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    (settings.sources_dir / "CVE-2021.jsonl.gz").write_bytes(b"not-gzip")
    (settings.sources_dir / "CVE-2021.jsonl").write_text(
        json.dumps({"CVE-2021-1234": {"CWE": ["79"]}}) + "\n",
        encoding="utf-8",
    )

    lookup = ExactGaleaxLookup(settings)
    result = lookup.lookup(["CVE-2021-1234"])
    lookup.close()

    assert "CVE-2021-1234" in result.records
    assert result.sources[0].status == "fallback"
    assert any("JSONL fallback" in warning for warning in result.warnings)
