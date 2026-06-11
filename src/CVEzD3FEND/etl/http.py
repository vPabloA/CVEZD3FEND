"""Bounded HTTP fetcher.

Every download is time-bounded, size-bounded, hashed (sha256), cached to
``data/raw/sources/<name>`` with a ``.meta.json`` sidecar, and never raises on
network failure -- callers receive a ``FetchResult`` with ``ok=False`` and an
``error`` message so the build can record a structured warning and continue
(per docs/DATA_SOURCES.md fallback rules).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.util import now_iso, sha256_bytes


@dataclass
class FetchResult:
    ok: bool
    url: str
    content: bytes = b""
    sha256: str = ""
    status_code: int | None = None
    error: str | None = None
    fetched_at: str = field(default_factory=now_iso)


def fetch_url(
    client: httpx.Client,
    url: str,
    settings: Settings,
    headers: dict[str, str] | None = None,
) -> FetchResult:
    """Fetch ``url`` with timeout + max-size enforcement. Never raises."""
    try:
        with client.stream("GET", url, timeout=settings.http_timeout_seconds, headers=headers) as resp:
            if resp.status_code >= 400:
                return FetchResult(
                    ok=False,
                    url=url,
                    status_code=resp.status_code,
                    error=f"HTTP {resp.status_code}",
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > settings.http_max_bytes:
                    return FetchResult(
                        ok=False,
                        url=url,
                        status_code=resp.status_code,
                        error=f"exceeded max size {settings.http_max_bytes} bytes",
                    )
                chunks.append(chunk)
            content = b"".join(chunks)
            return FetchResult(
                ok=True,
                url=url,
                content=content,
                sha256=sha256_bytes(content),
                status_code=resp.status_code,
            )
    except httpx.HTTPError as exc:
        return FetchResult(ok=False, url=url, error=str(exc))


def cache_raw(settings: Settings, name: str, result: FetchResult, extra_meta: dict | None = None) -> Path:
    """Persist raw bytes + a provenance sidecar under data/raw/sources/."""
    settings.sources_dir.mkdir(parents=True, exist_ok=True)
    raw_path = settings.sources_dir / name
    if result.ok:
        raw_path.write_bytes(result.content)
    meta = {
        "name": name,
        "url": result.url,
        "ok": result.ok,
        "status_code": result.status_code,
        "sha256": result.sha256 or None,
        "fetched_at": result.fetched_at,
        "error": result.error,
        "bytes": len(result.content) if result.ok else 0,
    }
    if extra_meta:
        meta.update(extra_meta)
    meta_path = settings.sources_dir / f"{name}.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return raw_path
