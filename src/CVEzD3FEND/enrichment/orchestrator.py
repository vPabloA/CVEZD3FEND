"""Source orchestration with live fetch, cache fallback and offline baseline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.enrichment.adapters import (
    fetch_attack,
    fetch_atlas,
    fetch_capec,
    fetch_cve2capec,
    fetch_cwe,
    fetch_d3fend,
    fetch_epss,
    fetch_ghsa,
    fetch_kev,
    fetch_nvd,
)
from CVEzD3FEND.enrichment.cache import EvidenceCache
from CVEzD3FEND.enrichment.models import NormalizedEvidence, SourceFetchError
from CVEzD3FEND.util import now_iso


@dataclass(frozen=True)
class OrchestratedResult:
    evidence: NormalizedEvidence
    from_cache: bool = False
    fallback_used: bool = False


class SourceOrchestrator:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self.client = client or httpx.Client(headers={"User-Agent": "CVEzD3FEND-enrichment/1.0"})
        self.cache = EvidenceCache(settings)
        self._adapters: dict[str, Callable[[httpx.Client, Settings, str], NormalizedEvidence]] = {
            "cve2capec": fetch_cve2capec,
            "nvd": fetch_nvd,
            "epss": fetch_epss,
            "ghsa": fetch_ghsa,
            "kev": fetch_kev,
            "attack": fetch_attack,
            "capec": fetch_capec,
            "cwe": fetch_cwe,
            "d3fend": fetch_d3fend,
            "atlas": fetch_atlas,
        }

    def close(self) -> None:
        self.client.close()

    def available(self) -> list[str]:
        return sorted(self._adapters)

    def collect(self, source: str, input_value: str, *, mode: str = "live") -> OrchestratedResult:
        adapter = self._adapters.get(source)
        if adapter is None:
            raise SourceFetchError(source, input_value, f"unknown source '{source}'")

        if mode not in {"live", "cached", "offline"}:
            raise SourceFetchError(source, input_value, f"unsupported mode '{mode}'")

        allow_live = mode == "live"
        allow_cache = mode in {"live", "cached"}

        if allow_live:
            try:
                evidence = adapter(self.client, self.settings, input_value)
            except SourceFetchError as exc:
                cached = self.cache.load(source, input_value) if allow_cache else None
                if cached is not None:
                    warning = f"{source}:{input_value} live fetch failed, cache reused: {exc.message}"
                    cached = cached.model_copy(
                        update={
                            "warnings": [*cached.warnings, warning],
                            "status": "cached",
                            "retrieved_at": now_iso(),
                        }
                    )
                    return OrchestratedResult(evidence=cached, from_cache=True, fallback_used=True)
                baseline = self._baseline(source, input_value, str(exc))
                return OrchestratedResult(evidence=baseline, fallback_used=True)
            cache_path = self.cache.save(evidence)
            evidence = evidence.model_copy(update={"cache_path": str(cache_path)})
            return OrchestratedResult(evidence=evidence)

        cached = self.cache.load(source, input_value) if allow_cache else None
        if cached is not None:
            cached = cached.model_copy(update={"status": "cached", "retrieved_at": now_iso()})
            return OrchestratedResult(evidence=cached, from_cache=True)

        baseline = self._baseline(source, input_value, "cache unavailable")
        return OrchestratedResult(evidence=baseline, fallback_used=True)

    def _baseline(self, source: str, input_value: str, reason: str) -> NormalizedEvidence:
        if source == "cve2capec":
            bundle = self._load_bundle()
            if bundle is not None:
                route_ids = bundle.get("indexes", {}).get("cve_routes", {}).get(input_value, [])
                return NormalizedEvidence(
                    source="cve2capec",
                    source_type="bundle_snapshot",
                    source_class="dataset_baseline",
                    source_classification="offline baseline snapshot",
                    retrieved_at=now_iso(),
                    input=input_value,
                    data={
                        "bundle_version": bundle.get("bundle_version"),
                        "generated_at": bundle.get("generated_at"),
                        "route_ids": route_ids,
                        "note": "Static bundle snapshot used as offline baseline.",
                    },
                    warnings=[reason],
                    status="fallback",
                    metadata={"offline": True},
                )
        return NormalizedEvidence(
            source=source,
            source_type="unknown",
            source_class="dataset_baseline" if source == "cve2capec" else "external_enrichment",
            source_classification="offline fallback",
            retrieved_at=now_iso(),
            input=input_value,
            data={"reason": reason},
            warnings=[reason],
            errors=[reason],
            status="unavailable",
            metadata={"offline": True},
        )

    def _load_bundle(self) -> dict | None:
        path = self.settings.bundle_path
        if not path.exists():
            return None
        try:
            import json

            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
