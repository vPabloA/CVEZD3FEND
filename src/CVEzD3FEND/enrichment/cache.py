"""Deterministic cache for normalized evidence snapshots."""

from __future__ import annotations

import json
from pathlib import Path

from CVEzD3FEND.config import Settings
from CVEzD3FEND.enrichment.models import NormalizedEvidence
from CVEzD3FEND.util import safe_id_fragment, sha256_bytes


class EvidenceCache:
    def __init__(self, settings: Settings):
        self.root = settings.cache_dir / "enrichment"
        self.root.mkdir(parents=True, exist_ok=True)

    def cache_path(self, source: str, input_value: str) -> Path:
        digest = sha256_bytes(f"{source}:{input_value}".encode("utf-8"))[:16]
        return self.root / safe_id_fragment(source) / f"{safe_id_fragment(input_value)}-{digest}.json"

    def load(self, source: str, input_value: str) -> NormalizedEvidence | None:
        path = self.cache_path(source, input_value)
        if not path.exists():
            return None
        try:
            evidence = NormalizedEvidence.model_validate_json(path.read_text(encoding="utf-8"))
            return evidence.model_copy(update={"cache_path": str(path)})
        except Exception:
            return None

    def save(self, evidence: NormalizedEvidence) -> Path:
        path = self.cache_path(evidence.source, evidence.input)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = evidence.model_copy(update={"cache_path": str(path)}).model_dump_json(indent=2)
        path.write_text(payload, encoding="utf-8")
        return path

    def load_or_save(self, evidence: NormalizedEvidence) -> NormalizedEvidence:
        path = self.save(evidence)
        return evidence.model_copy(update={"cache_path": str(path)})
