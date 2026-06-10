"""Deterministic, offline provider — the default (AI_ASSISTANCE_CONTRACT §5).

Used when `CVEZD3FEND_AI_PROVIDER=mock` (the default) and in all tests. Makes
no network calls and requires no API key, so `ai generate-candidates` works
out of the box in any environment.
"""

from __future__ import annotations

import hashlib


class MockProvider:
    name = "mock"

    def complete(self, system: str, prompt: str) -> str:
        digest = hashlib.sha256(f"{system}\n{prompt}".encode("utf-8")).hexdigest()[:12]
        return (
            f"[mock-{digest}] Deterministic offline rationale: no external "
            "model was called. This candidate was derived by analogy to a "
            "structurally similar, already-mapped node. Review the cited "
            "nodes/edges and the proposed edge(s) before validating or "
            "promoting this candidate."
        )
