"""Thin Google Gemini `generateContent` API adapter (AI_ASSISTANCE_CONTRACT §5).

A raw `httpx` client is used instead of the `google-generativeai` SDK to avoid
adding a new dependency (see docs/AI_GOVERNANCE.md). Requires `GEMINI_API_KEY`.
Network calls only happen when explicitly invoked via
`CVEzD3FEND ai generate-candidates --provider gemini`.
"""

from __future__ import annotations

import os

import httpx

from CVEzD3FEND.intelligence.providers.base import ProviderError

DEFAULT_MODEL = "gemini-1.5-flash"
API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider:
    name = "gemini"

    def __init__(self, model: str | None = None):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise ProviderError("GEMINI_API_KEY is not set")
        self.model = model or DEFAULT_MODEL

    def complete(self, system: str, prompt: str) -> str:
        url = f"{API_BASE}/{self.model}:generateContent?key={self.api_key}"
        try:
            resp = httpx.post(
                url,
                json={
                    "system_instruction": {"parts": [{"text": system}]},
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                },
                timeout=60,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderError(f"Gemini API error: {exc}") from exc
        data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)
