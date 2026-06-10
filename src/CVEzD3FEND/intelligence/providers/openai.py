"""Thin OpenAI Chat Completions API adapter (AI_ASSISTANCE_CONTRACT §5).

A raw `httpx` client is used instead of the `openai` SDK to avoid adding a new
dependency (see docs/AI_GOVERNANCE.md). Requires `OPENAI_API_KEY`. Network
calls only happen when explicitly invoked via
`CVEzD3FEND ai generate-candidates --provider openai`.
"""

from __future__ import annotations

import os

import httpx

from CVEzD3FEND.intelligence.providers.base import ProviderError

DEFAULT_MODEL = "gpt-4o-mini"
API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str | None = None):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ProviderError("OPENAI_API_KEY is not set")
        self.model = model or DEFAULT_MODEL

    def complete(self, system: str, prompt: str) -> str:
        try:
            resp = httpx.post(
                API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 512,
                },
                timeout=60,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderError(f"OpenAI API error: {exc}") from exc
        data = resp.json()
        return data["choices"][0]["message"]["content"]
