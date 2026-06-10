"""Thin Anthropic Messages API adapter (AI_ASSISTANCE_CONTRACT §5).

A raw `httpx` client is used instead of the `anthropic` SDK to avoid adding a
new dependency (see docs/AI_GOVERNANCE.md). Requires `ANTHROPIC_API_KEY`.
Network calls only happen when explicitly invoked via
`CVEzD3FEND ai generate-candidates --provider anthropic`.
"""

from __future__ import annotations

import os

import httpx

from CVEzD3FEND.intelligence.providers.base import ProviderError

DEFAULT_MODEL = "claude-sonnet-4-6"
API_URL = "https://api.anthropic.com/v1/messages"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        self.model = model or DEFAULT_MODEL

    def complete(self, system: str, prompt: str) -> str:
        try:
            resp = httpx.post(
                API_URL,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 512,
                    "system": system,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=60,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderError(f"Anthropic API error: {exc}") from exc
        data = resp.json()
        return "".join(block.get("text", "") for block in data.get("content", []))
