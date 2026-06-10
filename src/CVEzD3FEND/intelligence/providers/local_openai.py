"""Adapter for local/self-hosted OpenAI-compatible servers (AI_ASSISTANCE_CONTRACT §5).

Targets servers exposing an OpenAI-compatible `/chat/completions` endpoint
(e.g. Ollama, vLLM, LM Studio, llama.cpp server). Configured via
`LOCAL_OPENAI_BASE_URL` (default `http://localhost:11434/v1`, Ollama's
default) and optionally `LOCAL_OPENAI_API_KEY` for servers that require one.
Network calls only happen when explicitly invoked via
`CVEzD3FEND ai generate-candidates --provider local-openai-compatible`.
"""

from __future__ import annotations

import os

import httpx

from CVEzD3FEND.intelligence.providers.base import ProviderError

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_MODEL = "llama3"


class LocalOpenAIProvider:
    name = "local-openai-compatible"

    def __init__(self, model: str | None = None):
        self.base_url = os.environ.get("LOCAL_OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        self.api_key = os.environ.get("LOCAL_OPENAI_API_KEY")
        self.model = model or os.environ.get("LOCAL_OPENAI_MODEL", DEFAULT_MODEL)

    def complete(self, system: str, prompt: str) -> str:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                },
                timeout=120,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderError(f"Local OpenAI-compatible API error: {exc}") from exc
        data = resp.json()
        return data["choices"][0]["message"]["content"]
