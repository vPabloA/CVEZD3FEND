"""AI provider factory (AI_ASSISTANCE_CONTRACT §5).

`mock` is the default and requires no network access or API key. The other
providers are thin httpx adapters and are only imported (and only ever make a
network call) when explicitly selected via `CVEZD3FEND_AI_PROVIDER` and
invoked through `CVEzD3FEND ai generate-candidates`.
"""

from __future__ import annotations

from CVEzD3FEND.config import Settings
from CVEzD3FEND.intelligence.providers.base import Provider, ProviderError
from CVEzD3FEND.intelligence.providers.mock import MockProvider

PROVIDER_NAMES = ("mock", "anthropic", "openai", "gemini", "local-openai-compatible")


def get_provider(settings: Settings) -> Provider:
    name = settings.ai_provider

    if name == "mock":
        return MockProvider()
    if name == "anthropic":
        from CVEzD3FEND.intelligence.providers.anthropic import AnthropicProvider

        return AnthropicProvider(settings.ai_model)
    if name == "openai":
        from CVEzD3FEND.intelligence.providers.openai import OpenAIProvider

        return OpenAIProvider(settings.ai_model)
    if name == "gemini":
        from CVEzD3FEND.intelligence.providers.gemini import GeminiProvider

        return GeminiProvider(settings.ai_model)
    if name == "local-openai-compatible":
        from CVEzD3FEND.intelligence.providers.local_openai import LocalOpenAIProvider

        return LocalOpenAIProvider(settings.ai_model)

    raise ProviderError(
        f"Unknown AI provider '{name}'. Valid options: {', '.join(PROVIDER_NAMES)}"
    )
