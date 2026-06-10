"""Provider protocol shared by all AI/Intelligence backends."""

from __future__ import annotations

from typing import Protocol


class ProviderError(RuntimeError):
    """Raised when a provider cannot be used (missing key, network error, ...)."""


class Provider(Protocol):
    name: str

    def complete(self, system: str, prompt: str) -> str:
        """Return a free-text completion for `prompt` under `system` guidance."""
        ...
