"""Typed payloads for live source enrichment."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SourceClass = Literal[
    "dataset_baseline",
    "official_enrichment",
    "external_enrichment",
    "internal",
    "inferred",
]
SourceStatus = Literal["ok", "cached", "fallback", "unavailable", "error"]


class NormalizedEvidence(BaseModel):
    source: str
    source_type: str
    source_class: SourceClass
    source_classification: str
    retrieved_at: str
    source_url: str | None = None
    input: str
    raw_ref: str | None = None
    raw_hash: str | None = None
    cache_path: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    confidence_hint: float = 0.0
    status: SourceStatus = "ok"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceFetchError(RuntimeError):
    def __init__(self, source: str, input_value: str, message: str):
        super().__init__(message)
        self.source = source
        self.input_value = input_value
        self.message = message
