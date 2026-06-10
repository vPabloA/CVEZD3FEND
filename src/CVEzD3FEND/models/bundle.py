"""Bundle-level models per contracts/BUNDLE_CONTRACT.md and VALIDATION_CONTRACT.md."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from CVEzD3FEND.models.graph import Edge, Node

CoverageStatus = Literal["covered", "partial", "gap", "unknown", "not_applicable"]
SourceStatus = Literal["ok", "fallback", "unavailable", "error"]


class Source(BaseModel):
    source_id: str
    name: str
    kind: str
    url: str | None = None
    fetched_at: str
    version: str | None = None
    sha256: str | None = None
    record_count: int | None = None
    status: SourceStatus = "ok"
    compressed: bool = False
    license: str = "See docs/ATTRIBUTION.md"
    notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Route(BaseModel):
    route_id: str
    start_node: str
    end_node: str
    path: list[str]
    nodes: list[str]
    edges: list[str]
    confidence: float
    canonical: bool
    inferred: bool
    coverage_status: CoverageStatus = "unknown"
    recommended_actions: list[str] = Field(default_factory=list)
    evidence_required: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)


class CoverageTechnique(BaseModel):
    attack_technique: str
    defend_techniques: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    coverage_status: CoverageStatus = "unknown"
    gap_reason: str | None = None
    owner: str | None = None
    last_validated_at: str | None = None
    confidence: float = 1.0


class CoverageSummary(BaseModel):
    covered: int = 0
    partial: int = 0
    gap: int = 0
    unknown: int = 0
    not_applicable: int = 0


class Coverage(BaseModel):
    techniques: list[CoverageTechnique] = Field(default_factory=list)
    summary: CoverageSummary = Field(default_factory=CoverageSummary)


class Warning(BaseModel):
    code: str
    message: str
    context: dict[str, Any] = Field(default_factory=dict)


class QualityReport(BaseModel):
    generated_at: str
    bundle_version: str
    node_counts: dict[str, int] = Field(default_factory=dict)
    edge_counts: dict[str, int] = Field(default_factory=dict)
    routes: dict[str, int] = Field(default_factory=dict)
    gaps: dict[str, Any] = Field(default_factory=dict)
    warnings: list[Warning] = Field(default_factory=list)
    sources: dict[str, Any] = Field(default_factory=dict)
    edges_without_provenance: int = 0
    low_confidence_edges: dict[str, int] = Field(default_factory=dict)
    orphan_nodes: dict[str, Any] = Field(default_factory=dict)
    coverage_summary: dict[str, int] = Field(default_factory=dict)
    ai_candidates: dict[str, Any] = Field(default_factory=dict)
    fatal_errors: list[str] = Field(default_factory=list)


class Bundle(BaseModel):
    bundle_version: str
    generated_at: str
    schema_version: str
    sources: list[Source] = Field(default_factory=list)
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    indexes: dict[str, Any] = Field(default_factory=dict)
    routes: list[Route] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    quality: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    warnings: list[Warning] = Field(default_factory=list)
