"""Stable backend contracts for enrichment and reasoning outputs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ReasoningEdgeClassification = Literal[
    "official_explicit",
    "official_incomplete",
    "dataset_derived",
    "analytical_inferred",
    "conditional",
    "weak_fit",
    "unverified",
]


class HumanReview(BaseModel):
    required: bool = False
    reason: str = ""


class RiskSummary(BaseModel):
    cvss: dict[str, Any] | None = None
    epss: dict[str, Any] | None = None
    kev: dict[str, Any] | None = None
    exploitability: dict[str, Any] | None = None


class RouteContract(BaseModel):
    canonical_chain: list[str] = Field(default_factory=list)
    primary_nodes: list[str] = Field(default_factory=list)
    secondary_nodes: list[str] = Field(default_factory=list)
    conditional_nodes: list[str] = Field(default_factory=list)
    defensive_nodes: list[str] = Field(default_factory=list)
    weak_fit_nodes: list[str] = Field(default_factory=list)


class ReasoningEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    classification: ReasoningEdgeClassification
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    source_url: str | None = None
    note: str | None = None
    deterministic: bool = True
    inferred: bool = False
    conditional: bool = False
    weak_fit: bool = False


class Narrative(BaseModel):
    summary_es: str = ""
    executive_summary_es: str = ""
    decision_context_es: str = ""
    risk_rationale_es: str = ""
    tier1_conclusion_es: str = ""


class SocActionPack(BaseModel):
    validations: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    containment: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    evidence_expected: list[str] = Field(default_factory=list)


class DetectionEngineering(BaseModel):
    hypotheses: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    rule_ideas: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class ThreatHunting(BaseModel):
    hypotheses: list[str] = Field(default_factory=list)
    queries: list[str] = Field(default_factory=list)
    pivot_points: list[str] = Field(default_factory=list)


class Ctem(BaseModel):
    priority: str = ""
    remediation_actions: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    residual_risk: str = ""


class Exports(BaseModel):
    markdown: str = ""
    tree: str = ""
    mermaid: str = ""
    navigator_layer: str | None = None


class EnrichmentProfile(BaseModel):
    description: str = ""
    cwes: list[str] = Field(default_factory=list)
    cvss: dict[str, Any] | None = None
    epss: dict[str, Any] | None = None
    kev: dict[str, Any] | None = None
    affected_products: list[str] = Field(default_factory=list)
    ecosystems: list[str] = Field(default_factory=list)
    semantic_tags: list[str] = Field(default_factory=list)
    source_notes: list[str] = Field(default_factory=list)


class EnrichmentResult(BaseModel):
    input: str
    normalized_input: str
    status: str
    source_mode: str
    baseline_provider: str = "CVE2CAPEC"
    profile: EnrichmentProfile
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    provenance: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class ReasoningResult(BaseModel):
    input: str
    normalized_input: str
    status: str
    source_mode: str
    baseline_provider: str = "CVE2CAPEC"
    reasoning_mode: str
    human_review: HumanReview
    risk: RiskSummary
    route: RouteContract
    edges: list[ReasoningEdge] = Field(default_factory=list)
    provenance: dict[str, list[ReasoningEdge]] = Field(default_factory=dict)
    narrative: Narrative
    soc_action_pack: SocActionPack
    detection_engineering: DetectionEngineering
    threat_hunting: ThreatHunting
    ctem: Ctem
    exports: Exports
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
