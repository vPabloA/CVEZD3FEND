"""Stable backend contracts for enrichment and reasoning outputs."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from CVEzD3FEND.models.graph import Edge, Node

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


class AnalysisContext(BaseModel):
    technologies: list[str] = Field(default_factory=list)
    exposure: list[str] = Field(default_factory=list)
    priorities: list[str] = Field(default_factory=list)
    audience: str = Field(
        default="SOC",
        description=(
            "Presentation and narrative audience only; it does not alter deterministic "
            "scoring or ranking."
        ),
    )

    @field_validator("technologies", "exposure", "priorities", mode="before")
    @classmethod
    def _normalize_context_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [part.strip() for part in value.split(",")]
        if not isinstance(value, list):
            raise ValueError("context values must be a string or list of strings")
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))


class BatchAnalysisRequest(BaseModel):
    cve_ids: list[str]
    context: AnalysisContext = Field(default_factory=AnalysisContext)
    top_k: int = Field(default=10, ge=1, le=100)
    include_all_candidates: bool = Field(
        default=False,
        description=(
            "Include candidate_routes and candidate_graph only when explicitly requested; "
            "Selected remains the safe default."
        ),
    )
    use_ai: bool = False

    @field_validator("cve_ids", mode="before")
    @classmethod
    def _split_cve_inputs(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, (list, tuple, set)):
            values = [str(item) for item in value]
        else:
            raise ValueError("cve_ids must be a string or list of strings")

        tokens: list[str] = []
        for item in values:
            tokens.extend(part for part in re.split(r"[\s,]+", item.strip()) if part)
        return tokens


class RankedRoute(BaseModel):
    route_id: str
    cve_id: str
    cve_ids: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    defend_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    completeness: float = 0.0
    score: float = 0.0
    selection_reasons: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    shared_cve_count: int = 1
    defensive_reuse_count: int = 1
    corroborated_nodes: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    selection_rank: int | None = Field(default=None, ge=1)
    selection_basis: Literal[
        "coverage_floor",
        "contextual_utility",
        "top_k_constraint",
        "ai_rerank",
    ] | None = None


class BatchSelectionSummary(BaseModel):
    eligible_cves: int = 0
    represented_cves: list[str] = Field(default_factory=list)
    unrepresented_cves: list[str] = Field(default_factory=list)
    representation_policy: str = "no_eligible_routes"
    selection_mode: Literal["deterministic", "ai_reranked"] = "deterministic"
    fallback_used: bool = False


class BatchNarrative(BaseModel):
    executive_summary_es: str = ""
    operational_summary_es: str = ""
    technical_summary_es: str = ""


class GraphSlice(BaseModel):
    """A server-authored graph projection; clients must never reconstruct edges."""

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_integrity(self) -> "GraphSlice":
        node_ids = [node.id for node in self.nodes]
        edge_ids = [edge.id for edge in self.edges]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("graph slice contains duplicate node ids")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("graph slice contains duplicate edge ids")
        node_id_set = set(node_ids)
        missing_endpoints = sorted(
            {
                endpoint
                for edge in self.edges
                for endpoint in (edge.source, edge.target)
                if endpoint not in node_id_set
            }
        )
        if missing_endpoints:
            raise ValueError(
                "graph slice edges reference missing nodes: " + ", ".join(missing_endpoints)
            )
        return self


class BatchReasoningResult(BaseModel):
    status: str = "ok"
    requested_cves: list[str] = Field(default_factory=list)
    found_cves: list[str] = Field(default_factory=list)
    missing_cves: list[str] = Field(default_factory=list)
    invalid_inputs: list[str] = Field(default_factory=list)
    available_route_count: int = 0
    selected_route_count: int = 0
    candidate_routes: list[RankedRoute] = Field(default_factory=list)
    selected_routes: list[RankedRoute] = Field(default_factory=list)
    selected_graph: GraphSlice = Field(
        default_factory=GraphSlice,
        description="Complete graph projection for selected_routes; always present.",
    )
    candidate_graph: GraphSlice | None = Field(
        default=None,
        description=(
            "Complete graph projection for candidate_routes when requested. Omission means "
            "the graph was not included in the payload, not that no candidates exist."
        ),
    )
    shared_attack_techniques_selected: list[str] = Field(default_factory=list)
    shared_attack_techniques_all_candidates: list[str] = Field(default_factory=list)
    shared_defenses_selected: list[str] = Field(default_factory=list)
    shared_defenses_all_candidates: list[str] = Field(default_factory=list)
    selection_summary: BatchSelectionSummary = Field(default_factory=BatchSelectionSummary)
    narrative: BatchNarrative = Field(default_factory=BatchNarrative)
    provenance: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    # Temporary compatibility aliases. selected_graph and the *_selected fields
    # are the sole sources of truth for new consumers.
    @computed_field(return_type=list[Node])
    @property
    def nodes(self) -> list[Node]:
        return self.selected_graph.nodes

    @computed_field(return_type=list[Edge])
    @property
    def edges(self) -> list[Edge]:
        return self.selected_graph.edges

    @computed_field(return_type=list[str])
    @property
    def shared_attack_techniques(self) -> list[str]:
        return self.shared_attack_techniques_selected

    @computed_field(return_type=list[str])
    @property
    def shared_defenses(self) -> list[str]:
        return self.shared_defenses_selected
