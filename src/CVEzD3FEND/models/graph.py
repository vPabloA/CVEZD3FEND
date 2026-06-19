"""Node/Edge models per contracts/GRAPH_CONTRACT.md.

The enums below are the closed sets defined in GRAPH_CONTRACT §1 and §3.
Adding a value here without updating the contract (and vice versa) is a bug.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    ATTACK = "attack"
    DEFEND = "defend"
    ATLAS = "atlas"
    CONTROL = "control"
    DETECTION = "detection"
    EVIDENCE = "evidence"
    GAP = "gap"
    ASSET = "asset"
    PRODUCT = "product"
    VENDOR = "vendor"
    KEV = "kev"
    EXPLOIT = "exploit"
    MITIGATION = "mitigation"
    PLAYBOOK = "playbook"
    SOC_ACTION = "soc_action"
    CTEM_ACTION = "ctem_action"
    THREAT_HUNT = "threat_hunt"
    DATA_SOURCE = "data_source"
    LOG_SOURCE = "log_source"
    RULE = "rule"
    QUERY = "query"
    CASE = "case"
    NOTE = "note"


class ResolutionState(str, Enum):
    """Whether a referenced id could be resolved. GRAPH_CONTRACT §"Edge-state dimensions"."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


class LifecycleState(str, Enum):
    """Lifecycle of the referenced id in its source framework."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class ScopeState(str, Enum):
    """Whether the edge is in scope for the active trace profile."""

    INCLUDED = "included"
    EXCLUDED = "excluded"
    CONTEXTUAL = "contextual"


class AssertionType(str, Enum):
    """Provenance class of the assertion."""

    CANONICAL = "canonical"
    SOURCE_DERIVED = "source_derived"
    CURATED = "curated"
    INFERRED = "inferred"


class ConfidenceBasis(str, Enum):
    """Why the confidence value holds."""

    EXACT_ID = "exact_id"
    NUMERIC_PADDING = "numeric_padding"
    PARENT_IN_REGISTRY = "parent_in_registry"
    OFFICIAL_MAPPING = "official_mapping"
    UNVERIFIED = "unverified"
    UNRESOLVED = "unresolved"


class EdgeType(str, Enum):
    CVE_HAS_CWE = "cve_has_cwe"
    CWE_MAPS_TO_CAPEC = "cwe_maps_to_capec"
    CAPEC_MAPS_TO_ATTACK = "capec_maps_to_attack"
    ATTACK_MAPS_TO_DEFEND = "attack_maps_to_defend"
    ATTACK_MAPS_TO_ATLAS = "attack_maps_to_atlas"
    DEFEND_MITIGATES_ATTACK = "defend_mitigates_attack"
    CONTROL_IMPLEMENTS_DEFEND = "control_implements_defend"
    DETECTION_DETECTS_ATTACK = "detection_detects_attack"
    EVIDENCE_SUPPORTS_DETECTION = "evidence_supports_detection"
    GAP_BLOCKS_COVERAGE = "gap_blocks_coverage"
    KEV_PRIORITIZES_CVE = "kev_prioritizes_cve"
    EXPLOIT_TARGETS_CVE = "exploit_targets_cve"
    PLAYBOOK_RESPONDS_TO_ATTACK = "playbook_responds_to_attack"
    SOC_ACTION_OPERATIONALIZES_DEFEND = "soc_action_operationalizes_defend"
    CTEM_ACTION_PRIORITIZES_GAP = "ctem_action_prioritizes_gap"
    DATA_SOURCE_ENABLES_DETECTION = "data_source_enables_detection"
    RULE_IMPLEMENTS_DETECTION = "rule_implements_detection"
    QUERY_SUPPORTS_HUNT = "query_supports_hunt"


class Node(BaseModel):
    id: str
    type: NodeType
    name: str
    title: str = ""
    description: str = ""
    aliases: list[str] = Field(default_factory=list)
    external_refs: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    confidence: float = 1.0
    canonical: bool = True
    inferred: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    id: str
    source: str
    target: str
    type: EdgeType
    label: str = ""
    confidence: float = 1.0
    deterministic: bool = True
    inferred: bool = False
    source_ref: str | None = None
    source_url: str | None = None
    evidence: list[str] = Field(default_factory=list)
    resolution_state: ResolutionState = ResolutionState.RESOLVED
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE
    scope_state: ScopeState = ScopeState.INCLUDED
    assertion_type: AssertionType = AssertionType.CANONICAL
    confidence_basis: ConfidenceBasis | None = None
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)
