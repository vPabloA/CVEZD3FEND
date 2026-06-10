"""AI candidate model — see contracts/AI_ASSISTANCE_CONTRACT.md."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ValidationStatus = Literal["pending", "validated", "rejected"]
FinalStatus = Literal["candidate", "validated_candidate", "rejected", "canonical"]


class AICandidate(BaseModel):
    candidate_id: str
    created_at: str
    provider: str
    prompt_hash: str
    input_refs: list[str] = Field(default_factory=list)
    proposed_nodes: list[dict[str, Any]] = Field(default_factory=list)
    proposed_edges: list[dict[str, Any]] = Field(default_factory=list)
    rationale: str
    confidence: float
    validation_status: ValidationStatus = "pending"
    policy_decision: str | None = None
    reviewer: str | None = None
    final_status: FinalStatus = "candidate"
    validation_errors: list[str] = Field(default_factory=list)
