"""SOC Action Pack model — see product spec section 14 and docs/ARCHITECTURE.md."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Priority = Literal["Critical", "High", "Medium", "Low", "Info"]


class SocActionPack(BaseModel):
    id: str
    title: str
    executive_summary: str
    technical_summary: str
    attack_path: list[str] = Field(default_factory=list)
    defensive_path: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    hunting_hypotheses: list[str] = Field(default_factory=list)
    detection_opportunities: list[str] = Field(default_factory=list)
    required_logs: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    priority: Priority = "Medium"
    confidence: float = 1.0
    source_refs: list[str] = Field(default_factory=list)
