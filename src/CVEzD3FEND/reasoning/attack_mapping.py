"""Conditional ATT&CK mapping heuristics for the MVP slice."""

from __future__ import annotations

from dataclasses import dataclass

from CVEzD3FEND.enrichment.normalizers import canonical_semantic_tags


@dataclass(frozen=True)
class AttackCandidate:
    attack_id: str
    evidence: str
    confidence: float
    classification: str = "conditional"


def attack_candidates(semantic_tags: list[str]) -> list[AttackCandidate]:
    tags = set(canonical_semantic_tags(semantic_tags))
    candidates: list[AttackCandidate] = []

    if {"exposed_service", "public_facing_application", "ssrf"} & tags:
        candidates.append(
            AttackCandidate(
                attack_id="T1190",
                evidence="Contexto de servicio expuesto o web ingress sugiere explotación de servicio expuesto.",
                confidence=0.72,
            )
        )

    if {"remote_service", "container_context", "cloud_context", "kubernetes_context"} & tags:
        candidates.append(
            AttackCandidate(
                attack_id="T1210",
                evidence="Contexto remoto o distribuido sugiere explotación de servicios remotos.",
                confidence=0.63,
            )
        )

    if {"command_injection", "shell_execution", "rce"} & tags:
        candidates.append(
            AttackCandidate(
                attack_id="T1059",
                evidence="La ejecución de comandos o shell es plausible por las señales semánticas.",
                confidence=0.82,
            )
        )
        candidates.append(
            AttackCandidate(
                attack_id="T1059.004",
                evidence="PowerShell es plausible cuando la ejecución de comandos aparece en entornos Windows.",
                confidence=0.54,
            )
        )

    if {"deserialization", "traversal", "privilege_escalation"} & tags:
        candidates.append(
            AttackCandidate(
                attack_id="T1068",
                evidence="Patrones de escalamiento o traversal sugieren abuso de privilegios.",
                confidence=0.45,
            )
        )

    return candidates
