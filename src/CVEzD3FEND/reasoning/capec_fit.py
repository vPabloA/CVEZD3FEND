"""Deterministic CAPEC semantic-fit scoring."""

from __future__ import annotations

from dataclasses import dataclass

from CVEzD3FEND.enrichment.normalizers import canonical_semantic_tags


@dataclass(frozen=True)
class CapecFit:
    capec_id: str
    fit: float
    reason: str
    weak: bool = False


_SEMANTIC_MATCHES: list[tuple[str, tuple[str, ...], str]] = [
    ("rce", ("rce", "shell_execution", "command_injection"), "La técnica CAPEC encaja con ejecución remota o shell."),
    ("command_injection", ("command_injection", "shell_execution"), "La técnica CAPEC puede habilitar inyección de comandos."),
    ("config_injection", ("config_injection", "annotation_injection"), "La técnica CAPEC puede afectar configuración o anotaciones."),
    ("auth_bypass", ("auth_bypass",), "La técnica CAPEC apunta a bypass de autenticación/autorización."),
    ("ssrf", ("ssrf",), "La técnica CAPEC se relaciona con SSRF."),
    ("deserialization", ("deserialization",), "La técnica CAPEC se relaciona con deserialización insegura."),
    ("traversal", ("traversal",), "La técnica CAPEC se relaciona con traversal."),
    ("privilege_escalation", ("privilege escalation",), "La técnica CAPEC puede elevar privilegios."),
    ("secret_disclosure", ("secret_disclosure", "credential_exposure"), "La técnica CAPEC puede exponer secretos."),
    ("exposed_service", ("exposed_service", "public_facing_application"), "La técnica CAPEC apunta a superficie expuesta."),
]


def score_capec_fit(capec_id: str, semantic_tags: list[str]) -> CapecFit:
    semantic_tags = canonical_semantic_tags(semantic_tags)
    if not semantic_tags:
        return CapecFit(capec_id=capec_id, fit=0.25, reason="No hay señales semánticas suficientes para un ajuste fuerte.", weak=True)

    score = 0.25
    reasons: list[str] = []
    for tag, tags, rationale in _SEMANTIC_MATCHES:
        if tag in semantic_tags or any(t in semantic_tags for t in tags):
            score += 0.2
            reasons.append(rationale)

    if {"kubernetes_context", "cloud_context", "container_context"} & set(semantic_tags):
        score += 0.1
        reasons.append("El contexto de despliegue refuerza el patrón de abuso.")

    score = min(score, 0.95)
    weak = score < 0.55
    reason = " ".join(reasons) if reasons else "Coincidencia semántica débil; mantener como baseline pero con baja confianza."
    return CapecFit(capec_id=capec_id, fit=round(score, 2), reason=reason, weak=weak)
