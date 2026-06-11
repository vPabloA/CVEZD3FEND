"""Deterministic CAPEC semantic-fit scoring."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapecFit:
    capec_id: str
    fit: float
    reason: str
    weak: bool = False


_SEMANTIC_MATCHES: list[tuple[str, tuple[str, ...], str]] = [
    ("rce", ("remote code execution", "shell execution", "command injection"), "La técnica CAPEC encaja con ejecución remota o shell."),
    ("command_injection", ("command injection", "shell execution"), "La técnica CAPEC puede habilitar inyección de comandos."),
    ("config_injection", ("configuration injection", "annotation injection"), "La técnica CAPEC puede afectar configuración o anotaciones."),
    ("auth_bypass", ("authentication bypass", "authorization bypass"), "La técnica CAPEC apunta a bypass de autenticación/autorización."),
    ("ssrf", ("ssrf",), "La técnica CAPEC se relaciona con SSRF."),
    ("deserialization", ("deserialization",), "La técnica CAPEC se relaciona con deserialización insegura."),
    ("traversal", ("path traversal",), "La técnica CAPEC se relaciona con traversal."),
    ("privilege_escalation", ("privilege escalation",), "La técnica CAPEC puede elevar privilegios."),
    ("secret_disclosure", ("secret disclosure", "credential exposure"), "La técnica CAPEC puede exponer secretos."),
    ("exposed_service", ("exposed service", "public-facing application"), "La técnica CAPEC apunta a superficie expuesta."),
]


def score_capec_fit(capec_id: str, semantic_tags: list[str]) -> CapecFit:
    if not semantic_tags:
        return CapecFit(capec_id=capec_id, fit=0.25, reason="No hay señales semánticas suficientes para un ajuste fuerte.", weak=True)

    score = 0.25
    reasons: list[str] = []
    for tag, tags, rationale in _SEMANTIC_MATCHES:
        if tag in semantic_tags or any(t in semantic_tags for t in tags):
            score += 0.2
            reasons.append(rationale)

    if "kubernetes context" in semantic_tags or "cloud context" in semantic_tags or "container context" in semantic_tags:
        score += 0.1
        reasons.append("El contexto de despliegue refuerza el patrón de abuso.")

    score = min(score, 0.95)
    weak = score < 0.55
    reason = " ".join(reasons) if reasons else "Coincidencia semántica débil; mantener como baseline pero con baja confianza."
    return CapecFit(capec_id=capec_id, fit=round(score, 2), reason=reason, weak=weak)
