"""Spanish narrative rendering for the explain command."""

from __future__ import annotations


def render_spanish_narrative(
    cve_id: str,
    description: str,
    route_text: str,
    risk_text: str,
    provenance_text: str,
    actions_text: str,
) -> dict[str, str]:
    summary = (
        f"{cve_id} se normaliza con la evidencia disponible y, cuando existe, con la ruta base de CVE2CAPEC. "
        f"{description} El mapa de razonamiento conserva señales oficiales, derivadas y condicionales sin mezclar su nivel de certeza.\n\n"
        f"En la ruta priorizada se observa: {route_text}. Esto permite ubicar el problema en una cadena defensiva concreta y no solo en una etiqueta genérica de severidad.\n\n"
        f"El riesgo operacional se resume así: {risk_text}. La lectura de provenance distingue lo explícito de lo inferido para que el analista no trate como oficial lo que aún no lo es.\n\n"
        f"{actions_text} Con ese contexto, la decisión para Tier 1 es confirmar exposición, validar remediación y escalar solo cuando la telemetría o la ruta sugieran explotación real. Para Tier 1 significa actuar rápido, documentar la certeza y no canonizar supuestos."
    )
    executive = (
        f"{cve_id} muestra una superficie que puede requerir contención rápida si la ruta y los indicadores de riesgo se alinean."
    )
    decision_context = "La decisión debe balancear exposición, telemetría y la diferencia entre evidencia oficial y heurística."
    risk_rationale = risk_text
    tier1 = "Confirmar impacto, revisar exposición y elevar a remediación si la ruta sugiere explotación activa."
    return {
        "summary_es": summary,
        "executive_summary_es": executive,
        "decision_context_es": decision_context,
        "risk_rationale_es": risk_rationale,
        "tier1_conclusion_es": tier1,
    }
