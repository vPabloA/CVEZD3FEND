"""Deterministic defensive intent suggestions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefensiveIntent:
    label: str
    rationale: str
    status: str = "unverified"


def defensive_intents(semantic_tags: list[str]) -> list[DefensiveIntent]:
    tags = set(semantic_tags)
    intents: list[DefensiveIntent] = [
        DefensiveIntent("inventario de activos vulnerables", "Primero hay que identificar activos afectados antes de contener."),
        DefensiveIntent("parcheo o configuración segura", "La respuesta primaria debe reducir la superficie de explotación."),
        DefensiveIntent("restricción de configuración peligrosa", "Muchos abusos surgen por parámetros inseguros o defaults expuestos."),
        DefensiveIntent("aislamiento o filtrado de red", "Si el servicio es expuesto, la contención de tránsito reduce el riesgo."),
        DefensiveIntent("análisis de tráfico", "Correlacionar tráfico ayuda a confirmar explotación o reconnaissance."),
    ]
    if {"rce", "command injection", "shell execution"} & tags:
        intents.append(
            DefensiveIntent(
                "contención de ejecución",
                "Si hay ejecución remota o shell, la contención de procesos debe estar en el plan.",
            )
        )
    return intents
