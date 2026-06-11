"""SOC/CTEM output shaping for the MVP reasoning plane."""

from __future__ import annotations


def soc_action_pack(semantic_tags: list[str], attack_ids: list[str], defensive_labels: list[str]) -> dict[str, list[str]]:
    return {
        "validations": [
            "Validar exposición real del activo afectado.",
            "Confirmar si el CVE aplica a la versión desplegada.",
            "Corroborar si hay KEV o explotación pública.",
        ],
        "detections": [
            "Buscar patrones de acceso anómalos sobre el servicio afectado.",
            "Correlacionar creación de procesos, entradas web y errores de aplicación.",
            "Pivotar sobre comandos, shells o tráfico de administración si aplica.",
        ],
        "containment": [
            "Reducir exposición del servicio o aislar el activo si es público.",
            "Aplicar parcheo o hardening de configuración con prioridad alta.",
            "Bloquear rutas de acceso y filtrar tráfico sospechoso.",
        ],
        "owners": [
            "SOC Tier 1",
            "Vulnerability Management",
            "Owner de Aplicación",
        ],
        "evidence_expected": [
            "Descripción NVD",
            "EPSS",
            "KEV",
            "Reglas de acceso/proxy",
            "Telemetry de proceso o WAF",
        ],
    }


def detection_engineering(semantic_tags: list[str], attack_ids: list[str]) -> dict[str, list[str]]:
    return {
        "hypotheses": [
            "Si el CVE permite abuso externo, el patrón debe aparecer en logs de acceso y aplicación.",
            "Si hay comandos o shell, el proceso padre/hijo debe reflejar la cadena de ejecución.",
        ],
        "log_sources": [
            "WAF/proxy",
            "Application logs",
            "Endpoint process telemetry",
            "Cloud audit logs",
        ],
        "rule_ideas": [
            "Alertar sobre repetición de requests anómalos hacia endpoints sensibles.",
            "Detectar comandos interactivos o shells derivados de procesos del servicio.",
        ],
        "gaps": [
            "Confirmar cobertura de logs de aplicación y proxy.",
            "Revisar si hay telemetría de proceso suficiente para validar ejecución remota.",
        ],
    }


def threat_hunting(semantic_tags: list[str], attack_ids: list[str]) -> dict[str, list[str]]:
    return {
        "hypotheses": [
            "Buscar indicios de explotación alineados al vector semántico dominante del CVE.",
            "Pivotea por la exposición pública y por cualquier rastro de comandos o shells si aparecen.",
        ],
        "queries": [
            "Filtrar por la URL o endpoint asociado y buscar picos temporales de requests.",
            "Pivotar por proceso padre/hijo y por comandos en el host afectado.",
        ],
        "pivot_points": [
            "Ventana temporal de explotación",
            "Mismo usuario, host o IP origen",
            "Mismo user-agent o ruta HTTP",
        ],
    }


def ctem_plan(semantic_tags: list[str], attack_ids: list[str]) -> dict[str, object]:
    return {
        "priority": "high" if {"rce", "exposed service", "command injection"} & set(semantic_tags) else "medium",
        "remediation_actions": [
            "Corregir la vulnerabilidad o deshabilitar la superficie afectada.",
            "Validar configuración segura y reducir privilegios del servicio.",
            "Aislar o filtrar el camino de explotación si el parche no es inmediato.",
        ],
        "validation_steps": [
            "Confirmar remediación con prueba de versión o configuración.",
            "Verificar que no persista el patrón de tráfico o ejecución anómala.",
        ],
        "residual_risk": "La exposición residual depende de si el activo sigue accesible y de la cobertura de telemetría disponible.",
    }
