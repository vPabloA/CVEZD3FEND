"""Canonical reference catalogs used to populate operational node types.

Per contracts/MAPPING_CONTRACT.md, these are deterministic, versioned-with-the-
codebase catalogs (kind="derived_rule", confidence=0.30, `metadata.template =
true`). They are NOT framework-asserted facts -- they are operational
scaffolding an analyst must validate before use, and the UI renders them with
a distinct "template" style (UIX_CONTRACT §4).
"""

from __future__ import annotations

from CVEzD3FEND.util import slugify

# D3FEND tactics (closed set, from defend_db.jsonl).
D3FEND_TACTICS = ["Model", "Detect", "Isolate", "Harden", "Evict", "Restore", "Deceive"]

# One playbook template per D3FEND tactic.
PLAYBOOK_TEMPLATES: dict[str, dict] = {
    "Model": {
        "id": "PB-MODEL",
        "name": "Asset & Configuration Modeling Playbook",
        "description": (
            "Inventory and model the assets, configurations, and access "
            "relationships relevant to this technique before/while responding."
        ),
    },
    "Detect": {
        "id": "PB-DETECT",
        "name": "Detection & Triage Playbook",
        "description": (
            "Triage alerts/telemetry for this technique, confirm scope, and "
            "escalate per severity."
        ),
    },
    "Isolate": {
        "id": "PB-ISOLATE",
        "name": "Containment & Isolation Playbook",
        "description": (
            "Isolate affected hosts/accounts/network segments to limit blast "
            "radius for this technique."
        ),
    },
    "Harden": {
        "id": "PB-HARDEN",
        "name": "Hardening Playbook",
        "description": (
            "Apply configuration/permission hardening that reduces the "
            "attack surface for this technique."
        ),
    },
    "Evict": {
        "id": "PB-EVICT",
        "name": "Eviction Playbook",
        "description": "Remove attacker-controlled artifacts/persistence for this technique.",
    },
    "Restore": {
        "id": "PB-RESTORE",
        "name": "Recovery & Restoration Playbook",
        "description": "Restore affected assets/data to a known-good state after this technique.",
    },
    "Deceive": {
        "id": "PB-DECEIVE",
        "name": "Deception Playbook",
        "description": "Deploy decoys/honeytokens to detect or delay this technique.",
    },
}

# One SOC action template per D3FEND tactic.
SOC_ACTION_TEMPLATES: dict[str, dict] = {
    "Model": {
        "id": "SOC-ACT-MODEL",
        "name": "Maintain asset & configuration inventory",
        "description": "Operationalize D3FEND Model-tactic techniques as continuous inventory tasks.",
    },
    "Detect": {
        "id": "SOC-ACT-DETECT",
        "name": "Operate detections and tune alerting",
        "description": "Operationalize D3FEND Detect-tactic techniques as monitored detections.",
    },
    "Isolate": {
        "id": "SOC-ACT-ISOLATE",
        "name": "Pre-stage containment actions",
        "description": "Operationalize D3FEND Isolate-tactic techniques as ready-to-run containment actions.",
    },
    "Harden": {
        "id": "SOC-ACT-HARDEN",
        "name": "Track hardening baseline compliance",
        "description": "Operationalize D3FEND Harden-tactic techniques as configuration baselines.",
    },
    "Evict": {
        "id": "SOC-ACT-EVICT",
        "name": "Maintain eviction runbooks",
        "description": "Operationalize D3FEND Evict-tactic techniques as eviction runbooks.",
    },
    "Restore": {
        "id": "SOC-ACT-RESTORE",
        "name": "Validate recovery procedures",
        "description": "Operationalize D3FEND Restore-tactic techniques as recovery drills.",
    },
    "Deceive": {
        "id": "SOC-ACT-DECEIVE",
        "name": "Maintain deception assets",
        "description": "Operationalize D3FEND Deceive-tactic techniques as deception infrastructure.",
    },
}


def data_source_for_artifact(artifact: str) -> dict:
    """Deterministic telemetry-class derivation from a D3FEND artifact name."""
    slug = slugify(artifact)
    return {
        "id": f"DS-{slug.upper()}",
        "name": f"{artifact} Telemetry",
        "description": f"Telemetry capturing '{artifact}' activity, as referenced by D3FEND artifacts.",
    }


def log_source_for_artifact(artifact: str) -> dict:
    slug = slugify(artifact)
    return {
        "id": f"LOG-{slug.upper()}",
        "name": f"{artifact} Log",
        "description": f"Log source recording '{artifact}' events, as referenced by D3FEND artifacts.",
    }


GAP_REASON_DESCRIPTIONS: dict[str, str] = {
    "cve_without_cwe": "CVE has no associated CWE in the source dataset.",
    "cwe_without_capec": "CWE has no RelatedAttackPatterns (CAPEC) mapping in cwe_db.",
    "capec_without_attack": "CAPEC has no parsed ATT&CK taxonomy entry in capec_db.",
    "attack_without_defend": "ATT&CK technique has no D3FEND mapping in defend_db.",
    "attack_without_detection": (
        "ATT&CK technique has D3FEND mappings but none with tactic=Detect "
        "(no detection opportunity modeled)."
    ),
}


def attack_external_url(attack_id: str) -> str:
    tech = attack_id[1:] if attack_id.upper().startswith("T") else attack_id
    if "." in tech:
        base, sub = tech.split(".", 1)
        return f"https://attack.mitre.org/techniques/T{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/T{tech}/"


def cwe_external_url(cwe_id: str) -> str:
    num = cwe_id.split("-", 1)[-1]
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def capec_external_url(capec_id: str) -> str:
    num = capec_id.split("-", 1)[-1]
    return f"https://capec.mitre.org/data/definitions/{num}.html"


def d3fend_external_url(technique_name: str) -> str:
    pascal = "".join(part.capitalize() for part in technique_name.replace("-", " ").split())
    return f"https://d3fend.mitre.org/technique/d3f:{pascal}"
