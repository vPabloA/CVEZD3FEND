"""Small text normalizers shared by the source adapters."""

from __future__ import annotations

import re
from typing import Any


CANONICAL_SEMANTIC_TAGS: tuple[str, ...] = (
    "rce",
    "command_injection",
    "config_injection",
    "annotation_injection",
    "auth_bypass",
    "ssrf",
    "deserialization",
    "traversal",
    "privilege_escalation",
    "secret_disclosure",
    "credential_exposure",
    "exposed_service",
    "public_facing_application",
    "remote_service",
    "container_context",
    "kubernetes_context",
    "cloud_context",
    "control_plane_impact",
    "post_exploitation_execution",
    "shell_execution",
    "data_exfiltration_potential",
)


_CANONICAL_ALIASES: dict[str, str] = {
    "rce": "rce",
    "remote_code_execution": "rce",
    "arbitrary_code_execution": "rce",
    "code_execution": "rce",
    "command_injection": "command_injection",
    "shell_injection": "command_injection",
    "os_command": "command_injection",
    "os_command_execution": "command_injection",
    "config_injection": "config_injection",
    "configuration_injection": "config_injection",
    "annotation_injection": "annotation_injection",
    "auth_bypass": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "authorization_bypass": "auth_bypass",
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "deserialization": "deserialization",
    "deserialisation": "deserialization",
    "traversal": "traversal",
    "path_traversal": "traversal",
    "directory_traversal": "traversal",
    "privilege_escalation": "privilege_escalation",
    "secret_disclosure": "secret_disclosure",
    "sensitive_information_disclosure": "secret_disclosure",
    "information_disclosure": "secret_disclosure",
    "credential_exposure": "credential_exposure",
    "credentials_disclosure": "credential_exposure",
    "exposed_service": "exposed_service",
    "public_facing_application": "public_facing_application",
    "public_facing_service": "public_facing_application",
    "internet_facing": "public_facing_application",
    "remote_service": "remote_service",
    "container_context": "container_context",
    "container": "container_context",
    "kubernetes_context": "kubernetes_context",
    "kubernetes": "kubernetes_context",
    "cloud_context": "cloud_context",
    "cloud": "cloud_context",
    "control_plane_impact": "control_plane_impact",
    "control_plane": "control_plane_impact",
    "post_exploitation_execution": "post_exploitation_execution",
    "post_exploitation": "post_exploitation_execution",
    "shell_execution": "shell_execution",
    "spawn_shell": "shell_execution",
    "data_exfiltration_potential": "data_exfiltration_potential",
    "data_exfiltration": "data_exfiltration_potential",
    "exfiltration": "data_exfiltration_potential",
}


_TRAITS: list[tuple[str, re.Pattern[str]]] = [
    ("rce", re.compile(r"\b(remote code execution|arbitrary code execution|code execution|rce)\b", re.I)),
    ("command_injection", re.compile(r"\b(command injection|os command(?: execution)?|shell injection)\b", re.I)),
    ("config_injection", re.compile(r"\b(configuration injection|config(?:uration)? injection)\b", re.I)),
    ("annotation_injection", re.compile(r"\bannotation injection\b", re.I)),
    ("auth_bypass", re.compile(r"\b(authentication bypass|auth bypass|authorization bypass|authz bypass)\b", re.I)),
    ("ssrf", re.compile(r"\b(server-side request forgery|ssrf)\b", re.I)),
    ("deserialization", re.compile(r"\bdeseriali[sz]ation\b", re.I)),
    ("traversal", re.compile(r"\b(path traversal|directory traversal)\b", re.I)),
    ("privilege_escalation", re.compile(r"\bprivilege escalation\b", re.I)),
    ("secret_disclosure", re.compile(r"\b(secret disclosure|sensitive information disclosure|information disclosure)\b", re.I)),
    ("credential_exposure", re.compile(r"\b(credential exposure|credentials disclosure)\b", re.I)),
    ("exposed_service", re.compile(r"\bexposed service\b", re.I)),
    ("public_facing_application", re.compile(r"\b(public[- ]facing (?:application|service)|internet[- ]facing)\b", re.I)),
    ("remote_service", re.compile(r"\bremote service\b", re.I)),
    ("container_context", re.compile(r"\bcontainer\b", re.I)),
    ("kubernetes_context", re.compile(r"\bkubernetes\b", re.I)),
    ("cloud_context", re.compile(r"\bcloud\b", re.I)),
    ("control_plane_impact", re.compile(r"\bcontrol plane\b", re.I)),
    ("post_exploitation_execution", re.compile(r"\bpost[- ]exploitation\b", re.I)),
    ("shell_execution", re.compile(r"\b(shell execution|spawn shell)\b", re.I)),
    ("data_exfiltration_potential", re.compile(r"\b(data exfiltration|exfiltrat(?:e|ion))\b", re.I)),
]


def extract_semantic_traits(*parts: str) -> list[str]:
    text = " ".join(part for part in parts if part).strip()
    if not text:
        return []
    traits: list[str] = []
    for label, pattern in _TRAITS:
        if pattern.search(text):
            traits.append(label)
    return canonical_semantic_tags(traits)


def _semantic_tag_key(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "", value.strip().lower().replace("-", "_").replace(" ", "_"))


def canonical_semantic_tag(value: str) -> str | None:
    key = _semantic_tag_key(value)
    if not key:
        return None
    if key in _CANONICAL_ALIASES:
        return _CANONICAL_ALIASES[key]
    if key in CANONICAL_SEMANTIC_TAGS:
        return key
    return None


def canonical_semantic_tags(values: list[str]) -> list[str]:
    canonical: list[str] = []
    for value in values:
        tag = canonical_semantic_tag(value)
        if tag and tag not in canonical:
            canonical.append(tag)
    return canonical


def uniq_preserve(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def summarize_text(value: str | None, limit: int = 240) -> str | None:
    if not value:
        return None
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def best_of(values: list[Any], fallback: Any = None) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return fallback
