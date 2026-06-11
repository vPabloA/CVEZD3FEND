"""Small text normalizers shared by the source adapters."""

from __future__ import annotations

import re
from typing import Any


_TRAITS: list[tuple[str, re.Pattern[str]]] = [
    ("remote code execution", re.compile(r"\b(remote code execution|arbitrary code execution|code execution|rce)\b", re.I)),
    ("command injection", re.compile(r"\b(command injection|os command(?: execution)?|shell injection)\b", re.I)),
    ("configuration injection", re.compile(r"\b(configuration injection|config(?:uration)? injection)\b", re.I)),
    ("annotation injection", re.compile(r"\bannotation injection\b", re.I)),
    ("authentication bypass", re.compile(r"\b(authentication bypass|auth bypass)\b", re.I)),
    ("authorization bypass", re.compile(r"\b(authorization bypass|authz bypass)\b", re.I)),
    ("ssrf", re.compile(r"\b(server-side request forgery|ssrf)\b", re.I)),
    ("deserialization", re.compile(r"\bdeseriali[sz]ation\b", re.I)),
    ("path traversal", re.compile(r"\b(path traversal|directory traversal)\b", re.I)),
    ("privilege escalation", re.compile(r"\bprivilege escalation\b", re.I)),
    ("secret disclosure", re.compile(r"\b(secret disclosure|sensitive information disclosure|information disclosure)\b", re.I)),
    ("credential exposure", re.compile(r"\b(credential exposure|credentials disclosure)\b", re.I)),
    ("exposed service", re.compile(r"\bexposed service\b", re.I)),
    ("public-facing application", re.compile(r"\b(public[- ]facing application|internet[- ]facing)\b", re.I)),
    ("remote service", re.compile(r"\bremote service\b", re.I)),
    ("container context", re.compile(r"\bcontainer\b", re.I)),
    ("kubernetes context", re.compile(r"\bkubernetes\b", re.I)),
    ("cloud context", re.compile(r"\bcloud\b", re.I)),
    ("control plane impact", re.compile(r"\bcontrol plane\b", re.I)),
    ("post-exploitation execution", re.compile(r"\bpost[- ]exploitation\b", re.I)),
    ("shell execution", re.compile(r"\b(shell execution|spawn shell)\b", re.I)),
    ("data exfiltration potential", re.compile(r"\b(data exfiltration|exfiltrat(?:e|ion))\b", re.I)),
]


def extract_semantic_traits(*parts: str) -> list[str]:
    text = " ".join(part for part in parts if part).strip()
    if not text:
        return []
    traits: list[str] = []
    for label, pattern in _TRAITS:
        if pattern.search(text):
            traits.append(label)
    return traits


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
