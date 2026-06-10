"""Small shared helpers: timestamps, deterministic ids, slugs."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def edge_id(edge_type: str, source: str, target: str) -> str:
    """Deterministic edge id per GRAPH_CONTRACT §4."""
    digest = hashlib.sha1(f"{edge_type}:{source}->{target}".encode("utf-8")).hexdigest()
    return digest[:16]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = _SLUG_RE.sub("-", text)
    return text.strip("-")


def safe_id_fragment(node_id: str) -> str:
    """Replace characters unsafe in derived ids (slashes, dots) with underscores."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", node_id)
