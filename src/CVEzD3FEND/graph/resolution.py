"""Phase 2B CAPEC -> ATT&CK mapping resolution."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from CVEzD3FEND.models.graph import ConfidenceBasis, LifecycleState, ResolutionState

TECHNIQUE_STRUCT_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalize_attack_id(raw: str) -> str:
    raw = str(raw).strip().upper()
    if not raw:
        return ""
    if raw.startswith("T"):
        raw = raw[1:].strip()
    if not raw or not raw[0].isdigit():
        return ""
    return f"T{raw}"


@dataclass(frozen=True)
class AttackUniverse:
    techniques: frozenset[str] = frozenset()
    deprecated: frozenset[str] = frozenset()
    revoked: Mapping[str, str] = field(default_factory=dict)
    available: bool = True

    @classmethod
    def empty(cls) -> "AttackUniverse":
        return cls(available=False)

    @classmethod
    def from_techniques_db(
        cls,
        data: Mapping[str, object] | None,
        *,
        extra_ids: Iterable[str] = (),
        deprecated: Iterable[str] = (),
        revoked: Mapping[str, str] | None = None,
    ) -> "AttackUniverse":
        # `available` describes the authoritative ATT&CK registry, not whether
        # auxiliary sources happened to contribute a few technique ids.  When
        # techniques_db is unavailable it is represented as an empty mapping;
        # keeping this distinction preserves the structural-only fallback for
        # every well-formed CAPEC ATT&CK reference instead of treating the
        # auxiliary subset as a complete registry.
        registry_available = bool(data)
        ids = {normalize_attack_id(k) for k in (data or {})}
        ids |= {normalize_attack_id(x) for x in extra_ids}
        ids = {t for t in ids if t}
        ids |= {t.split(".")[0] for t in ids if "." in t}
        if not ids and not registry_available:
            return cls.empty()
        return cls(
            techniques=frozenset(ids),
            deprecated=frozenset(
                t for t in (normalize_attack_id(x) for x in deprecated) if t
            ),
            revoked={
                norm: repl
                for key, repl in (revoked or {}).items()
                if (norm := normalize_attack_id(key))
            },
            available=registry_available,
        )

    def __contains__(self, attack_id: str) -> bool:
        return attack_id in self.techniques


@dataclass(frozen=True)
class MappingResolution:
    raw_id: str
    normalized_candidate: str
    resolution_state: ResolutionState
    lifecycle_state: LifecycleState
    confidence_basis: ConfidenceBasis
    resolution_method: str
    replacement: str | None = None
    note: str = ""

    @property
    def is_mappable(self) -> bool:
        return self.resolution_state == ResolutionState.RESOLVED

    def as_metadata(self) -> dict[str, str]:
        meta = {
            "raw_id": self.raw_id,
            "normalized_candidate": self.normalized_candidate,
            "resolution_method": self.resolution_method,
        }
        if self.replacement:
            meta["replacement"] = self.replacement
        if self.note:
            meta["resolution_note"] = self.note
        return meta


def resolve_attack_id(raw: str, universe: AttackUniverse) -> MappingResolution:
    raw_str = str(raw).strip()
    candidate = normalize_attack_id(raw_str)
    raw_was_prefixed = raw_str.upper().startswith("T")

    if not candidate:
        return MappingResolution(
            raw_id=raw_str,
            normalized_candidate="",
            resolution_state=ResolutionState.INVALID,
            lifecycle_state=LifecycleState.UNKNOWN,
            confidence_basis=ConfidenceBasis.UNRESOLVED,
            resolution_method="non_numeric_taxonomy_entry",
            note="Taxonomy entry contains no ATT&CK technique number.",
        )

    if not TECHNIQUE_STRUCT_RE.match(candidate):
        return MappingResolution(
            raw_id=raw_str,
            normalized_candidate=candidate,
            resolution_state=ResolutionState.INVALID,
            lifecycle_state=LifecycleState.UNKNOWN,
            confidence_basis=ConfidenceBasis.UNRESOLVED,
            resolution_method="legacy_numeric_unmapped",
            note="Structurally invalid ATT&CK id (expected T + 4 digits, optional .3 digits).",
        )

    if candidate in universe.revoked:
        repl = universe.revoked[candidate]
        return MappingResolution(
            raw_id=raw_str,
            normalized_candidate=repl,
            resolution_state=ResolutionState.RESOLVED,
            lifecycle_state=LifecycleState.REVOKED,
            confidence_basis=ConfidenceBasis.EXACT_ID,
            resolution_method="revocation_redirect",
            replacement=repl,
            note=f"{candidate} revoked; redirected to {repl}.",
        )

    if not universe.available:
        return MappingResolution(
            raw_id=raw_str,
            normalized_candidate=candidate,
            resolution_state=ResolutionState.RESOLVED,
            lifecycle_state=LifecycleState.UNKNOWN,
            confidence_basis=ConfidenceBasis.UNVERIFIED,
            resolution_method="structural_only_registry_unavailable",
            note="ATT&CK registry unavailable; membership not verified.",
        )

    if candidate in universe.techniques:
        basis = ConfidenceBasis.EXACT_ID if raw_was_prefixed else ConfidenceBasis.NUMERIC_PADDING
        return MappingResolution(
            raw_id=raw_str,
            normalized_candidate=candidate,
            resolution_state=ResolutionState.RESOLVED,
            lifecycle_state=LifecycleState.ACTIVE,
            confidence_basis=basis,
            resolution_method="registry_exact_match",
        )

    if candidate in universe.deprecated:
        return MappingResolution(
            raw_id=raw_str,
            normalized_candidate=candidate,
            resolution_state=ResolutionState.RESOLVED,
            lifecycle_state=LifecycleState.DEPRECATED,
            confidence_basis=ConfidenceBasis.EXACT_ID,
            resolution_method="registry_deprecated_match",
            note=f"{candidate} is deprecated in the ATT&CK registry.",
        )

    if "." in candidate:
        parent = candidate.split(".")[0]
        if parent in universe.techniques:
            return MappingResolution(
                raw_id=raw_str,
                normalized_candidate=candidate,
                resolution_state=ResolutionState.RESOLVED,
                lifecycle_state=LifecycleState.ACTIVE,
                confidence_basis=ConfidenceBasis.PARENT_IN_REGISTRY,
                resolution_method="subtechnique_parent_match",
                note=f"{candidate} not enumerated in registry, but parent {parent} is known.",
            )

    return MappingResolution(
        raw_id=raw_str,
        normalized_candidate=candidate,
        resolution_state=ResolutionState.UNRESOLVED,
        lifecycle_state=LifecycleState.UNKNOWN,
        confidence_basis=ConfidenceBasis.UNRESOLVED,
        resolution_method="absent_from_registry",
        note=f"{candidate} is well-formed but not present in the ATT&CK registry.",
    )
