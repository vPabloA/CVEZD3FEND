"""Mutable build-time graph state: dedup, merge, and helper constructors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from CVEzD3FEND.models.graph import (
    AssertionType,
    ConfidenceBasis,
    Edge,
    EdgeType,
    LifecycleState,
    Node,
    NodeType,
    ResolutionState,
    ScopeState,
)
from CVEzD3FEND.util import edge_id, now_iso


@dataclass
class GraphContext:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    # -- nodes -----------------------------------------------------------
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # Merge: union aliases/external_refs/source_refs/tags; keep the
        # richer description/title if the existing one is empty.
        merged = existing.model_copy(
            update={
                "aliases": _union(existing.aliases, node.aliases),
                "external_refs": _union(existing.external_refs, node.external_refs),
                "source_refs": _union(existing.source_refs, node.source_refs),
                "tags": _union(existing.tags, node.tags),
                "description": existing.description or node.description,
                "title": existing.title or node.title,
                "metadata": {**node.metadata, **existing.metadata},
                "updated_at": now_iso(),
            }
        )
        self.nodes[node.id] = merged
        return merged

    def get_node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    # -- edges -------------------------------------------------------------
    def add_edge(self, edge: Edge) -> Edge:
        if edge.id in self.edges:
            existing = self.edges[edge.id]
            if edge.metadata.get("cross_validated"):
                merged_meta = {**existing.metadata, **edge.metadata}
                merged_evidence = _union(existing.evidence, edge.evidence)[:10]
                existing = existing.model_copy(
                    update={
                        "metadata": merged_meta,
                        "evidence": merged_evidence,
                        "confidence": max(existing.confidence, edge.confidence),
                        "updated_at": now_iso(),
                    }
                )
                self.edges[edge.id] = existing
            return self.edges[edge.id]
        self.edges[edge.id] = edge
        return edge

    def get_edge(self, edge_type: EdgeType, source: str, target: str) -> Edge | None:
        return self.edges.get(edge_id(edge_type.value, source, target))

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def _union(a: list[str], b: list[str]) -> list[str]:
    seen = list(a)
    for item in b:
        if item not in seen:
            seen.append(item)
    return seen


def make_node(
    node_id: str,
    type_: NodeType,
    name: str,
    *,
    title: str = "",
    description: str = "",
    aliases: list[str] | None = None,
    external_refs: list[str] | None = None,
    source_refs: list[str] | None = None,
    tags: list[str] | None = None,
    confidence: float = 1.0,
    canonical: bool = True,
    inferred: bool = False,
    metadata: dict[str, Any] | None = None,
) -> Node:
    ts = now_iso()
    return Node(
        id=node_id,
        type=type_,
        name=name,
        title=title or name,
        description=description,
        aliases=aliases or [],
        external_refs=external_refs or [],
        source_refs=source_refs or [],
        tags=tags or [],
        created_at=ts,
        updated_at=ts,
        confidence=confidence,
        canonical=canonical,
        inferred=inferred,
        metadata=metadata or {},
    )


def make_edge(
    type_: EdgeType,
    source: str,
    target: str,
    *,
    label: str = "",
    confidence: float = 1.0,
    deterministic: bool = True,
    inferred: bool = False,
    source_ref: str | None = None,
    source_url: str | None = None,
    evidence: list[str] | None = None,
    resolution_state: ResolutionState | str = ResolutionState.RESOLVED,
    lifecycle_state: LifecycleState | str = LifecycleState.ACTIVE,
    scope_state: ScopeState | str = ScopeState.INCLUDED,
    assertion_type: AssertionType | str = AssertionType.CANONICAL,
    confidence_basis: ConfidenceBasis | str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Edge:
    ts = now_iso()
    return Edge(
        id=edge_id(type_.value, source, target),
        source=source,
        target=target,
        type=type_,
        label=label,
        confidence=confidence,
        deterministic=deterministic,
        inferred=inferred,
        source_ref=source_ref,
        source_url=source_url,
        evidence=evidence or [],
        resolution_state=resolution_state,
        lifecycle_state=lifecycle_state,
        scope_state=scope_state,
        assertion_type=assertion_type,
        confidence_basis=confidence_basis,
        created_at=ts,
        updated_at=ts,
        metadata=metadata or {},
    )
