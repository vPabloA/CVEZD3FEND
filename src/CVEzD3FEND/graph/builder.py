"""Graph builder orchestration — implements contracts/MAPPING_CONTRACT.md.

`build_graph()` fetches every required/optional source, then deterministically
constructs nodes and edges. No AI is involved anywhere in this module
(AI_ASSISTANCE_CONTRACT §2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.etl import cve_years, frameworks, kev
from CVEzD3FEND.graph import catalogs
from CVEzD3FEND.graph.context import GraphContext, make_edge, make_node
from CVEzD3FEND.graph.resolution import AttackUniverse, resolve_attack_id
from CVEzD3FEND.models.bundle import Source
from CVEzD3FEND.models.graph import Edge, EdgeType, Node, NodeType
from CVEzD3FEND.util import now_iso, safe_id_fragment

ATTACK_TAXONOMY_RE = re.compile(r"TAXONOMY NAME:ATTACK:ENTRY ID:([\w.]+)")


@dataclass
class BuildResult:
    nodes: list[Node]
    edges: list[Edge]
    sources: list[Source]
    warnings: list[str]


# ---------------------------------------------------------------------------
# Id normalization / placeholder ("ensure") helpers
# ---------------------------------------------------------------------------


def attack_id_from_raw(raw: str) -> str:
    raw = str(raw).strip()
    if raw.upper().startswith("T"):
        return "T" + raw[1:]
    return f"T{raw}"


def cwe_id_from_raw(raw: str) -> str:
    raw = str(raw).strip()
    return raw if raw.upper().startswith("CWE-") else f"CWE-{raw}"


def capec_id_from_raw(raw: str) -> str:
    raw = str(raw).strip()
    return raw if raw.upper().startswith("CAPEC-") else f"CAPEC-{raw}"


def ensure_attack_node(ctx: GraphContext, attack_id: str, source_refs: list[str]) -> Node:
    existing = ctx.get_node(attack_id)
    if existing:
        return existing
    return ctx.add_node(
        make_node(
            attack_id,
            NodeType.ATTACK,
            attack_id,
            description=f"MITRE ATT&CK technique {attack_id}.",
            external_refs=[catalogs.attack_external_url(attack_id)],
            source_refs=source_refs,
            confidence=1.0,
        )
    )


def ensure_cwe_node(ctx: GraphContext, cwe_id: str, source_refs: list[str]) -> Node:
    existing = ctx.get_node(cwe_id)
    if existing:
        return existing
    return ctx.add_node(
        make_node(
            cwe_id,
            NodeType.CWE,
            cwe_id,
            description=f"MITRE {cwe_id}. See {catalogs.cwe_external_url(cwe_id)} for the full definition.",
            external_refs=[catalogs.cwe_external_url(cwe_id)],
            source_refs=source_refs,
            confidence=0.6,
        )
    )


def ensure_capec_node(ctx: GraphContext, capec_id: str, source_refs: list[str]) -> Node:
    existing = ctx.get_node(capec_id)
    if existing:
        return existing
    return ctx.add_node(
        make_node(
            capec_id,
            NodeType.CAPEC,
            capec_id,
            description=f"CAPEC attack pattern {capec_id}.",
            external_refs=[catalogs.capec_external_url(capec_id)],
            source_refs=source_refs,
            confidence=0.6,
        )
    )


def mark_cross_validated(ctx: GraphContext, edge: Edge, cve_id: str) -> None:
    evidence = list(edge.evidence)
    if cve_id not in evidence and len(evidence) < 10:
        evidence.append(cve_id)
    new_conf = edge.confidence
    if edge.type == EdgeType.CAPEC_MAPS_TO_ATTACK and new_conf < 0.95:
        new_conf = round(min(1.0, new_conf + 0.1), 2)
    ctx.edges[edge.id] = edge.model_copy(
        update={
            "metadata": {**edge.metadata, "cross_validated": True},
            "evidence": evidence,
            "confidence": new_conf,
            "updated_at": now_iso(),
        }
    )


# ---------------------------------------------------------------------------
# Per-source ingestion
# ---------------------------------------------------------------------------


def build_attack_universe(
    techniques_db: dict | None,
    defend_records: list[dict] | None,
    atlas_data: dict | None,
    techniques_association: dict | None,
) -> AttackUniverse:
    """Build the ATT&CK universe used to resolve CAPEC taxonomy ids."""

    extra: list[str] = []
    for rec in defend_records or []:
        extra.extend(rec.keys())
    extra.extend((atlas_data or {}).keys())
    extra.extend((techniques_association or {}).keys())
    return AttackUniverse.from_techniques_db(techniques_db or {}, extra_ids=extra)


def add_capec_db(ctx: GraphContext, data: dict, source: Source, universe: AttackUniverse | None = None) -> None:
    universe = universe or AttackUniverse.empty()
    for capec_num, info in data.items():
        capec_id = capec_id_from_raw(capec_num)
        name = (info.get("name") or "").strip()
        techniques_raw = info.get("techniques") or ""

        resolved: list[tuple[str, object, str]] = []
        unresolved: list[dict[str, str]] = []
        for m in ATTACK_TAXONOMY_RE.finditer(techniques_raw):
            resolution = resolve_attack_id(m.group(1), universe)
            if resolution.is_mappable:
                resolved.append((resolution.normalized_candidate, resolution, m.group(0)))
            else:
                unresolved.append(
                    {
                        "raw_id": resolution.raw_id,
                        "normalized_candidate": resolution.normalized_candidate,
                        "resolution_state": resolution.resolution_state.value,
                        "resolution_method": resolution.resolution_method,
                    }
                )

        metadata: dict = {}
        if techniques_raw:
            metadata["raw_techniques"] = techniques_raw
        if unresolved:
            metadata["unresolved_attack_refs"] = unresolved
            ctx.warn(
                f"{capec_id}: {len(unresolved)} ATT&CK taxonomy entr"
                f"{'y' if len(unresolved) == 1 else 'ies'} unresolved "
                f"({', '.join(u['raw_id'] for u in unresolved)})"
            )

        ctx.add_node(
            make_node(
                capec_id,
                NodeType.CAPEC,
                name or capec_id,
                title=f"{capec_id}: {name}" if name else capec_id,
                description=(
                    f"CAPEC attack pattern {capec_id}" + (f": {name}." if name else ".")
                ),
                external_refs=[catalogs.capec_external_url(capec_id)],
                source_refs=[source.source_id],
                confidence=1.0,
                metadata=metadata,
            )
        )
        for attack_id, resolution, evidence in resolved:
            ensure_attack_node(ctx, attack_id, [source.source_id])
            ctx.add_edge(
                make_edge(
                    EdgeType.CAPEC_MAPS_TO_ATTACK,
                    capec_id,
                    attack_id,
                    confidence=0.85,
                    source_ref=source.source_id,
                    source_url=source.url,
                    evidence=[evidence],
                    resolution_state=resolution.resolution_state.value,
                    lifecycle_state=resolution.lifecycle_state.value,
                    confidence_basis=resolution.confidence_basis.value,
                    metadata=resolution.as_metadata(),
                )
            )


def add_cwe_db(ctx: GraphContext, data: dict, source: Source) -> None:
    for cwe_num, info in data.items():
        cwe_id = cwe_id_from_raw(cwe_num)
        child_of = [cwe_id_from_raw(c) for c in info.get("ChildOf", [])]
        ctx.add_node(
            make_node(
                cwe_id,
                NodeType.CWE,
                cwe_id,
                description=(
                    f"MITRE {cwe_id}. See {catalogs.cwe_external_url(cwe_id)} for the full definition."
                ),
                external_refs=[catalogs.cwe_external_url(cwe_id)],
                source_refs=[source.source_id],
                confidence=1.0,
                metadata={"child_of": child_of} if child_of else {},
            )
        )
        for capec_num in info.get("RelatedAttackPatterns", []) or []:
            capec_id = capec_id_from_raw(capec_num)
            ensure_capec_node(ctx, capec_id, [source.source_id])
            ctx.add_edge(
                make_edge(
                    EdgeType.CWE_MAPS_TO_CAPEC,
                    cwe_id,
                    capec_id,
                    confidence=1.0,
                    source_ref=source.source_id,
                    source_url=source.url,
                    evidence=[f"cwe_db.json: {cwe_id}.RelatedAttackPatterns includes {capec_num}"],
                )
            )


def add_techniques_association(ctx: GraphContext, data: dict, source: Source) -> None:
    for raw_id, assoc in data.items():
        attack_id = attack_id_from_raw(raw_id)
        aliases: list[str] = []
        mobile = assoc.get("mobile")
        ics = assoc.get("ics")
        if mobile:
            aliases.append(f"ATTACK-MOBILE-T{mobile}")
        if ics:
            aliases.append(f"ATTACK-ICS-T{ics}")
        node = ensure_attack_node(ctx, attack_id, [source.source_id])
        if aliases:
            ctx.add_node(
                node.model_copy(
                    update={
                        "aliases": list(dict.fromkeys([*node.aliases, *aliases])),
                        "source_refs": list(dict.fromkeys([*node.source_refs, source.source_id])),
                    }
                )
            )


def add_atlas_db(ctx: GraphContext, data: dict, source: Source) -> None:
    for raw_attack_id, atlas_list in data.items():
        attack_id = attack_id_from_raw(raw_attack_id)
        ensure_attack_node(ctx, attack_id, [source.source_id])
        for entry in atlas_list:
            atlas_id = entry.get("id")
            if not atlas_id:
                continue
            ctx.add_node(
                make_node(
                    atlas_id,
                    NodeType.ATLAS,
                    entry.get("name", atlas_id),
                    description=f"MITRE ATLAS technique {atlas_id}: {entry.get('name', '')}.",
                    external_refs=[entry["url"]] if entry.get("url") else [],
                    source_refs=[source.source_id],
                    confidence=1.0,
                    metadata={"tactics": entry.get("tactics", [])},
                )
            )
            ctx.add_edge(
                make_edge(
                    EdgeType.ATTACK_MAPS_TO_ATLAS,
                    attack_id,
                    atlas_id,
                    confidence=1.0,
                    source_ref=source.source_id,
                    source_url=source.url,
                )
            )


def add_defend_db(ctx: GraphContext, records: list[dict], source: Source) -> None:
    defend_technique_name: dict[str, str] = {}
    defend_tactic: dict[str, str] = {}
    defend_artifacts: dict[str, set[str]] = {}
    pairs_seen: set[tuple[str, str]] = set()

    for rec in records:
        for raw_attack_id, entries in rec.items():
            attack_id = attack_id_from_raw(raw_attack_id)
            ensure_attack_node(ctx, attack_id, [source.source_id])
            for e in entries:
                d3_id = e.get("id")
                tactic = e.get("tactic")
                technique = e.get("technique", d3_id)
                artifact = e.get("artifact", "Unknown")
                if not d3_id or not tactic:
                    continue
                defend_technique_name[d3_id] = technique
                defend_tactic[d3_id] = tactic
                defend_artifacts.setdefault(d3_id, set()).add(artifact)

                ctx.add_edge(
                    make_edge(
                        EdgeType.ATTACK_MAPS_TO_DEFEND,
                        attack_id,
                        d3_id,
                        confidence=1.0,
                        source_ref=source.source_id,
                        source_url=source.url,
                        metadata={"tactic": tactic, "artifact": artifact},
                    )
                )

                pair = (attack_id, d3_id)
                if pair in pairs_seen:
                    continue
                pairs_seen.add(pair)

                if tactic == "Detect":
                    _add_detection_chain(ctx, attack_id, d3_id, technique, artifact, source)
                else:
                    ctx.add_edge(
                        make_edge(
                            EdgeType.DEFEND_MITIGATES_ATTACK,
                            d3_id,
                            attack_id,
                            confidence=1.0,
                            source_ref=source.source_id,
                            source_url=source.url,
                            metadata={"tactic": tactic},
                        )
                    )

    # Defend / control / mitigation nodes (one per distinct D3FEND technique id).
    for d3_id, technique in defend_technique_name.items():
        tactic = defend_tactic[d3_id]
        ctx.add_node(
            make_node(
                d3_id,
                NodeType.DEFEND,
                technique,
                description=f"MITRE D3FEND technique {d3_id}: {technique} (tactic: {tactic}).",
                external_refs=[catalogs.d3fend_external_url(technique)],
                source_refs=[source.source_id],
                confidence=1.0,
                metadata={"tactic": tactic, "artifacts": sorted(defend_artifacts[d3_id])},
            )
        )
        ctrl_id = f"CTRL-{d3_id}"
        ctx.add_node(
            make_node(
                ctrl_id,
                NodeType.CONTROL,
                f"Control: {technique}",
                description=f"Operational control implementing D3FEND {d3_id} ({technique}).",
                source_refs=[source.source_id],
                confidence=1.0,
                metadata={"derivation": "one_per_defend_technique", "defend": d3_id},
            )
        )
        ctx.add_edge(
            make_edge(
                EdgeType.CONTROL_IMPLEMENTS_DEFEND,
                ctrl_id,
                d3_id,
                confidence=1.0,
                source_ref=source.source_id,
                source_url=source.url,
                metadata={"derivation": "one_per_defend_technique"},
            )
        )
        if tactic != "Detect":
            mit_id = f"MIT-{d3_id}"
            ctx.add_node(
                make_node(
                    mit_id,
                    NodeType.MITIGATION,
                    f"Mitigation: {technique}",
                    description=f"Mitigation operationalizing D3FEND {d3_id} ({technique}).",
                    source_refs=[source.source_id],
                    confidence=1.0,
                    metadata={"derivation": "one_per_non_detect_defend_technique", "defend": d3_id},
                )
            )
            ctx.add_edge(
                make_edge(
                    EdgeType.CONTROL_IMPLEMENTS_DEFEND,
                    mit_id,
                    d3_id,
                    confidence=1.0,
                    source_ref=source.source_id,
                    source_url=source.url,
                    metadata={"derivation": "one_per_non_detect_defend_technique"},
                )
            )


def _add_detection_chain(
    ctx: GraphContext, attack_id: str, d3_id: str, technique: str, artifact: str, source: Source
) -> None:
    detection_id = f"DET-{safe_id_fragment(attack_id)}-{safe_id_fragment(d3_id)}"
    ctx.add_node(
        make_node(
            detection_id,
            NodeType.DETECTION,
            f"Detection: {technique} for {attack_id}",
            description=(
                f"Detection opportunity for {attack_id} using D3FEND {d3_id} "
                f"({technique}); artifact: {artifact}."
            ),
            source_refs=[source.source_id],
            confidence=1.0,
            metadata={"attack": attack_id, "defend": d3_id, "artifact": artifact},
        )
    )
    ctx.add_edge(
        make_edge(
            EdgeType.DETECTION_DETECTS_ATTACK,
            detection_id,
            attack_id,
            confidence=1.0,
            source_ref=source.source_id,
            source_url=source.url,
        )
    )

    evidence_id = f"EVID-{detection_id}"
    ctx.add_node(
        make_node(
            evidence_id,
            NodeType.EVIDENCE,
            f"Evidence: {artifact} for {attack_id} / {d3_id}",
            description=f"Evidence artifact ('{artifact}') required to validate {detection_id}.",
            source_refs=[source.source_id],
            confidence=0.85,
            metadata={"artifact": artifact, "detection": detection_id},
        )
    )
    ctx.add_edge(
        make_edge(
            EdgeType.EVIDENCE_SUPPORTS_DETECTION,
            evidence_id,
            detection_id,
            confidence=0.85,
            source_ref=source.source_id,
            source_url=source.url,
        )
    )

    rule_id = f"RULE-{detection_id}"
    ctx.add_node(
        make_node(
            rule_id,
            NodeType.RULE,
            f"Rule draft: {technique} ({attack_id})",
            description=(
                f"Draft detection rule implementing {detection_id}. "
                "Template only — validate against your environment before deployment."
            ),
            source_refs=["CVEzD3FEND:catalog_rule_templates"],
            confidence=0.30,
            metadata={"template": True, "detection": detection_id},
        )
    )
    ctx.add_edge(
        make_edge(
            EdgeType.RULE_IMPLEMENTS_DETECTION,
            rule_id,
            detection_id,
            confidence=0.30,
            source_ref="CVEzD3FEND:catalog_rule_templates",
            metadata={"template": True, "derivation": "canonical_reference_catalog"},
        )
    )

    ds = catalogs.data_source_for_artifact(artifact)
    ctx.add_node(
        make_node(
            ds["id"],
            NodeType.DATA_SOURCE,
            ds["name"],
            description=ds["description"],
            source_refs=["CVEzD3FEND:catalog_data_sources"],
            confidence=0.30,
            metadata={"template": True, "derivation": "artifact_to_telemetry_template", "artifact": artifact},
        )
    )
    ctx.add_edge(
        make_edge(
            EdgeType.DATA_SOURCE_ENABLES_DETECTION,
            ds["id"],
            detection_id,
            confidence=0.30,
            source_ref="CVEzD3FEND:catalog_data_sources",
            metadata={"template": True, "derivation": "canonical_reference_catalog"},
        )
    )

    log = catalogs.log_source_for_artifact(artifact)
    ctx.add_node(
        make_node(
            log["id"],
            NodeType.LOG_SOURCE,
            log["name"],
            description=log["description"],
            source_refs=["CVEzD3FEND:catalog_log_sources"],
            confidence=0.30,
            metadata={"template": True, "derivation": "artifact_to_telemetry_template", "artifact": artifact},
        )
    )
    ctx.add_edge(
        make_edge(
            EdgeType.DATA_SOURCE_ENABLES_DETECTION,
            log["id"],
            detection_id,
            confidence=0.30,
            source_ref="CVEzD3FEND:catalog_log_sources",
            metadata={"template": True, "derivation": "canonical_reference_catalog"},
        )
    )


def add_cve_records(ctx: GraphContext, year: int, records: list[tuple[str, dict]], source: Source) -> None:
    for cve_id, payload in records:
        cwes = [cwe_id_from_raw(c) for c in payload.get("CWE", []) or []]
        capecs = [capec_id_from_raw(c) for c in payload.get("CAPEC", []) or []]
        techniques = [attack_id_from_raw(t) for t in payload.get("TECHNIQUES", []) or []]
        defends = [
            d.get("id") for d in (payload.get("DEFEND", []) or []) if isinstance(d, dict) and d.get("id")
        ]

        existing = ctx.get_node(cve_id)
        years_meta = set(existing.metadata.get("years", [])) if existing else set()
        years_meta.add(year)

        ctx.add_node(
            make_node(
                cve_id,
                NodeType.CVE,
                cve_id,
                description=f"{cve_id} — entry from the CVE2CAPEC {year} dataset.",
                external_refs=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                source_refs=[source.source_id],
                confidence=1.0,
                metadata={
                    "years": sorted(years_meta),
                    "reported_cwe": payload.get("CWE", []),
                    "reported_capec": payload.get("CAPEC", []),
                    "reported_techniques": payload.get("TECHNIQUES", []),
                    "reported_defend": defends,
                },
            )
        )

        for cwe_id in cwes:
            ensure_cwe_node(ctx, cwe_id, [source.source_id])
            ctx.add_edge(
                make_edge(
                    EdgeType.CVE_HAS_CWE,
                    cve_id,
                    cwe_id,
                    confidence=1.0,
                    source_ref=source.source_id,
                    source_url=source.url,
                )
            )

        for cwe_id in cwes:
            for capec_id in capecs:
                e = ctx.get_edge(EdgeType.CWE_MAPS_TO_CAPEC, cwe_id, capec_id)
                if e:
                    mark_cross_validated(ctx, e, cve_id)

        for capec_id in capecs:
            for attack_id in techniques:
                e = ctx.get_edge(EdgeType.CAPEC_MAPS_TO_ATTACK, capec_id, attack_id)
                if e:
                    mark_cross_validated(ctx, e, cve_id)

        for attack_id in techniques:
            for d3_id in defends:
                e = ctx.get_edge(EdgeType.ATTACK_MAPS_TO_DEFEND, attack_id, d3_id)
                if e:
                    mark_cross_validated(ctx, e, cve_id)


def add_playbooks_and_soc_actions(ctx: GraphContext) -> None:
    attack_tactics: dict[str, set[str]] = {}
    tactic_defends: dict[str, set[str]] = {}
    for e in ctx.edges.values():
        if e.type == EdgeType.ATTACK_MAPS_TO_DEFEND:
            tactic = e.metadata.get("tactic")
            if not tactic:
                continue
            attack_tactics.setdefault(e.source, set()).add(tactic)
            tactic_defends.setdefault(tactic, set()).add(e.target)

    for tactic, tmpl in catalogs.PLAYBOOK_TEMPLATES.items():
        ctx.add_node(
            make_node(
                tmpl["id"],
                NodeType.PLAYBOOK,
                tmpl["name"],
                description=tmpl["description"],
                source_refs=["CVEzD3FEND:catalog_playbooks"],
                confidence=0.30,
                metadata={"template": True, "tactic": tactic},
            )
        )

    for tactic, tmpl in catalogs.SOC_ACTION_TEMPLATES.items():
        ctx.add_node(
            make_node(
                tmpl["id"],
                NodeType.SOC_ACTION,
                tmpl["name"],
                description=tmpl["description"],
                source_refs=["CVEzD3FEND:catalog_soc_actions"],
                confidence=0.30,
                metadata={"template": True, "tactic": tactic},
            )
        )
        for d3_id in sorted(tactic_defends.get(tactic, [])):
            ctx.add_edge(
                make_edge(
                    EdgeType.SOC_ACTION_OPERATIONALIZES_DEFEND,
                    tmpl["id"],
                    d3_id,
                    confidence=0.30,
                    source_ref="CVEzD3FEND:catalog_soc_actions",
                    metadata={"template": True, "derivation": "canonical_reference_catalog"},
                )
            )

    for attack_id, tactics in attack_tactics.items():
        for tactic in tactics:
            tmpl = catalogs.PLAYBOOK_TEMPLATES.get(tactic)
            if not tmpl:
                continue
            ctx.add_edge(
                make_edge(
                    EdgeType.PLAYBOOK_RESPONDS_TO_ATTACK,
                    tmpl["id"],
                    attack_id,
                    confidence=0.30,
                    source_ref="CVEzD3FEND:catalog_playbooks",
                    metadata={"template": True, "derivation": "canonical_reference_catalog"},
                )
            )


def add_threat_hunts(ctx: GraphContext) -> None:
    for node_id, node in list(ctx.nodes.items()):
        if node.type != NodeType.ATTACK:
            continue
        safe = safe_id_fragment(node_id)
        hunt_id = f"HUNT-{safe}"
        query_id = f"QUERY-{safe}"
        ctx.add_node(
            make_node(
                hunt_id,
                NodeType.THREAT_HUNT,
                f"Hunt hypothesis: {node_id}",
                description=(
                    f"Hunting hypothesis for {node_id}: search available telemetry for "
                    "behaviors consistent with this technique, even absent an alert."
                ),
                source_refs=["CVEzD3FEND:catalog_threat_hunts"],
                confidence=0.30,
                metadata={"template": True, "attack": node_id},
            )
        )
        ctx.add_node(
            make_node(
                query_id,
                NodeType.QUERY,
                f"Hunt query draft: {node_id}",
                description=(
                    f"Draft hunting query for {node_id}. Template only — adapt field "
                    "names to your data platform."
                ),
                source_refs=["CVEzD3FEND:catalog_queries"],
                confidence=0.30,
                metadata={"template": True, "attack": node_id},
            )
        )
        ctx.add_edge(
            make_edge(
                EdgeType.QUERY_SUPPORTS_HUNT,
                query_id,
                hunt_id,
                confidence=0.30,
                source_ref="CVEzD3FEND:catalog_queries",
                metadata={"template": True, "derivation": "canonical_reference_catalog"},
            )
        )


def add_kev(ctx: GraphContext, vulns: list[dict], source: Source | None) -> None:
    if not source:
        return
    for v in vulns:
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        cve_node = ctx.get_node(cve_id)
        if cve_node is None:
            # Only attach KEV info to CVEs already present in the bundle
            # (per MAX_CVES_PER_YEAR sampling) — avoids unbounded growth.
            continue
        kev_id = f"KEV-{cve_id}"
        ctx.add_node(
            make_node(
                kev_id,
                NodeType.KEV,
                f"KEV: {cve_id}",
                description=v.get("shortDescription", f"CISA KEV entry for {cve_id}."),
                external_refs=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                source_refs=[source.source_id],
                confidence=1.0,
                metadata={
                    "vendorProject": v.get("vendorProject"),
                    "product": v.get("product"),
                    "dateAdded": v.get("dateAdded"),
                    "dueDate": v.get("dueDate"),
                    "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
                },
            )
        )
        ctx.add_edge(
            make_edge(
                EdgeType.KEV_PRIORITIZES_CVE,
                kev_id,
                cve_id,
                confidence=1.0,
                source_ref=source.source_id,
                source_url=source.url,
            )
        )


# ---------------------------------------------------------------------------
# Internal pseudo-sources (canonical reference catalogs, coverage engine)
# ---------------------------------------------------------------------------


def internal_sources() -> list[Source]:
    """Source entries for `CVEzD3FEND:*` pseudo-sources referenced by
    catalog-derived edges/nodes (PROVENANCE_CONTRACT requires every
    `source_ref` to resolve to `bundle.sources[]`).
    """
    ts = now_iso()
    catalogs_meta = [
        ("CVEzD3FEND:catalog_rule_templates", "Detection rule draft templates"),
        ("CVEzD3FEND:catalog_data_sources", "Telemetry data-source catalog (derived from D3FEND artifacts)"),
        ("CVEzD3FEND:catalog_log_sources", "Log-source catalog (derived from D3FEND artifacts)"),
        ("CVEzD3FEND:catalog_playbooks", "Response playbook templates (one per D3FEND tactic)"),
        ("CVEzD3FEND:catalog_soc_actions", "SOC action templates (one per D3FEND tactic)"),
        ("CVEzD3FEND:catalog_threat_hunts", "Threat-hunt hypothesis templates (one per ATT&CK technique)"),
        ("CVEzD3FEND:catalog_queries", "Hunt query draft templates (one per ATT&CK technique)"),
    ]
    sources = [
        Source(
            source_id=source_id,
            name=name,
            kind="derived_rule",
            url=None,
            fetched_at=ts,
            version="1.0.0",
            status="ok",
            metadata={"derivation": "canonical_reference_catalog"},
        )
        for source_id, name in catalogs_meta
    ]
    sources.append(
        Source(
            source_id="CVEzD3FEND:coverage_engine",
            name="CVEzD3FEND Coverage Engine",
            kind="derived_rule",
            url=None,
            fetched_at=ts,
            version="1.0.0",
            status="ok",
            metadata={"derivation": "coverage_engine"},
        )
    )
    return sources


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def build_graph(settings: Settings, client: httpx.Client | None = None) -> BuildResult:
    own_client = client is None
    if client is None:
        client = httpx.Client(headers={"User-Agent": "CVEzD3FEND-build/1.0"})
    ctx = GraphContext()
    sources: list[Source] = []
    warnings: list[str] = []

    try:
        techniques_db, techniques_db_source, w = frameworks.fetch_techniques_db(client, settings)
        sources.append(techniques_db_source)
        if w:
            warnings.append(w)

        ta_data, ta_source, w = frameworks.fetch_techniques_association(client, settings)
        sources.append(ta_source)
        if w:
            warnings.append(w)

        atlas_data, atlas_source, w = frameworks.fetch_atlas_db(client, settings)
        sources.append(atlas_source)
        if w:
            warnings.append(w)

        defend_records, defend_source, w = frameworks.fetch_defend_db(client, settings)
        sources.append(defend_source)
        if w:
            warnings.append(w)

        universe = build_attack_universe(techniques_db, defend_records, atlas_data, ta_data)

        capec_data, capec_source, w = frameworks.fetch_capec_db(client, settings)
        sources.append(capec_source)
        if w:
            warnings.append(w)
        add_capec_db(ctx, capec_data, capec_source, universe)

        cwe_data, cwe_source, w = frameworks.fetch_cwe_db(client, settings)
        sources.append(cwe_source)
        if w:
            warnings.append(w)
        add_cwe_db(ctx, cwe_data, cwe_source)

        if ta_data:
            add_techniques_association(ctx, ta_data, ta_source)
        if atlas_data:
            add_atlas_db(ctx, atlas_data, atlas_source)
        if defend_records:
            add_defend_db(ctx, defend_records, defend_source)

        for year in cve_years.resolve_years(settings):
            cve_records, cve_source, w = cve_years.fetch_cve_year(client, settings, year)
            sources.append(cve_source)
            if w:
                warnings.append(w)
            if cve_records:
                add_cve_records(ctx, year, cve_records, cve_source)

        kev_vulns, kev_source, w = kev.fetch_kev(client, settings)
        if w:
            warnings.append(w)
        if kev_source:
            sources.append(kev_source)
            add_kev(ctx, kev_vulns, kev_source)

        add_playbooks_and_soc_actions(ctx)
        add_threat_hunts(ctx)
    finally:
        if own_client:
            client.close()

    sources.extend(internal_sources())
    warnings.extend(ctx.warnings)
    return BuildResult(
        nodes=list(ctx.nodes.values()),
        edges=list(ctx.edges.values()),
        sources=sources,
        warnings=warnings,
    )
