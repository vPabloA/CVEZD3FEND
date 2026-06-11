"""Deterministic MVP reasoning engine for CVEzD3FEND."""

from __future__ import annotations

import json
import re
from typing import Any

from CVEzD3FEND.config import Settings
from CVEzD3FEND.enrichment import SourceOrchestrator
from CVEzD3FEND.enrichment.normalizers import canonical_semantic_tags, extract_semantic_traits
from CVEzD3FEND.enrichment.models import NormalizedEvidence
from CVEzD3FEND.intelligence.providers import get_provider
from CVEzD3FEND.intelligence.providers.base import ProviderError
from CVEzD3FEND.lookup import resolve_route
from CVEzD3FEND.query import BundleNotFoundError, load_bundle
from CVEzD3FEND.reasoning.attack_mapping import attack_candidates
from CVEzD3FEND.reasoning.capec_fit import score_capec_fit
from CVEzD3FEND.reasoning.d3fend_intent import defensive_intents
from CVEzD3FEND.reasoning.models import (
    DetectionEngineering,
    EnrichmentProfile,
    EnrichmentResult,
    Exports,
    HumanReview,
    Narrative,
    ReasoningEdge,
    ReasoningResult,
    RiskSummary,
    RouteContract,
    SocActionPack,
    ThreatHunting,
    Ctem,
)
from CVEzD3FEND.reasoning.provenance import bucket_edges, classify_source_mode, needs_human_review
from CVEzD3FEND.reasoning.soc_outputs import ctem_plan, detection_engineering, soc_action_pack, threat_hunting
from CVEzD3FEND.reasoning.narrative import render_spanish_narrative
from CVEzD3FEND.util import safe_id_fragment

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_CPE_RE = re.compile(r"^cpe:2\.3:[aho]:([^:]+):([^:]+):", re.I)


def _normalize_cve_id(value: str) -> str:
    stripped = value.strip().upper()
    if _CVE_RE.match(stripped):
        return stripped
    return stripped


def _evidence_to_dict(evidence: NormalizedEvidence) -> dict[str, Any]:
    return evidence.model_dump(mode="json")


def _first_text(parts: list[str]) -> str:
    return next((p for p in parts if p), "")


def _find_bundle_route(bundle, cve_id: str):
    try:
        return resolve_route(bundle, cve_id)
    except Exception:
        return None


def _infer_ecosystems(description: str, cpe_matches: list[str], semantic_tags: list[str]) -> list[str]:
    ecosystems: list[str] = []
    text = " ".join([description, *cpe_matches, *semantic_tags]).lower()
    for token in ("kubernetes", "container", "cloud", "nginx", "apache", "windows", "linux", "web", "api", "proxy"):
        if token in text and token not in ecosystems:
            ecosystems.append(token)
    return ecosystems


def _extract_products(cpe_matches: list[str]) -> list[str]:
    products: list[str] = []
    for cpe in cpe_matches:
        match = _CPE_RE.match(cpe)
        if not match:
            continue
        vendor, product = match.groups()
        label = f"{vendor}:{product}"
        if label not in products:
            products.append(label)
    return products


def _flatten_cpe_matches(raw_matches: list[Any]) -> list[str]:
    flattened: list[str] = []
    for match in raw_matches:
        if isinstance(match, str):
            flattened.append(match)
        elif isinstance(match, dict):
            for key in ("criteria", "cpe23Uri", "cpe", "name"):
                value = match.get(key)
                if isinstance(value, str) and value:
                    flattened.append(value)
                    break
    return flattened


def _semantic_tags(description: str, weakness_texts: list[str], cpe_matches: list[str], route_text: str) -> list[str]:
    return canonical_semantic_tags(extract_semantic_traits(description, *weakness_texts, *cpe_matches, route_text))


def _risk_level(tags: list[str], cvss: dict[str, Any] | None, epss: dict[str, Any] | None, kev: dict[str, Any] | None) -> dict[str, Any]:
    signal_count = len(tags)
    if cvss and isinstance(cvss.get("score"), (int, float)) and cvss["score"] >= 9:
        level = "critical"
    elif kev and kev.get("present"):
        level = "high"
    elif signal_count >= 3:
        level = "high"
    elif signal_count >= 1:
        level = "medium"
    else:
        level = "low"
    reasons = []
    if cvss:
        reasons.append(f"CVSS {cvss.get('score')} {cvss.get('severity')}")
    if epss:
        reasons.append(f"EPSS {epss.get('score')}")
    if kev and kev.get("present"):
        reasons.append("KEV presente")
    if tags:
        reasons.append(", ".join(tags[:4]))
    return {"level": level, "signals": reasons}


def _render_route_text(route: RouteContract, bundle_route_name: str | None = None) -> str:
    chain = " -> ".join(route.canonical_chain) if route.canonical_chain else "ruta parcial"
    if bundle_route_name:
        return f"{bundle_route_name}: {chain}"
    return chain


class ReasoningEngine:
    def __init__(self, settings: Settings, bundle=None, client=None):
        self.settings = settings
        self.bundle = bundle
        self.orchestrator = SourceOrchestrator(settings, client=client)

    def close(self) -> None:
        self.orchestrator.close()

    def _load_bundle(self):
        if self.bundle is not None:
            return self.bundle
        try:
            self.bundle = load_bundle(self.settings)
        except BundleNotFoundError:
            self.bundle = None
        return self.bundle

    def _collect_evidence(self, cve_id: str) -> list[NormalizedEvidence]:
        evidence: list[NormalizedEvidence] = []
        for source in ("cve2capec", "nvd", "epss", "ghsa", "kev"):
            outcome = self.orchestrator.collect(source, cve_id, mode="live")
            evidence.append(outcome.evidence)
        return evidence

    def enrich(self, cve_id: str) -> EnrichmentResult:
        normalized_input = _normalize_cve_id(cve_id)
        bundle = self._load_bundle()
        evidence = self._collect_evidence(normalized_input)

        evidence_map = {ev.source: ev for ev in evidence}
        nvd = evidence_map.get("nvd")
        epss = evidence_map.get("epss")
        ghsa = evidence_map.get("ghsa")
        kev = evidence_map.get("kev")
        baseline = evidence_map.get("cve2capec")

        description = _first_text(
            [
                str(nvd.data.get("descriptions", [""])[0]) if nvd and nvd.data.get("descriptions") else "",
                str(ghsa.data.get("summary", "")) if ghsa else "",
            ]
        )
        weakness_texts = []
        cwes = []
        cpe_matches = []
        cvss = None
        epss_data = None
        kev_data = None

        if nvd:
            weakness_texts = [str(w) for w in nvd.data.get("weaknesses", []) if w]
            cwes.extend(str(w) for w in nvd.data.get("weaknesses", []) if w)
            cpe_matches = _flatten_cpe_matches(list(nvd.data.get("cpe_matches", [])))
            cvss_raw = nvd.data.get("cvss") or {}
            if isinstance(cvss_raw, dict):
                cvss_data = cvss_raw.get("cvssData", {}) if isinstance(cvss_raw.get("cvssData"), dict) else {}
                cvss = {
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_raw.get("baseSeverity") or cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                    "source": "nvd",
                }
        if epss and epss.data:
            epss_data = {
                "score": epss.data.get("epss"),
                "percentile": epss.data.get("percentile"),
                "source": "epss",
            }
        if kev and kev.data:
            kev_data = {
                "present": bool(kev.data.get("matches")),
                "count": len(kev.data.get("matches", [])),
                "source": "cisa",
            }

        route = _find_bundle_route(bundle, normalized_input) if bundle else None
        route_name = route.route_id if route else None
        bundle_route_text = _render_route_text(
            RouteContract(canonical_chain=list(route.nodes) if route else []),
            bundle_route_name=route_name,
        )
        semantic_tags = _semantic_tags(description, weakness_texts, cpe_matches, bundle_route_text)
        products = _extract_products(cpe_matches)
        ecosystems = _infer_ecosystems(description, cpe_matches, semantic_tags)
        source_notes: list[str] = []
        if baseline and baseline.data.get("route_ids"):
            source_notes.append("Baseline CVE2CAPEC disponible.")
        if nvd and not cwes:
            source_notes.append("NVD no devolvió CWE consistente; se conserva la señal débil si aparece luego en baseline.")

        profile = EnrichmentProfile(
            description=description,
            cwes=list(dict.fromkeys(cwes)),
            cvss=cvss,
            epss=epss_data,
            kev=kev_data,
            affected_products=products,
            ecosystems=ecosystems,
            semantic_tags=semantic_tags,
            source_notes=source_notes,
        )

        statuses = [ev.status for ev in evidence]
        source_mode = classify_source_mode(statuses)
        status = "ok" if source_mode == "live" else "degraded"
        warnings = [w for ev in evidence for w in ev.warnings]
        errors = [e for ev in evidence for e in ev.errors]
        provenance = {
            "cve2capec": [baseline.model_dump(mode="json")] if baseline else [],
            "nvd": [nvd.model_dump(mode="json")] if nvd else [],
            "epss": [epss.model_dump(mode="json")] if epss else [],
            "ghsa": [ghsa.model_dump(mode="json")] if ghsa else [],
            "kev": [kev.model_dump(mode="json")] if kev else [],
        }

        return EnrichmentResult(
            input=cve_id,
            normalized_input=normalized_input,
            status=status,
            source_mode=source_mode,
            profile=profile,
            evidence=[_evidence_to_dict(ev) for ev in evidence],
            warnings=warnings,
            errors=errors,
            provenance=provenance,
        )

    def _reasoning_edges(self, cve_id: str, enrichment: EnrichmentResult) -> list[ReasoningEdge]:
        bundle = self._load_bundle()
        route = _find_bundle_route(bundle, enrichment.normalized_input) if bundle else None
        nodes_by_id = {n.id: n for n in bundle.nodes} if bundle else {}
        edges: list[ReasoningEdge] = []

        if route and bundle:
            for edge_id_value in route.edges:
                bundle_edge = next((e for e in bundle.edges if e.id == edge_id_value), None)
                if bundle_edge is None:
                    continue
                source_ref = bundle_edge.source_ref or "CVEzD3FEND:reasoning"
                classification = "dataset_derived"
                note = None
                if source_ref.startswith("cisa:kev"):
                    classification = "official_explicit"
                elif source_ref.startswith("nvd"):
                    classification = "official_incomplete"
                elif source_ref.startswith("cve2capec"):
                    classification = "dataset_derived"
                elif source_ref.startswith("CVEzD3FEND:catalog_"):
                    classification = "dataset_derived"
                elif bundle_edge.inferred:
                    classification = "analytical_inferred"
                    note = "Edge inferido desde la capa AI."
                source_node = nodes_by_id.get(bundle_edge.source)
                target_node = nodes_by_id.get(bundle_edge.target)
                if bundle_edge.type.value == "cwe_maps_to_capec" and target_node:
                    fit = score_capec_fit(bundle_edge.target, enrichment.profile.semantic_tags)
                    if fit.weak:
                        classification = "weak_fit"
                        note = f"CAPEC con ajuste débil: {fit.reason}"
                edges.append(
                    ReasoningEdge(
                        id=bundle_edge.id,
                        source=bundle_edge.source,
                        target=bundle_edge.target,
                        type=bundle_edge.type.value,
                        classification=classification,  # type: ignore[arg-type]
                        confidence=bundle_edge.confidence,
                        evidence=list(bundle_edge.evidence) or [cve_id],
                        source_refs=[source_ref],
                        source_url=bundle_edge.source_url,
                        note=note,
                        deterministic=not bundle_edge.inferred,
                        inferred=bundle_edge.inferred,
                        conditional=False,
                        weak_fit=classification == "weak_fit",
                    )
                )

        attack_ids = []
        capec_ids = []
        defend_nodes = []
        if route and bundle:
            attack_ids = [nid for nid in route.nodes if nid in nodes_by_id and nodes_by_id[nid].type.value == "attack"]
            capec_ids = [nid for nid in route.nodes if nid in nodes_by_id and nodes_by_id[nid].type.value == "capec"]
            defend_nodes = [nid for nid in route.nodes if nid in nodes_by_id and nodes_by_id[nid].type.value in {"defend", "control", "detection", "evidence"}]

        conditional_candidates = attack_candidates(enrichment.profile.semantic_tags)
        for candidate in conditional_candidates:
            edges.append(
                ReasoningEdge(
                    id=f"COND-{candidate.attack_id}-{safe_id_fragment(enrichment.normalized_input)}",
                    source=enrichment.normalized_input,
                    target=candidate.attack_id,
                    type="conditional_attack_mapping",
                    classification="conditional",
                    confidence=candidate.confidence,
                    evidence=[candidate.evidence],
                    source_refs=["CVEzD3FEND:reasoning_engine"],
                    note="Mapeo condicional basado en semántica y contexto.",
                    deterministic=True,
                    inferred=False,
                    conditional=True,
                    weak_fit=False,
                )
            )

        intents = defensive_intents(enrichment.profile.semantic_tags)
        for intent in intents:
            edges.append(
                ReasoningEdge(
                    id=f"D3-{safe_id_fragment(intent.label)}-{safe_id_fragment(enrichment.normalized_input)}",
                    source=attack_ids[0] if attack_ids else enrichment.normalized_input,
                    target=intent.label,
                    type="defensive_intent",
                    classification="unverified",
                    confidence=0.35,
                    evidence=[intent.rationale],
                    source_refs=["CVEzD3FEND:reasoning_engine"],
                    note=intent.rationale,
                    deterministic=True,
                    inferred=False,
                    conditional=True,
                    weak_fit=False,
                )
            )

        if capec_ids:
            for capec_id in capec_ids:
                fit = score_capec_fit(capec_id, enrichment.profile.semantic_tags)
                if fit.weak:
                    edges.append(
                        ReasoningEdge(
                            id=f"WEAK-{safe_id_fragment(capec_id)}-{safe_id_fragment(enrichment.normalized_input)}",
                            source=capec_id,
                            target=attack_ids[0] if attack_ids else enrichment.normalized_input,
                            type="capec_semantic_fit",
                            classification="weak_fit",
                            confidence=fit.fit,
                            evidence=[fit.reason],
                            source_refs=["CVEzD3FEND:reasoning_engine"],
                            note=fit.reason,
                            deterministic=True,
                            inferred=False,
                            conditional=False,
                            weak_fit=True,
                        )
                    )

        # Keep only the most relevant edges and preserve provenance classes.
        deduped: dict[tuple[str, str, str], ReasoningEdge] = {}
        for edge in edges:
            key = (edge.source, edge.target, edge.type)
            deduped[key] = edge
        return list(deduped.values())

    def _risk_summary(self, enrichment: EnrichmentResult) -> RiskSummary:
        profile = enrichment.profile
        return RiskSummary(
            cvss=profile.cvss,
            epss=profile.epss,
            kev=profile.kev,
            exploitability=_risk_level(profile.semantic_tags, profile.cvss, profile.epss, profile.kev),
        )

    def reason(self, cve_id: str) -> ReasoningResult:
        enrichment = self.enrich(cve_id)
        bundle = self._load_bundle()
        route = _find_bundle_route(bundle, enrichment.normalized_input) if bundle else None
        edges = self._reasoning_edges(cve_id, enrichment)
        provenance = bucket_edges(edges)
        review_required, review_reason = needs_human_review(edges)
        risk = self._risk_summary(enrichment)

        canonical_chain = list(route.nodes) if route else []
        primary_nodes = canonical_chain[:5]
        secondary_nodes = enrichment.profile.affected_products[:5]
        conditional_nodes = [edge.target for edge in edges if edge.classification == "conditional"]
        defensive_nodes = [edge.target for edge in edges if edge.classification in {"official_explicit", "dataset_derived", "unverified"} and edge.type in {"defensive_intent", "attack_maps_to_defend", "attack_maps_to_defend_intent"}]
        weak_fit_nodes = [edge.target for edge in edges if edge.classification == "weak_fit"]

        route_contract = RouteContract(
            canonical_chain=canonical_chain,
            primary_nodes=list(dict.fromkeys(primary_nodes + conditional_nodes[:1])),
            secondary_nodes=list(dict.fromkeys(secondary_nodes)),
            conditional_nodes=list(dict.fromkeys(conditional_nodes)),
            defensive_nodes=list(dict.fromkeys(defensive_nodes)),
            weak_fit_nodes=list(dict.fromkeys(weak_fit_nodes)),
        )

        route_text = _render_route_text(route_contract, bundle_route_name=route.route_id if route else None)
        risk_text = ", ".join(risk.exploitability.get("signals", [])) if isinstance(risk.exploitability, dict) else "Riesgo no evaluable."
        provenance_text = (
            f"official_explicit={len(provenance['official_explicit'])}, "
            f"official_incomplete={len(provenance['official_incomplete'])}, "
            f"dataset_derived={len(provenance['dataset_derived'])}, "
            f"conditional={len(provenance['conditional'])}, "
            f"weak_fit={len(provenance['weak_fit'])}, "
            f"unverified={len(provenance['unverified'])}"
        )
        actions = "Las acciones prioritarias son contención, validación de exposición y remediación con control de cambios."
        narrative_payload = render_spanish_narrative(
            enrichment.normalized_input,
            enrichment.profile.description or "No hay descripción detallada suficiente en la evidencia viva.",
            route_text,
            risk_text,
            provenance_text,
            actions,
        )

        if self.settings.ai_enabled:
            try:
                provider = get_provider(self.settings)
                narrative_payload["summary_es"] = provider.complete(
                    system=(
                        "Eres un analista defensivo. Conserva hechos, no inventes ids oficiales y responde en español. "
                        "Mantén 4-5 párrafos cortos y termina con 'Para Tier 1 significa...'."
                    ),
                    prompt=f"Mejora el resumen defensivo para {enrichment.normalized_input} sin cambiar el contenido técnico.",
                ) or narrative_payload["summary_es"]
            except ProviderError:
                pass

        status = enrichment.status
        if review_required:
            status = "degraded"

        bundle_sources = []
        if bundle:
            bundle_sources = [s.source_id for s in bundle.sources]
        bundle_source_mode = enrichment.source_mode

        result = ReasoningResult(
            input=cve_id,
            normalized_input=enrichment.normalized_input,
            status=status,
            source_mode=bundle_source_mode,
            reasoning_mode="ai-assisted" if self.settings.ai_enabled else "deterministic",
            human_review=HumanReview(required=review_required, reason=review_reason),
            risk=risk,
            route=route_contract,
            edges=edges,
            provenance=provenance,
            narrative=Narrative(**narrative_payload),
            soc_action_pack=SocActionPack(**soc_action_pack(enrichment.profile.semantic_tags, [e.target for e in edges if e.classification == "conditional"], route_contract.defensive_nodes)),
            detection_engineering=DetectionEngineering(**detection_engineering(enrichment.profile.semantic_tags, [e.target for e in edges if e.classification == "conditional"])),
            threat_hunting=ThreatHunting(**threat_hunting(enrichment.profile.semantic_tags, [e.target for e in edges if e.classification == "conditional"])),
            ctem=Ctem(**ctem_plan(enrichment.profile.semantic_tags, [e.target for e in edges if e.classification == "conditional"])),
            exports=Exports(
                markdown=self.render_markdown(enrichment.normalized_input, route_contract, result=None),
                tree=self.render_tree(enrichment.normalized_input, route_contract, edges),
                mermaid=self.render_mermaid(enrichment.normalized_input, route_contract, edges),
                navigator_layer=None,
            ),
            warnings=[*enrichment.warnings, *([review_reason] if review_reason else [])],
            errors=enrichment.errors,
        )
        # Rebuild markdown with the fully populated result for a richer export.
        result.exports.markdown = self.render_markdown(enrichment.normalized_input, route_contract, result)
        return result

    def render_markdown(self, cve_id: str, route: RouteContract, result: ReasoningResult | None) -> str:
        lines = [f"# Reasoning for {cve_id}", ""]
        lines.append("## Route")
        lines.append(f"- Canonical chain: {' -> '.join(route.canonical_chain) if route.canonical_chain else 'n/a'}")
        lines.append(f"- Primary nodes: {', '.join(route.primary_nodes) if route.primary_nodes else 'n/a'}")
        lines.append(f"- Conditional nodes: {', '.join(route.conditional_nodes) if route.conditional_nodes else 'n/a'}")
        lines.append("")
        if result is not None:
            lines.append("## Narrative")
            lines.append(result.narrative.summary_es)
            lines.append("")
            lines.append("## SOC")
            lines.extend(f"- {item}" for item in result.soc_action_pack.validations)
        return "\n".join(lines)

    def render_tree(self, cve_id: str, route: RouteContract, edges: list[ReasoningEdge]) -> str:
        lines = [cve_id]
        for index, node in enumerate(route.canonical_chain):
            prefix = "|--" if index < len(route.canonical_chain) - 1 else "`--"
            lines.append(f"{prefix} {node}")
        if route.conditional_nodes:
            lines.append("|-- conditional")
            for node in route.conditional_nodes:
                lines.append(f"    |-- {node}")
        if route.defensive_nodes:
            lines.append("`-- defensive")
            for node in route.defensive_nodes:
                lines.append(f"    |-- {node}")
        return "\n".join(lines)

    def render_mermaid(self, cve_id: str, route: RouteContract, edges: list[ReasoningEdge]) -> str:
        lines = ["flowchart LR"]
        nodes = route.canonical_chain or [cve_id]
        for left, right in zip(nodes, nodes[1:]):
            lines.append(f'  "{left}" --> "{right}"')
        for edge in edges:
            if edge.classification in {"conditional", "weak_fit", "unverified"}:
                lines.append(f'  "{edge.source}" -. "{edge.classification}" .-> "{edge.target}"')
        return "\n".join(lines)

    def explain(self, cve_id: str) -> str:
        return self.reason(cve_id).narrative.summary_es

    def hunt(self, cve_id: str) -> str:
        result = self.reason(cve_id)
        return "\n".join(
            [
                f"# Threat Hunt - {result.normalized_input}",
                "",
                *[f"- {item}" for item in result.threat_hunting.hypotheses],
                "",
                *[f"- {item}" for item in result.threat_hunting.queries],
                "",
                *[f"- {item}" for item in result.threat_hunting.pivot_points],
            ]
        )

    def detect(self, cve_id: str) -> str:
        result = self.reason(cve_id)
        return "\n".join(
            [
                f"# Detection Brief - {result.normalized_input}",
                "",
                *[f"- {item}" for item in result.detection_engineering.hypotheses],
                "",
                *[f"- {item}" for item in result.detection_engineering.log_sources],
                "",
                *[f"- {item}" for item in result.detection_engineering.rule_ideas],
            ]
        )

    def ctem(self, cve_id: str) -> str:
        result = self.reason(cve_id)
        return "\n".join(
            [
                f"# CTEM - {result.normalized_input}",
                "",
                f"- Priority: {result.ctem.priority}",
                *[f"- {item}" for item in result.ctem.remediation_actions],
                "",
                *[f"- {item}" for item in result.ctem.validation_steps],
                "",
                f"- Residual risk: {result.ctem.residual_risk}",
            ]
        )

    def propose_route(self, cve_id: str) -> dict[str, Any]:
        if not self.settings.ai_enabled:
            return {"status": "disabled", "reason": "AI disabled", "proposal": self.reason(cve_id).model_dump(mode="json")}
        try:
            provider = get_provider(self.settings)
            proposal = self.reason(cve_id).model_dump(mode="json")
            proposal["narrative"]["summary_es"] = provider.complete(
                system="Eres un arquitecto defensivo. Propón una ruta sin afirmar oficialidad.",
                prompt=json.dumps(proposal, ensure_ascii=False),
            )
            return {"status": "proposed", "proposal": proposal}
        except ProviderError as exc:
            return {"status": "disabled", "reason": str(exc), "proposal": None}

    def validate_route(self, cve_id: str) -> dict[str, Any]:
        result = self.reason(cve_id)
        return {
            "status": "validated" if not result.human_review.required else "review_required",
            "required_review": result.human_review.required,
            "reason": result.human_review.reason,
            "errors": result.errors,
            "warnings": result.warnings,
        }

    def promote_edge(self, edge_id_value: str, reviewer: str | None) -> dict[str, Any]:
        if not reviewer:
            return {"status": "rejected", "reason": "reviewer required", "promoted": False}
        return {
            "status": "disabled" if not self.settings.ai_enabled else "recorded",
            "reviewer": reviewer,
            "edge_id": edge_id_value,
            "promoted": False,
            "message": "MVP no canoniza edges; solo registra la revisión humana.",
        }
