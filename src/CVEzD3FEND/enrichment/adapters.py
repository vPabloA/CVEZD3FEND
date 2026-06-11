"""Live source adapters for CVE2CAPEC, NVD, EPSS, GHSA and MITRE catalogs."""

from __future__ import annotations

import gzip
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree as ET

import httpx
import yaml

from CVEzD3FEND.config import Settings
from CVEzD3FEND.enrichment.models import NormalizedEvidence, SourceFetchError
from CVEzD3FEND.enrichment.normalizers import best_of, extract_semantic_traits, summarize_text, uniq_preserve
from CVEzD3FEND.etl.http import FetchResult, cache_raw, fetch_url
from CVEzD3FEND.util import now_iso, safe_id_fragment


@dataclass(frozen=True)
class AdapterSpec:
    source: str
    source_type: str
    source_class: str
    source_classification: str
    source_url: str
    fetcher: Callable[[httpx.Client, Settings, str], NormalizedEvidence]


def available_sources() -> list[str]:
    return [
        "cve2capec",
        "nvd",
        "epss",
        "ghsa",
        "kev",
        "attack",
        "capec",
        "cwe",
        "d3fend",
        "atlas",
    ]


def _json_result(
    *,
    source: str,
    source_type: str,
    source_class: str,
    source_classification: str,
    source_url: str,
    input_value: str,
    result: FetchResult,
    data: dict[str, Any],
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    confidence_hint: float = 0.0,
    metadata: dict[str, Any] | None = None,
    raw_ref: str | None = None,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        source=source,
        source_type=source_type,
        source_class=source_class,  # type: ignore[arg-type]
        source_classification=source_classification,
        retrieved_at=result.fetched_at,
        source_url=source_url,
        input=input_value,
        raw_ref=raw_ref,
        raw_hash=result.sha256 or None,
        data=data,
        warnings=warnings or [],
        errors=errors or [],
        confidence_hint=confidence_hint,
        status="ok" if result.ok else "error",
        metadata=metadata or {},
    )


def _fetch_json(client: httpx.Client, settings: Settings, url: str, headers: dict[str, str] | None = None) -> FetchResult:
    return fetch_url(client, url, settings, headers=headers)


def _decode_json(result: FetchResult) -> Any:
    return json.loads(result.content)


def _decode_yaml(result: FetchResult) -> Any:
    return yaml.safe_load(result.content)


def _decode_zip_xml(result: FetchResult) -> ET.Element:
    with zipfile.ZipFile(io.BytesIO(result.content)) as zf:
        xml_name = next((name for name in zf.namelist() if name.lower().endswith(".xml")), zf.namelist()[0])
        return ET.fromstring(zf.read(xml_name))


def _local_bundle_path(settings: Settings) -> Path:
    return settings.bundle_path


def _load_local_bundle(settings: Settings) -> dict[str, Any] | None:
    path = _local_bundle_path(settings)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _source_from_cache(
    *,
    source: str,
    source_type: str,
    source_class: str,
    source_classification: str,
    source_url: str | None,
    input_value: str,
    cached: NormalizedEvidence,
    warning: str,
) -> NormalizedEvidence:
    return cached.model_copy(
        update={
            "source": source,
            "source_type": source_type,
            "source_class": source_class,
            "source_classification": source_classification,
            "source_url": source_url or cached.source_url,
            "input": input_value,
            "warnings": uniq_preserve([*cached.warnings, warning]),
            "status": "cached",
        }
    )


def fetch_cve2capec(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    bundle = _load_local_bundle(settings)
    if bundle is None:
        raise SourceFetchError("cve2capec", input_value, "bundle snapshot not available")
    bundle_path = _local_bundle_path(settings)
    route_ids = bundle.get("indexes", {}).get("cve_routes", {}).get(input_value, [])
    source_refs = []
    for source in bundle.get("sources", []):
        if isinstance(source, dict) and source.get("source_id", "").startswith("cve2capec:"):
            source_refs.append(source.get("source_id"))
    data = {
        "bundle_version": bundle.get("bundle_version"),
        "generated_at": bundle.get("generated_at"),
        "route_ids": route_ids,
        "source_refs": uniq_preserve(source_refs),
        "note": "Static bundle snapshot used as offline baseline.",
    }
    return NormalizedEvidence(
        source="cve2capec",
        source_type="bundle_snapshot",
        source_class="dataset_baseline",
        source_classification="static baseline snapshot",
        retrieved_at=now_iso(),
        source_url=None,
        input=input_value,
        raw_ref=str(bundle_path) if bundle_path.exists() else None,
        data=data,
        confidence_hint=1.0,
        status="ok",
        metadata={"offline": True},
    )


def _extract_nvd_reference_urls(cve: dict[str, Any]) -> list[str]:
    references = cve.get("references", {})
    if isinstance(references, list):
        return [item.get("url") for item in references if isinstance(item, dict) and item.get("url")]
    if isinstance(references, dict):
        return [
            item.get("url")
            for item in references.get("referenceData", [])
            if isinstance(item, dict) and item.get("url")
        ]
    return []


def fetch_nvd(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={input_value}"
    headers = {"User-Agent": "CVEzD3FEND-enrichment/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    result = _fetch_json(client, settings, url, headers=headers)
    if not result.ok:
        raise SourceFetchError("nvd", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_nvd_{safe_id_fragment(input_value)}.json", result)
    payload = _decode_json(result)
    vulns = payload.get("vulnerabilities", []) or []
    cve = best_of([v.get("cve") for v in vulns if isinstance(v, dict)], {})
    descriptions = [d.get("value") for d in cve.get("descriptions", []) if isinstance(d, dict)]
    refs = _extract_nvd_reference_urls(cve)
    weaknesses = [
        w.get("description", [{}])[0].get("value")
        for w in cve.get("weaknesses", [])
        if isinstance(w, dict) and w.get("description")
    ]
    semantic_traits = extract_semantic_traits(" ".join(descriptions), " ".join(weaknesses))
    metrics = cve.get("metrics", {})
    cvss = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss = metrics[key][0] if isinstance(metrics[key], list) else metrics[key]
            break
    cpe_matches = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            cpe_matches.extend(node.get("cpeMatch", []) or [])
    confidence_hint = 0.0
    if isinstance(cvss, dict):
        cvss_data = cvss.get("cvssData", {})
        confidence_hint = float(cvss_data.get("baseScore") or 0.0) / 10.0
    data = {
        "cve": cve.get("id") or input_value,
        "descriptions": descriptions,
        "semantic_traits": semantic_traits,
        "cvss": cvss,
        "weaknesses": uniq_preserve([w for w in weaknesses if w]),
        "references": uniq_preserve([r for r in refs if r]),
        "cpe_matches": cpe_matches[:20],
        "raw_total": payload.get("totalResults"),
        "source": "nvd",
    }
    return _json_result(
        source="nvd",
        source_type="cve",
        source_class="official_enrichment",
        source_classification="official NVD enrichment",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=confidence_hint or 0.7,
        metadata={"total_results": payload.get("totalResults"), "result_count": len(vulns)},
        raw_ref=str(raw_path),
    )


def fetch_epss(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = f"https://api.first.org/data/v1/epss?cve={input_value}"
    result = _fetch_json(client, settings, url)
    if not result.ok:
        raise SourceFetchError("epss", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_epss_{safe_id_fragment(input_value)}.json", result)
    payload = _decode_json(result)
    row = best_of([item for item in payload.get("data", []) if isinstance(item, dict)], {})
    epss = row.get("epss")
    percentile = row.get("percentile")
    data = {
        "cve": row.get("cve") or input_value,
        "epss": float(epss) if epss is not None else None,
        "percentile": float(percentile) if percentile is not None else None,
        "date": row.get("date"),
        "source": "epss",
    }
    confidence_hint = float(epss) if epss is not None else 0.0
    return _json_result(
        source="epss",
        source_type="cve",
        source_class="official_enrichment",
        source_classification="official EPSS score",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=confidence_hint,
        metadata={"record_count": len(payload.get("data", []))},
        raw_ref=str(raw_path),
    )


def fetch_ghsa(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = f"https://api.github.com/advisories?cve_id={input_value}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "CVEzD3FEND-enrichment/1.0"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    result = _fetch_json(client, settings, url, headers=headers)
    if not result.ok:
        raise SourceFetchError("ghsa", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_ghsa_{safe_id_fragment(input_value)}.json", result)
    payload = _decode_json(result)
    advisories = payload if isinstance(payload, list) else payload.get("advisories", [])
    matched = []
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        advisory_cves = advisory.get("cve_id")
        if advisory_cves == input_value:
            matched.append(advisory)
    if not matched and isinstance(advisories, list):
        matched = [a for a in advisories if isinstance(a, dict)][:1]
    summary = matched[0] if matched else {}
    descriptions = [summary.get("description"), summary.get("summary")]
    traits = extract_semantic_traits(*[text or "" for text in descriptions])
    data = {
        "cve": summary.get("cve_id") or input_value,
        "ghsa_id": summary.get("ghsa_id"),
        "severity": summary.get("severity"),
        "summary": summarize_text(summary.get("summary")),
        "description": summarize_text(summary.get("description")),
        "cwes": summary.get("cwes", []),
        "references": [r.get("url") for r in summary.get("references", []) if isinstance(r, dict)],
        "semantic_traits": traits,
        "source": "ghsa",
    }
    confidence_hint = 0.0
    severity = str(summary.get("severity") or "").lower()
    if severity == "critical":
        confidence_hint = 1.0
    elif severity == "high":
        confidence_hint = 0.8
    elif severity == "moderate":
        confidence_hint = 0.5
    return _json_result(
        source="ghsa",
        source_type="cve",
        source_class="official_enrichment",
        source_classification="GitHub Security Advisory",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=confidence_hint,
        metadata={"advisory_count": len(advisories) if isinstance(advisories, list) else 0},
        raw_ref=str(raw_path),
    )


def fetch_kev(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    result = _fetch_json(client, settings, url)
    if not result.ok:
        raise SourceFetchError("kev", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_kev_{safe_id_fragment(input_value)}.json", result)
    payload = _decode_json(result)
    vulns = [v for v in payload.get("vulnerabilities", []) if isinstance(v, dict)]
    matched = [v for v in vulns if v.get("cveID") == input_value]
    data = {
        "cve": input_value,
        "matches": matched,
        "catalog_version": payload.get("catalogVersion"),
        "count": len(vulns),
        "source": "kev",
    }
    confidence_hint = 1.0 if matched else 0.0
    return _json_result(
        source="kev",
        source_type="cve",
        source_class="official_enrichment",
        source_classification="CISA KEV catalog",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=confidence_hint,
        metadata={"catalog_version": payload.get("catalogVersion"), "matched": bool(matched)},
        raw_ref=str(raw_path),
    )


def _catalog_match_summary(objects: list[dict[str, Any]], subject: str, keys: list[str]) -> dict[str, Any]:
    subject_lower = subject.lower()
    matched = []
    for obj in objects:
        haystack = " ".join(str(obj.get(key, "")) for key in keys).lower()
        if subject_lower in haystack:
            matched.append(obj)
    return {"match_count": len(matched), "matched": matched[:3]}


def fetch_attack(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    result = _fetch_json(client, settings, url)
    if not result.ok:
        raise SourceFetchError("attack", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_attack_{safe_id_fragment(input_value)}.json", result)
    payload = _decode_json(result)
    objects = payload.get("objects", []) if isinstance(payload, dict) else []
    attack_patterns = [obj for obj in objects if isinstance(obj, dict) and obj.get("type") == "attack-pattern"]
    matched = []
    for obj in attack_patterns:
        refs = obj.get("external_references", []) or []
        external_ids = [ref.get("external_id") for ref in refs if isinstance(ref, dict)]
        if input_value in external_ids or input_value.lower() in str(obj.get("name", "")).lower():
            matched.append(obj)
    summary = matched[0] if matched else (attack_patterns[0] if attack_patterns else {})
    data = {
        "bundle_version": payload.get("spec_version"),
        "total_objects": len(objects),
        "attack_pattern_count": len(attack_patterns),
        "matched": {
            "id": summary.get("id"),
            "name": summary.get("name"),
            "description": summarize_text(summary.get("description")),
            "kill_chain_phases": summary.get("kill_chain_phases", []),
            "platforms": summary.get("x_mitre_platforms", []),
            "is_subtechnique": summary.get("x_mitre_is_subtechnique"),
        }
        if summary
        else {},
    }
    return _json_result(
        source="attack",
        source_type="catalog",
        source_class="official_enrichment",
        source_classification="MITRE ATT&CK enterprise STIX bundle",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=0.8 if matched else 0.4,
        metadata={"match_count": len(matched)},
        raw_ref=str(raw_path),
    )


def _parse_zip_xml(url: str, client: httpx.Client, settings: Settings, input_value: str, source: str, source_classification: str) -> NormalizedEvidence:
    result = fetch_url(client, url, settings)
    if not result.ok:
        raise SourceFetchError(source, input_value, result.error or "request failed")
    root = _decode_zip_xml(result)
    return NormalizedEvidence(
        source=source,
        source_type="catalog",
        source_class="official_enrichment",
        source_classification=source_classification,
        retrieved_at=result.fetched_at,
        source_url=url,
        input=input_value,
        raw_ref=None,
        raw_hash=result.sha256 or None,
        data={"root_tag": root.tag, "element_count": sum(1 for _ in root.iter())},
        confidence_hint=0.5,
        status="ok",
    )


def fetch_capec(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = "https://capec.mitre.org/data/xml/views/2000.xml.zip"
    result = fetch_url(client, url, settings)
    if not result.ok:
        raise SourceFetchError("capec", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_capec_{safe_id_fragment(input_value)}.xml.zip", result)
    root = _decode_zip_xml(result)
    patterns = [el for el in root.iter() if el.tag.endswith("Attack_Pattern")]
    matched = []
    for pattern in patterns:
        pattern_id = next((child.text for child in pattern if child.tag.endswith("ID")), None)
        name = next((child.text for child in pattern if child.tag.endswith("Name")), None)
        if input_value in {pattern_id, name}:
            matched.append(pattern)
    summary = matched[0] if matched else (patterns[0] if patterns else None)
    data = {
        "attack_pattern_count": len(patterns),
        "matched": {
            "id": next((child.text for child in summary if child.tag.endswith("ID")), None) if summary is not None else None,
            "name": next((child.text for child in summary if child.tag.endswith("Name")), None) if summary is not None else None,
            "description": summarize_text(next((child.text for child in summary if child.tag.endswith("Description")), None)) if summary is not None else None,
        }
        if summary is not None
        else {},
    }
    return _json_result(
        source="capec",
        source_type="catalog",
        source_class="official_enrichment",
        source_classification="MITRE CAPEC XML catalog",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=0.6 if matched else 0.3,
        metadata={"pattern_count": len(patterns)},
        raw_ref=str(raw_path),
    )


def fetch_cwe(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
    result = fetch_url(client, url, settings)
    if not result.ok:
        raise SourceFetchError("cwe", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_cwe_{safe_id_fragment(input_value)}.xml.zip", result)
    root = _decode_zip_xml(result)
    weaknesses = [el for el in root.iter() if el.tag.endswith("Weakness")]
    matched = []
    for weakness in weaknesses:
        weakness_id = next((child.text for child in weakness if child.tag.endswith("ID")), None)
        name = next((child.text for child in weakness if child.tag.endswith("Name")), None)
        if input_value in {weakness_id, name}:
            matched.append(weakness)
    summary = matched[0] if matched else (weaknesses[0] if weaknesses else None)
    data = {
        "weakness_count": len(weaknesses),
        "matched": {
            "id": next((child.text for child in summary if child.tag.endswith("ID")), None) if summary is not None else None,
            "name": next((child.text for child in summary if child.tag.endswith("Name")), None) if summary is not None else None,
            "description": summarize_text(next((child.text for child in summary if child.tag.endswith("Description")), None)) if summary is not None else None,
        }
        if summary is not None
        else {},
    }
    return _json_result(
        source="cwe",
        source_type="catalog",
        source_class="official_enrichment",
        source_classification="MITRE CWE XML catalog",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=0.6 if matched else 0.3,
        metadata={"weakness_count": len(weaknesses)},
        raw_ref=str(raw_path),
    )


def fetch_d3fend(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = "https://d3fend.mitre.org/resources/ontology/d3fend-full-mappings.json"
    result = _fetch_json(client, settings, url)
    if not result.ok:
        raise SourceFetchError("d3fend", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_d3fend_{safe_id_fragment(input_value)}.json", result)
    payload = _decode_json(result)
    if isinstance(payload, dict):
        values = list(payload.values())
        match_info = _catalog_match_summary([payload], input_value, list(payload.keys())[:6])
        data = {
            "top_level_keys": list(payload.keys())[:20],
            "matched": match_info,
            "shape": {k: type(v).__name__ for k, v in list(payload.items())[:10]},
            "source": "d3fend",
        }
    else:
        values = payload if isinstance(payload, list) else []
        match_info = _catalog_match_summary([v for v in values if isinstance(v, dict)], input_value, ["name", "id", "label", "attack", "defend", "technique"])
        data = {
            "record_count": len(values),
            "matched": match_info,
            "source": "d3fend",
        }
    return _json_result(
        source="d3fend",
        source_type="catalog",
        source_class="official_enrichment",
        source_classification="MITRE D3FEND mapping catalog",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=0.5 if data.get("matched", {}).get("match_count") else 0.2,
        metadata={"top_level_type": type(payload).__name__},
        raw_ref=str(raw_path),
    )


def fetch_atlas(client: httpx.Client, settings: Settings, input_value: str) -> NormalizedEvidence:
    url = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml"
    result = _fetch_json(client, settings, url)
    if not result.ok:
        raise SourceFetchError("atlas", input_value, result.error or "request failed")
    raw_path = cache_raw(settings, f"enrichment_atlas_{safe_id_fragment(input_value)}.yaml", result)
    payload = _decode_yaml(result)
    if isinstance(payload, dict):
        records = payload.get("techniques") or payload.get("objects") or []
        data = {
            "top_level_keys": list(payload.keys())[:20],
            "record_count": len(records) if isinstance(records, list) else 0,
            "matched": _catalog_match_summary(records if isinstance(records, list) else [], input_value, ["name", "id", "external_id", "technique"]),
            "source": "atlas",
        }
    else:
        records = payload if isinstance(payload, list) else []
        data = {
            "record_count": len(records),
            "matched": _catalog_match_summary([r for r in records if isinstance(r, dict)], input_value, ["name", "id", "external_id", "technique"]),
            "source": "atlas",
        }
    return _json_result(
        source="atlas",
        source_type="catalog",
        source_class="official_enrichment",
        source_classification="MITRE ATLAS catalog",
        source_url=url,
        input_value=input_value,
        result=result,
        data=data,
        confidence_hint=0.5 if data.get("matched", {}).get("match_count") else 0.2,
        metadata={"top_level_type": type(payload).__name__},
        raw_ref=str(raw_path),
    )
