// Client-side port of src/CVEzD3FEND/actions/soc_action_pack.py — every field
// is a deterministic, read-only projection over bundle nodes/edges/indexes,
// so the SOC Action Pack page works fully offline (static-first principle).
import { getNode } from "./bundle";
import type { BundleNode, KnowledgeBundle, SocActionPack } from "./types";

const PRIORITY_BY_COVERAGE: Record<string, SocActionPack["priority"]> = {
  gap: "High",
  partial: "Medium",
  covered: "Low",
  unknown: "Medium",
};

const CONFIDENCE_BY_COVERAGE: Record<string, number> = {
  gap: 0.3,
  partial: 0.6,
  covered: 1.0,
  unknown: 0.3,
};

function safeIdFragment(nodeId: string): string {
  return nodeId.replace(/[^A-Za-z0-9_-]/g, "_");
}

export function buildSocActionPack(bundle: KnowledgeBundle, attackId: string): SocActionPack {
  const attackNode = getNode(bundle, attackId);
  if (!attackNode || attackNode.type !== "attack") {
    throw new Error(`Unknown ATT&CK technique: ${attackId}`);
  }

  const idx = bundle.indexes;
  const defendIds = idx.attack_to_defend[attackId] ?? [];
  const detections = idx.attack_to_detections[attackId] ?? [];
  const coverageStatus = idx.coverage_by_technique[attackId] ?? "unknown";
  const gapIds = idx.gaps_by_technique[attackId] ?? [];

  const nodesById = new Map<string, BundleNode>(bundle.nodes.map((n) => [n.id, n]));

  const controls: string[] = [];
  const mitigations: string[] = [];
  for (const d of defendIds) {
    for (const c of idx.defend_to_controls[d] ?? []) {
      if (!controls.includes(c)) controls.push(c);
    }
    const mitId = `MIT-${d}`;
    if (nodesById.has(mitId) && !mitigations.includes(mitId)) mitigations.push(mitId);
  }

  const socActions: string[] = [];
  for (const e of bundle.edges) {
    if (e.type === "soc_action_operationalizes_defend" && defendIds.includes(e.target)) {
      if (!socActions.includes(e.source)) socActions.push(e.source);
    }
  }

  const evidence: string[] = [];
  const dataSources: string[] = [];
  const logSources: string[] = [];
  const detectionSet = new Set(detections);
  for (const e of bundle.edges) {
    if (e.type === "evidence_supports_detection" && detectionSet.has(e.target)) {
      if (!evidence.includes(e.source)) evidence.push(e.source);
    } else if (e.type === "data_source_enables_detection" && detectionSet.has(e.target)) {
      const srcNode = nodesById.get(e.source);
      if (srcNode?.type === "log_source" && !logSources.includes(e.source)) {
        logSources.push(e.source);
      } else if (srcNode?.type === "data_source" && !dataSources.includes(e.source)) {
        dataSources.push(e.source);
      }
    }
  }

  const huntId = `HUNT-${safeIdFragment(attackId)}`;
  const huntingHypotheses = nodesById.has(huntId) ? [huntId] : [];

  let attackPath: string[] = [attackId];
  for (const r of bundle.routes) {
    if (r.start_node.startsWith("CVE-") && r.nodes.includes(attackId)) {
      attackPath = r.nodes;
      break;
    }
  }

  const defensivePath = [...defendIds, ...controls];

  const sourceRefs: string[] = [];
  for (const nid of [attackId, ...defendIds, ...controls, ...detections]) {
    const node = nodesById.get(nid);
    if (!node) continue;
    for (const ref of node.source_refs) {
      if (!sourceRefs.includes(ref)) sourceRefs.push(ref);
    }
  }

  const executiveSummary =
    `${attackId} (${attackNode.name}) is currently '${coverageStatus}'. ` +
    `${defendIds.length} D3FEND technique(s), ${detections.length} detection opportunity(ies), ` +
    `and ${gapIds.length} open gap(s) are tracked for this technique.`;

  const technicalSummary =
    `D3FEND mappings: ${defendIds.join(", ") || "none"}. ` +
    `Controls: ${controls.join(", ") || "none"}. ` +
    `Mitigations: ${mitigations.join(", ") || "none"}. ` +
    `Detections: ${detections.join(", ") || "none"}.`;

  return {
    id: `PACK-${safeIdFragment(attackId)}`,
    title: `SOC Action Pack: ${attackNode.name} (${attackId})`,
    executive_summary: executiveSummary,
    technical_summary: technicalSummary,
    attack_path: attackPath,
    defensive_path: defensivePath,
    recommended_actions: [...controls, ...socActions],
    hunting_hypotheses: huntingHypotheses,
    detection_opportunities: detections,
    required_logs: [...dataSources, ...logSources],
    required_evidence: evidence,
    mitigations,
    gaps: gapIds,
    priority: PRIORITY_BY_COVERAGE[coverageStatus] ?? "Medium",
    confidence: CONFIDENCE_BY_COVERAGE[coverageStatus] ?? 0.3,
    source_refs: sourceRefs,
  };
}
