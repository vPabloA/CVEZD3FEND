// Client-side ports of src/CVEzD3FEND/export/{markdown,json}.py — Markdown
// and JSON exports work fully offline, mirroring EXPORT_CONTRACT §1 output
// byte-for-byte where the source data is identical.
import { getNode } from "./bundle";
import type { BundleNode, KnowledgeBundle, Route, SocActionPack } from "./types";

function nodeById(bundle: KnowledgeBundle): Map<string, BundleNode> {
  return new Map(bundle.nodes.map((n) => [n.id, n]));
}

function section(lines: string[], title: string, items: string[], nodes: Map<string, BundleNode>): void {
  lines.push(`## ${title}`);
  if (items.length === 0) {
    lines.push("_None_");
  } else {
    for (const itemId of items) {
      const node = nodes.get(itemId);
      if (node && node.name && node.name !== itemId) {
        lines.push(`- **${itemId}** — ${node.name}`);
      } else {
        lines.push(`- **${itemId}**`);
      }
    }
  }
  lines.push("");
}

function attackNodeId(route: Route): string | undefined {
  return route.nodes.find((_, i) => route.path[i] === "attack");
}

export function routeToMarkdown(bundle: KnowledgeBundle, route: Route): string {
  const nodes = nodeById(bundle);
  const edges = new Map(bundle.edges.map((e) => [e.id, e]));
  const sources = new Map(bundle.sources.map((s) => [s.source_id, s]));

  const lines: string[] = [];
  const endNode = nodes.get(route.end_node);
  lines.push(`# Route ${route.route_id}: ${route.start_node} -> ${route.end_node}`, "");

  lines.push("## Summary");
  lines.push(`- Confidence: ${route.confidence.toFixed(2)}`);
  lines.push(`- Canonical: ${route.canonical}`);
  lines.push(`- Inferred: ${route.inferred}`);
  lines.push(`- Coverage status: ${route.coverage_status}`);
  if (endNode) lines.push(`- Target: **${route.end_node}** — ${endNode.name}`);
  lines.push("");

  lines.push("## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)");
  route.nodes.forEach((nodeId, i) => {
    const node = nodes.get(nodeId);
    const name = node ? node.name : nodeId;
    if (i === 0) {
      lines.push(`- **${nodeId}** — ${name}`);
    } else {
      const edge = edges.get(route.edges[i - 1]);
      const conf = edge ? edge.confidence : route.confidence;
      const src = edge?.source_ref ?? "-";
      lines.push(`- **${nodeId}** — ${name} _(confidence: ${conf.toFixed(2)}, source: ${src})_`);
    }
  });
  lines.push("");

  const attackId = attackNodeId(route);
  const detections = attackId ? bundle.indexes.attack_to_detections[attackId] ?? [] : [];
  const defendIds = attackId ? bundle.indexes.attack_to_defend[attackId] ?? [] : [];
  const mitigations = defendIds.map((d) => `MIT-${d}`).filter((m) => nodes.has(m));
  const gaps = attackId ? bundle.indexes.gaps_by_technique[attackId] ?? [] : [];

  section(lines, "Recommended Actions", route.recommended_actions, nodes);
  section(lines, "Detection Opportunities", detections, nodes);
  section(lines, "Required Evidence / Logs", route.evidence_required, nodes);
  section(lines, "Mitigations", mitigations, nodes);
  section(lines, "Gaps", gaps, nodes);

  lines.push("## Sources");
  if (route.source_refs.length === 0) {
    lines.push("_None_");
  } else {
    for (const sourceId of route.source_refs) {
      const s = sources.get(sourceId);
      if (s) {
        lines.push(`- \`${s.source_id}\` — ${s.name} (${s.url || "internal"}), fetched_at=${s.fetched_at}`);
      } else {
        lines.push(`- \`${sourceId}\``);
      }
    }
  }
  lines.push("");

  return lines.join("\n");
}

export function socActionPackToMarkdown(bundle: KnowledgeBundle, pack: SocActionPack): string {
  const nodes = nodeById(bundle);
  const sources = new Map(bundle.sources.map((s) => [s.source_id, s]));

  const lines: string[] = [`# ${pack.title}`, ""];
  lines.push("## Summary");
  lines.push(pack.executive_summary, "");
  lines.push(pack.technical_summary);
  lines.push(`- Priority: ${pack.priority}`);
  lines.push(`- Confidence: ${pack.confidence.toFixed(2)}`);
  lines.push("");

  lines.push("## Path (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND)");
  if (pack.attack_path.length === 0) {
    lines.push("_None_");
  } else {
    for (const nodeId of pack.attack_path) {
      const node = nodes.get(nodeId);
      const name = node ? node.name : nodeId;
      lines.push(`- **${nodeId}** — ${name}`);
    }
  }
  lines.push("");

  section(lines, "Recommended Actions", pack.recommended_actions, nodes);
  section(lines, "Hunting Hypotheses", pack.hunting_hypotheses, nodes);
  section(lines, "Detection Opportunities", pack.detection_opportunities, nodes);
  section(lines, "Required Evidence / Logs", [...pack.required_evidence, ...pack.required_logs], nodes);
  section(lines, "Mitigations", pack.mitigations, nodes);
  section(lines, "Gaps", pack.gaps, nodes);

  lines.push("## Sources");
  if (pack.source_refs.length === 0) {
    lines.push("_None_");
  } else {
    for (const sourceId of pack.source_refs) {
      const s = sources.get(sourceId);
      if (s) {
        lines.push(`- \`${s.source_id}\` — ${s.name} (${s.url || "internal"}), fetched_at=${s.fetched_at}`);
      } else {
        lines.push(`- \`${sourceId}\``);
      }
    }
  }
  lines.push("");

  return lines.join("\n");
}

export function downloadText(filename: string, content: string, mime = "text/markdown"): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function downloadJson(filename: string, data: unknown): void {
  downloadText(filename, JSON.stringify(data, null, 2), "application/json");
}

// re-export for pages that need a node lookup alongside export helpers
export { getNode };
