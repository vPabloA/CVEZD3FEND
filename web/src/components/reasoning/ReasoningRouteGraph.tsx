import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  COLORS,
  REASONING_CLASSIFICATION_LABELS,
  classificationBorderStyle,
  classificationClass,
} from "@/lib/colors";
import type { ReasoningEdge, ReasoningResult } from "@/lib/reasoningTypes";

type NodeKind = "cve" | "cwe" | "capec" | "attack" | "defend" | "control" | "mitigation" | "detection" | "evidence" | "other";

interface GraphNode {
  id: string;
  kind: NodeKind;
  x: number;
  y: number;
  routeRole: "canonical" | "primary" | "secondary" | "conditional" | "defensive" | "weak-fit" | "context";
}

interface GraphModel {
  nodes: GraphNode[];
  edges: ReasoningEdge[];
  hiddenNodeCount: number;
  visibleIds: Set<string>;
}

const MAX_CONTEXT_NODES = 18;

const TYPE_COLUMNS: Record<NodeKind, number> = {
  cve: 8,
  cwe: 24,
  capec: 40,
  attack: 58,
  defend: 76,
  control: 84,
  mitigation: 84,
  detection: 88,
  evidence: 92,
  other: 50,
};

function nodeKind(id: string): NodeKind {
  if (/^CVE-/i.test(id)) return "cve";
  if (/^CWE-/i.test(id)) return "cwe";
  if (/^CAPEC-/i.test(id)) return "capec";
  if (/^T\d/i.test(id)) return "attack";
  if (/^D3-/i.test(id)) return "defend";
  if (/^CTRL-/i.test(id)) return "control";
  if (/^MIT-/i.test(id)) return "mitigation";
  if (/^DET-/i.test(id)) return "detection";
  if (/^EVID-/i.test(id)) return "evidence";
  return "other";
}

function roleFor(id: string, result: ReasoningResult): GraphNode["routeRole"] {
  if (result.route.canonical_chain.includes(id)) return "canonical";
  if (result.route.weak_fit_nodes.includes(id)) return "weak-fit";
  if (result.route.conditional_nodes.includes(id)) return "conditional";
  if (result.route.defensive_nodes.includes(id)) return "defensive";
  if (result.route.primary_nodes.includes(id)) return "primary";
  if (result.route.secondary_nodes.includes(id)) return "secondary";
  return "context";
}

function nodeColor(kind: NodeKind, role: GraphNode["routeRole"]): string {
  if (role === "weak-fit") return COLORS.template;
  if (role === "conditional") return COLORS.conditional;
  if (kind === "attack" || kind === "capec") return COLORS.offense;
  if (kind === "defend" || kind === "control" || kind === "mitigation" || kind === "detection") return COLORS.defense;
  if (kind === "evidence") return COLORS.evidence;
  if (kind === "cve" || kind === "cwe") return COLORS.link;
  return COLORS.template;
}

function buildGraph(result: ReasoningResult): GraphModel {
  const routeIds = new Set<string>([
    ...result.route.canonical_chain,
    ...result.route.primary_nodes,
    ...result.route.conditional_nodes,
    ...result.route.defensive_nodes,
    ...result.route.weak_fit_nodes,
  ]);
  const allIds = new Set<string>(routeIds);
  result.route.secondary_nodes.forEach((id) => allIds.add(id));
  result.edges.forEach((edge) => {
    allIds.add(edge.source);
    allIds.add(edge.target);
  });

  if (routeIds.size === 0) {
    result.edges.slice(0, MAX_CONTEXT_NODES).forEach((edge) => {
      routeIds.add(edge.source);
      routeIds.add(edge.target);
    });
  }

  const contextIds = [...allIds].filter((id) => !routeIds.has(id));
  contextIds.slice(0, Math.max(0, MAX_CONTEXT_NODES - routeIds.size)).forEach((id) => routeIds.add(id));

  const canonical = result.route.canonical_chain.filter((id) => routeIds.has(id));
  const canonicalPositions = new Map<string, { x: number; y: number }>();
  canonical.forEach((id, index) => {
    const denominator = Math.max(1, canonical.length - 1);
    canonicalPositions.set(id, { x: 8 + (index / denominator) * 84, y: 50 });
  });

  const nonCanonical = [...routeIds].filter((id) => !canonicalPositions.has(id));
  const laneCounts = new Map<NodeKind, number>();
  const nodes: GraphNode[] = [
    ...canonical.map((id) => ({
      id,
      kind: nodeKind(id),
      routeRole: roleFor(id, result),
      ...(canonicalPositions.get(id) ?? { x: 50, y: 50 }),
    })),
    ...nonCanonical.map((id, index) => {
      const kind = nodeKind(id);
      const count = laneCounts.get(kind) ?? 0;
      laneCounts.set(kind, count + 1);
      const role = roleFor(id, result);
      const verticalSlots = [28, 72, 18, 84, 38, 62];
      const xJitter = ((index % 3) - 1) * 2.5;
      return {
        id,
        kind,
        routeRole: role,
        x: Math.min(94, Math.max(6, TYPE_COLUMNS[kind] + xJitter)),
        y: verticalSlots[count % verticalSlots.length],
      };
    }),
  ];

  const visibleIds = new Set(nodes.map((node) => node.id));
  return {
    nodes,
    visibleIds,
    edges: result.edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)),
    hiddenNodeCount: Math.max(0, allIds.size - visibleIds.size),
  };
}

function edgeStroke(edge: ReasoningEdge): string {
  if (edge.classification === "official_explicit" || edge.classification === "official_incomplete") return COLORS.ok;
  if (edge.classification === "dataset_derived") return COLORS.link;
  if (edge.classification === "analytical_inferred") return COLORS.inferred;
  if (edge.classification === "conditional") return COLORS.conditional;
  if (edge.classification === "unverified") return COLORS.gap;
  return COLORS.template;
}

function nodeRadius(role: GraphNode["routeRole"]): number {
  if (role === "canonical") return 3.9;
  if (role === "primary" || role === "defensive") return 3.2;
  return 2.7;
}

export default function ReasoningRouteGraph({
  result,
  selectedNode,
  onSelectNode,
}: {
  result: ReasoningResult;
  selectedNode: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  const graph = useMemo(() => buildGraph(result), [result]);
  const positions = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const selected = selectedNode ? positions.get(selectedNode) : null;
  const pathLabel = result.route.canonical_chain.length > 0 ? result.route.canonical_chain.join(" → ") : "Partial route from available edges";

  return (
    <section className="relative flex min-h-[34rem] flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-xl">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(31,111,235,0.22),transparent_30%),radial-gradient(circle_at_78%_28%,rgba(21,128,61,0.18),transparent_26%),linear-gradient(135deg,rgba(15,23,42,0.98),rgba(2,6,23,0.98))]" />
      <div className="pointer-events-none absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(148,163,184,0.12)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.12)_1px,transparent_1px)] [background-size:28px_28px]" />

      <div className="relative z-10 flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/80 px-4 py-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Interactive Knowledge Graph</p>
          <h2 className="mt-1 text-base font-semibold text-slate-100">Ruta activa</h2>
          <p className="mt-1 max-w-3xl truncate font-mono text-xs text-slate-400" title={pathLabel}>
            {pathLabel}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-full border border-slate-700 bg-slate-900/80 px-2 py-1 text-slate-300">
            {graph.nodes.length} nodes
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-900/80 px-2 py-1 text-slate-300">
            {graph.edges.length} edges
          </span>
          <span className="rounded-full border border-ok/70 bg-green-950/40 px-2 py-1 text-green-200">Stabilized</span>
        </div>
      </div>

      <div className="relative z-10 flex flex-1 flex-col">
        <svg viewBox="0 0 100 100" className="min-h-[25rem] flex-1" role="img" aria-label={`Route graph for ${result.normalized_input || result.input}`}>
          <defs>
            <filter id="node-glow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="1.8" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <marker id="edge-arrow" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="3.4" markerHeight="3.4" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={COLORS.template} opacity="0.78" />
            </marker>
          </defs>

          {graph.edges.map((edge) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            if (!source || !target) return null;
            const relatedToSelection = !selectedNode || edge.source === selectedNode || edge.target === selectedNode;
            const stroke = edgeStroke(edge);
            const dashed = classificationBorderStyle(edge.classification) === "dashed" || edge.conditional;
            const midX = (source.x + target.x) / 2;
            const midY = (source.y + target.y) / 2 - 8;
            return (
              <path
                key={edge.id}
                d={`M ${source.x} ${source.y} Q ${midX} ${midY} ${target.x} ${target.y}`}
                fill="none"
                stroke={stroke}
                strokeWidth={relatedToSelection ? 0.75 : 0.35}
                strokeDasharray={dashed ? "2 1.8" : undefined}
                opacity={relatedToSelection ? 0.72 : 0.16}
                markerEnd="url(#edge-arrow)"
              >
                <title>{`${edge.source} to ${edge.target}: ${REASONING_CLASSIFICATION_LABELS[edge.classification]}, confidence ${edge.confidence.toFixed(2)}`}</title>
              </path>
            );
          })}

          {graph.nodes.map((node) => {
            const color = nodeColor(node.kind, node.routeRole);
            const relatedToSelection =
              !selectedNode ||
              node.id === selectedNode ||
              graph.edges.some((edge) => (edge.source === selectedNode && edge.target === node.id) || (edge.target === selectedNode && edge.source === node.id));
            const selectedNodeMatch = node.id === selectedNode;
            return (
              <g
                key={node.id}
                role="button"
                tabIndex={0}
                aria-label={`Focus ${node.id}`}
                onClick={() => onSelectNode(node.id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") onSelectNode(node.id);
                }}
                className="cursor-pointer outline-none"
                opacity={relatedToSelection ? 1 : 0.28}
              >
                <title>{`${node.id} (${node.routeRole})`}</title>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={nodeRadius(node.routeRole) + (selectedNodeMatch ? 1.4 : 0)}
                  fill="transparent"
                  stroke={color}
                  strokeWidth={selectedNodeMatch ? 0.75 : 0.32}
                  opacity={selectedNodeMatch ? 0.95 : 0.5}
                />
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={nodeRadius(node.routeRole)}
                  fill={color}
                  filter="url(#node-glow)"
                  opacity={node.routeRole === "weak-fit" ? 0.58 : 0.94}
                />
                <text
                  x={node.x}
                  y={node.y + nodeRadius(node.routeRole) + 4.3}
                  textAnchor="middle"
                  className="select-none fill-slate-200 font-mono text-[2.4px]"
                >
                  {node.id.length > 15 ? `${node.id.slice(0, 13)}…` : node.id}
                </text>
              </g>
            );
          })}
        </svg>

        <div className="relative z-10 grid gap-3 border-t border-slate-800/80 bg-slate-950/70 p-4 md:grid-cols-[1fr_auto]">
          <div className="flex flex-wrap gap-1.5">
            {(["official_explicit", "dataset_derived", "analytical_inferred", "conditional", "weak_fit", "unverified"] as const).map((classification) => (
              <span key={classification} className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${classificationClass(classification)}`}>
                {REASONING_CLASSIFICATION_LABELS[classification]}
              </span>
            ))}
          </div>
          {graph.hiddenNodeCount > 0 && (
            <p className="self-center text-xs text-slate-400">{graph.hiddenNodeCount} context node(s) hidden to keep the route focused.</p>
          )}
        </div>

        {selected && (
          <div className="absolute bottom-20 left-4 z-20 max-w-sm rounded-xl border border-slate-700 bg-slate-950/95 p-3 shadow-2xl backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Selected node</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-semibold text-slate-100">{selected.id}</span>
              <span className="rounded-full border border-slate-700 px-2 py-0.5 text-[11px] capitalize text-slate-300">{selected.routeRole}</span>
            </div>
            <Link to={`/node/${encodeURIComponent(selected.id)}`} className="mt-2 inline-flex text-xs font-medium text-blue-300 hover:underline">
              Open node detail
            </Link>
          </div>
        )}
      </div>
    </section>
  );
}
