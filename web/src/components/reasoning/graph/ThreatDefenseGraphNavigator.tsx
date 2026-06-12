import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { ForceGraphMethods } from "react-force-graph-2d";
import { COLORS, REASONING_CLASSIFICATION_LABELS } from "@/lib/colors";
import { buildGraphModel } from "./graphAdapter";
import GraphControls from "./GraphControls";
import GraphInspector from "./GraphInspector";
import GraphLegend from "./GraphLegend";
import type { GraphLinkData, GraphMode, GraphNodeData, GraphSelection } from "./graphTypes";
import { buildHighlightState } from "./pathHighlighting";
import { graphLinkSourceId, graphLinkTargetId } from "./graphRuntime";
import type { ReasoningEdgeClassification, ReasoningResult } from "@/lib/reasoningTypes";

const DEFAULT_CLASSIFICATIONS: ReasoningEdgeClassification[] = [
  "official_explicit",
  "official_incomplete",
  "dataset_derived",
  "analytical_inferred",
  "conditional",
  "weak_fit",
  "unverified",
];

type RenderedNode = GraphNodeData & { highlighted: boolean; focused: boolean; mitigation: boolean };
type RenderedLink = GraphLinkData & { highlighted: boolean; focused: boolean; mitigation: boolean };

function classificationColor(classification: ReasoningEdgeClassification): string {
  switch (classification) {
    case "official_explicit":
    case "official_incomplete":
      return COLORS.ok;
    case "dataset_derived":
      return COLORS.link;
    case "analytical_inferred":
      return COLORS.inferred;
    case "conditional":
      return COLORS.conditional;
    case "weak_fit":
      return COLORS.template;
    case "unverified":
      return COLORS.gap;
  }
  return COLORS.template;
}

function nodeColor(node: GraphNodeData): string {
  if (node.routeRole === "weak-fit") return COLORS.template;
  if (node.routeRole === "conditional") return COLORS.conditional;
  if (node.kind === "defend" || node.kind === "control" || node.kind === "mitigation") return COLORS.defense;
  if (node.kind === "attack" || node.kind === "capec") return COLORS.offense;
  if (node.kind === "evidence") return COLORS.evidence;
  if (node.kind === "gap") return COLORS.gap;
  return COLORS.link;
}

function nodeRadius(node: GraphNodeData): number {
  if (node.routeRole === "canonical") return 8.5;
  if (node.routeRole === "primary" || node.routeRole === "defensive") return 7.5;
  if (node.routeRole === "conditional" || node.routeRole === "secondary") return 6.5;
  return 6;
}

function hasFullRoute(chain: string[], nodes: GraphNodeData[]): boolean {
  if (chain.length < 5) return false;
  const routeKinds = new Set(nodes.filter((node) => chain.includes(node.id)).map((node) => node.kind));
  return ["cve", "cwe", "capec", "attack", "defend"].every((kind) => routeKinds.has(kind as GraphNodeData["kind"]));
}

export default function ThreatDefenseGraphNavigator({
  result,
  selection,
  onSelectNode,
  onSelectEdge,
  onClearSelection,
}: {
  result: ReasoningResult;
  selection: GraphSelection;
  onSelectNode: (nodeId: string) => void;
  onSelectEdge: (edgeId: string) => void;
  onClearSelection: () => void;
}) {
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined);
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const autoFittedRef = useRef(false);
  const [canvasSize, setCanvasSize] = useState<{ width: number; height: number } | null>(null);
  const [mode, setMode] = useState<GraphMode>("focused-route");
  const [classificationFilters, setClassificationFilters] = useState<Set<ReasoningEdgeClassification>>(new Set(DEFAULT_CLASSIFICATIONS));
  const [stabilized, setStabilized] = useState(false);
  const classificationFilterKey = [...classificationFilters].sort().join("|");
  const selectionFilterKey = selection ? `${selection.kind}:${selection.id}` : "none";
  const mitigationMode = mode === "mitigation-path";

  useEffect(() => {
    setStabilized(false);
  }, [result, mode, classificationFilterKey, selectionFilterKey]);

  // Re-frame the route once per data/mode change so the graph fills the stage.
  useEffect(() => {
    autoFittedRef.current = false;
  }, [result, mode, classificationFilterKey]);

  // react-force-graph sizes its canvas to the window by default; track the
  // stage container instead so the canvas always matches the visible frame.
  useEffect(() => {
    const el = canvasRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (rect && rect.width > 0 && rect.height > 0) {
        setCanvasSize({ width: rect.width, height: rect.height });
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const graph = useMemo(() => buildGraphModel(result, mode, selection), [result, mode, selection]);
  const highlights = useMemo(() => buildHighlightState(graph, selection, mode), [graph, selection, mode]);

  const renderedLinks = useMemo(
    () =>
      graph.links.filter((link) => classificationFilters.has(link.classification)).map((link) => ({
        ...link,
        highlighted: highlights.highlightedLinks.has(link.id),
        focused: highlights.focusedLinks.has(link.id),
        mitigation: highlights.mitigationLinks.has(link.id),
      })) as RenderedLink[],
    [classificationFilters, graph.links, highlights.focusedLinks, highlights.highlightedLinks, highlights.mitigationLinks]
  );

  const renderedNodes = useMemo(() => {
    const visibleIds = new Set<string>();
    renderedLinks.forEach((link) => {
      visibleIds.add(graphLinkSourceId(link));
      visibleIds.add(graphLinkTargetId(link));
    });
    graph.nodes.forEach((node) => {
      if (visibleIds.size === 0 || visibleIds.has(node.id) || highlights.highlightedNodes.has(node.id)) {
        visibleIds.add(node.id);
      }
    });
    return graph.nodes
      .filter((node) => visibleIds.has(node.id))
      .map((node) => ({
        ...node,
        highlighted: highlights.highlightedNodes.has(node.id),
        focused: highlights.focusedNodes.has(node.id),
        mitigation: highlights.mitigationNodes.has(node.id),
      })) as RenderedNode[];
  }, [graph.nodes, highlights.focusedNodes, highlights.highlightedNodes, highlights.mitigationNodes, renderedLinks]);

  const selectedNodeVisible = selection?.kind === "node" ? renderedNodes.some((node) => node.id === selection.id) : true;
  const selectedEdgeVisible = selection?.kind === "edge" ? renderedLinks.some((link) => link.id === selection.id) : true;
  const selectedHidden = Boolean(selection && (!selectedNodeVisible || !selectedEdgeVisible));
  const stateNotices = useMemo(() => {
    const notices: { tone: "info" | "warning"; text: string }[] = [];
    if (graph.nodes.length === 0 && result.errors.length > 0) {
      notices.push({ tone: "warning", text: "Graph data is unavailable for this CVE. Review the API status and try Analyze again." });
    } else if (graph.nodes.length === 0) {
      notices.push({ tone: "info", text: "No graphable route was produced for this CVE." });
    } else if (graph.links.length === 0) {
      notices.push({ tone: "info", text: "No graphable relationships were produced yet. Evidence is still available in the drawer." });
    }

    if (graph.nodes.length > 0 && !hasFullRoute(graph.routeChain, graph.nodes)) {
      notices.push({ tone: "info", text: "This route is partial. Defensive intent is available, but no canonical CWE/CAPEC chain was found." });
    }

    if (selectedHidden) {
      notices.push({ tone: "warning", text: selection?.kind === "edge" ? "The selected edge is hidden by the current filters." : "The selected node is hidden by the current filters." });
    }

    return notices.slice(0, 3);
  }, [graph.links.length, graph.nodes, graph.routeChain, result.errors.length, selectedHidden, selection?.kind]);

  const fitView = () => {
    fgRef.current?.zoomToFit?.(350, 60);
    // Small routes otherwise over-zoom into giant nodes; cap the fit zoom.
    window.setTimeout(() => {
      const fg = fgRef.current;
      const current = fg?.zoom?.();
      if (typeof current === "number" && current > 2) fg?.zoom?.(2, 200);
    }, 420);
  };

  const resetSelection = () => {
    onSelectNode(graph.routeChain[0] ?? result.normalized_input ?? result.input);
    onSelectEdge("");
    setMode("focused-route");
    setClassificationFilters(new Set(DEFAULT_CLASSIFICATIONS));
    setStabilized(false);
    window.requestAnimationFrame(() => fitView());
  };

  const clearSelection = () => onClearSelection();

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl">
      <div className="border-b border-slate-800/80 bg-slate-950/90 px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Threat-Defense Knowledge Graph Navigator</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold text-slate-100">Ruta activa</h2>
              <span className="rounded-full border border-sky-500/40 bg-sky-950/40 px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.18em] text-sky-300">
                Interactive Knowledge Graph
              </span>
            </div>
            {graph.routeChain.length > 0 ? (
              <div className="mt-2 flex flex-wrap items-center gap-1" title={graph.routeChain.join(" → ")}>
                {graph.routeChain.map((id, index) => (
                  <span key={id} className="flex items-center gap-1">
                    <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">{id}</span>
                    {index < graph.routeChain.length - 1 && (
                      <span className="text-slate-600" aria-hidden="true">
                        →
                      </span>
                    )}
                  </span>
                ))}
              </div>
            ) : (
              <p className="mt-2 font-mono text-xs text-slate-400">Partial route from available reasoning edges</p>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-300">
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1">
              {graph.nodes.length} nodes · {graph.links.length} edges
            </span>
            {mitigationMode && (
              <span className="rounded-full border border-defense bg-green-50 px-2 py-1 font-semibold text-defense">Mitigation path</span>
            )}
            <span className={`rounded-full border px-2 py-1 ${result.human_review.required ? "border-amber-400 bg-amber-50 text-amber-800" : "border-ok bg-green-50 text-ok"}`}>
              {result.human_review.required ? "Human review required" : "Route validated"}
            </span>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{result.source_mode}</span>
          </div>
        </div>
      </div>

      <div className="flex min-h-[42rem] flex-col gap-3 p-3 2xl:min-h-[46rem]">
        {stateNotices.length > 0 && (
          <div className="grid gap-2">
            {stateNotices.map((notice) => (
              <div
                key={notice.text}
                className={`rounded-xl border px-3 py-2 text-sm ${
                  notice.tone === "warning"
                    ? "border-amber-400/50 bg-amber-950/30 text-amber-100"
                    : "border-sky-500/30 bg-sky-950/30 text-sky-100"
                }`}
              >
                {notice.text}
              </div>
            ))}
          </div>
        )}

        <GraphControls
          mode={mode}
          onModeChange={setMode}
          classificationFilters={classificationFilters}
          onToggleClassification={(classification) => {
            setClassificationFilters((current) => {
              const next = new Set(current);
              if (next.has(classification)) next.delete(classification);
              else next.add(classification);
              return next.size === 0 ? new Set(DEFAULT_CLASSIFICATIONS) : next;
            });
          }}
          onFitView={fitView}
          onResetSelection={resetSelection}
          onClearSelection={clearSelection}
          hiddenNodeCount={graph.hiddenNodeCount}
          hiddenLinkCount={graph.hiddenLinkCount}
        />

        <div className="relative flex flex-1 flex-col gap-3">
          <div
            ref={canvasRef}
            className="relative flex min-h-[32rem] flex-1 overflow-hidden rounded-2xl border border-slate-800 bg-[radial-gradient(circle_at_20%_20%,rgba(31,111,235,0.18),transparent_28%),radial-gradient(circle_at_78%_26%,rgba(21,128,61,0.14),transparent_28%),linear-gradient(135deg,rgba(2,6,23,1),rgba(15,23,42,0.98))]"
          >
            <div className="absolute inset-0 pointer-events-none opacity-25 [background-image:linear-gradient(rgba(148,163,184,0.12)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.12)_1px,transparent_1px)] [background-size:28px_28px]" />
            <ForceGraph2D
              ref={fgRef}
              width={canvasSize?.width}
              height={canvasSize?.height}
              graphData={{ nodes: renderedNodes, links: renderedLinks }}
              backgroundColor="transparent"
              enableNodeDrag
              enableZoomInteraction
              enablePanInteraction
              cooldownTicks={120}
              d3AlphaDecay={0.045}
              d3VelocityDecay={0.35}
              linkColor={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return COLORS.defense;
                if (mitigationMode) return `${classificationColor(typed.classification)}33`;
                if (typed.focused) return COLORS.ok;
                if (typed.highlighted) return classificationColor(typed.classification);
                return `${classificationColor(typed.classification)}88`;
              }}
              linkWidth={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return typed.focused ? 4.2 : 3.4;
                return typed.focused ? 2.6 : typed.highlighted ? 1.8 : 1.0;
              }}
              linkVisibility={(link) => classificationFilters.has((link as GraphLinkData).classification)}
              linkDirectionalArrowLength={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return 6;
                return typed.highlighted ? 4.5 : 3.2;
              }}
              linkDirectionalArrowRelPos={1}
              linkDirectionalParticles={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return 4;
                return typed.focused ? 3 : typed.highlighted ? 1 : 0;
              }}
              linkDirectionalParticleWidth={() => 1.4}
              nodeColor={(node) => nodeColor(node as GraphNodeData)}
              nodeRelSize={8}
              nodeLabel={(node) => {
                const typed = node as RenderedNode;
                return [
                  typed.id,
                  typed.description,
                  `Route role: ${typed.routeRole}`,
                  typed.evidence.length > 0 ? `Evidence: ${typed.evidence.join(" | ")}` : null,
                ]
                  .filter(Boolean)
                  .join("\n");
              }}
              linkLabel={(link) => {
                const typed = link as RenderedLink;
                const sourceId = graphLinkSourceId(typed);
                const targetId = graphLinkTargetId(typed);
                return [
                  `${sourceId} → ${targetId}`,
                  REASONING_CLASSIFICATION_LABELS[typed.classification],
                  typed.mitigation ? "Mitigation path: attack reasoning to defensive action" : null,
                  `Confidence: ${typed.confidence.toFixed(2)}`,
                  typed.note ?? null,
                ]
                  .filter(Boolean)
                  .join("\n");
              }}
              onNodeClick={(node) => {
                onSelectNode((node as GraphNodeData).id);
                onSelectEdge("");
              }}
              onLinkClick={(link) => {
                const typed = link as GraphLinkData;
                onSelectNode(graphLinkSourceId(typed));
                onSelectEdge(typed.id);
              }}
              onBackgroundClick={() => clearSelection()}
              onEngineStop={() => {
                setStabilized(true);
                if (!autoFittedRef.current) {
                  autoFittedRef.current = true;
                  fitView();
                }
              }}
              nodeCanvasObject={(node, ctx, _globalScale) => {
                const typed = node as RenderedNode;
                const x = typed.x ?? 0;
                const y = typed.y ?? 0;
                const radius = nodeRadius(typed);
                const fill = nodeColor(typed);
                const highlight = typed.focused || typed.highlighted || selection?.kind === "node" && selection.id === typed.id;
                const mitigation = typed.mitigation && mitigationMode;
                const dimmed = mitigationMode && !typed.mitigation && !highlight;

                ctx.save();
                if (dimmed) ctx.globalAlpha = 0.35;
                ctx.beginPath();
                ctx.arc(x, y, radius + (mitigation ? 4.2 : highlight ? 2.2 : 0.8), 0, Math.PI * 2);
                ctx.fillStyle = mitigation ? `${COLORS.defense}44` : highlight ? `${fill}33` : "rgba(15, 23, 42, 0.12)";
                ctx.fill();
                ctx.beginPath();
                ctx.arc(x, y, radius, 0, Math.PI * 2);
                ctx.fillStyle = fill;
                ctx.shadowBlur = mitigation ? 26 : highlight ? 18 : 10;
                ctx.shadowColor = mitigation ? COLORS.defense : fill;
                ctx.fill();
                ctx.shadowBlur = 0;
                ctx.lineWidth = mitigation ? 2.5 : highlight ? 2 : 1;
                ctx.strokeStyle = mitigation ? COLORS.defense : highlight ? "#f8fafc" : "#0f172a";
                ctx.stroke();
                ctx.restore();
              }}
              nodePointerAreaPaint={(node, color, ctx) => {
                const typed = node as RenderedNode;
                const radius = nodeRadius(typed) + 4;
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(typed.x ?? 0, typed.y ?? 0, radius, 0, Math.PI * 2);
                ctx.fill();
              }}
            />

            <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap items-center gap-2">
              <div className="rounded-full border border-slate-800 bg-slate-950/90 px-3 py-1 text-[11px] text-slate-300 backdrop-blur">
                {mitigationMode ? "Mitigation path focus" : selection?.kind === "edge" ? "Edge focus" : selection?.kind === "node" ? "Node focus" : "Route focus"}
              </div>
              <div className="rounded-full border border-slate-800 bg-slate-950/90 px-3 py-1 text-[11px] text-slate-300 backdrop-blur">
                {stabilized ? "Simulation stable" : "Simulation stabilizing"}
              </div>
            </div>
          </div>

          {selection && (
            <div className="xl:absolute xl:bottom-3 xl:right-3 xl:top-3 xl:flex xl:w-[20.5rem]">
              <GraphInspector
                selection={selection}
                nodes={renderedNodes}
                links={renderedLinks}
                resultEdges={result.edges}
                mitigationNodeIds={highlights.mitigationNodes}
                mitigationLinkIds={highlights.mitigationLinks}
                onFocusNode={(nodeId) => onSelectNode(nodeId)}
                onFocusEdge={(edgeId) => onSelectEdge(edgeId)}
                onClearSelection={clearSelection}
              />
            </div>
          )}
        </div>

        <details className="rounded-xl border border-slate-800 bg-slate-950/60">
          <summary className="cursor-pointer select-none px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200">
            Legend & classification key
          </summary>
          <div className="px-3 pb-3">
            <GraphLegend />
          </div>
        </details>
      </div>
    </section>
  );
}
