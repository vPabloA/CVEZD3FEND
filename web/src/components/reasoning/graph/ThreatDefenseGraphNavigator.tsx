import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { ForceGraphMethods } from "react-force-graph-2d";
import { COLORS, REASONING_CLASSIFICATION_LABELS } from "@/lib/colors";
import { buildGraphModel } from "./graphAdapter";
import GraphControls from "./GraphControls";
import GraphInspector from "./GraphInspector";
import GraphLegend from "./GraphLegend";
import type { GraphLayout, GraphLinkData, GraphMode, GraphModel, GraphNodeData, GraphRouteEmphasis, GraphSelection } from "./graphTypes";
import { buildHighlightState } from "./pathHighlighting";
import { graphLinkSourceId, graphLinkTargetId, isDefensiveGraphNode } from "./graphRuntime";
import { applyTraceLayout, traceLayerIdForNode, type TraceLayoutPlan } from "./traceLayout";
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

// Classification is never encoded with color alone (UIX_CONTRACT §7): solid
// strokes for official/dataset edges, distinct dash patterns for everything
// the reasoning plane inferred, conditioned or could not verify.
function classificationDash(classification: ReasoningEdgeClassification): number[] | null {
  switch (classification) {
    case "official_explicit":
    case "official_incomplete":
    case "dataset_derived":
      return null;
    case "analytical_inferred":
      return [6, 3];
    case "conditional":
      return [5, 4];
    case "weak_fit":
      return [2, 3];
    case "unverified":
      return [2, 5];
  }
  return null;
}

function classificationStrokeWeight(classification: ReasoningEdgeClassification): number {
  switch (classification) {
    case "official_explicit":
      return 1.35;
    case "official_incomplete":
    case "dataset_derived":
      return 1.18;
    case "analytical_inferred":
      return 1.05;
    case "conditional":
      return 0.95;
    case "weak_fit":
    case "unverified":
      return 0.82;
  }
  return 1;
}

function nodeColor(node: GraphNodeData): string {
  if (node.routeRole === "weak-fit") return COLORS.template;
  if (node.routeRole === "conditional") return COLORS.conditional;
  if (node.routeRole === "defensive" || node.kind === "defend" || node.kind === "control" || node.kind === "mitigation") return COLORS.defense;
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

function isSecondaryEmphasisLink(link: GraphLinkData): boolean {
  return link.conditional || link.weakFit || link.classification === "conditional" || link.classification === "weak_fit" || link.classification === "unverified";
}

export interface GraphNavigatorContext {
  eyebrow?: string;
  title?: string;
  badge?: string;
  status?: string;
  sourceMode?: string;
  reviewRequired?: boolean;
  errors?: string[];
  rootId?: string;
  scopeLabel?: string;
}

export default function ThreatDefenseGraphNavigator({
  result,
  graphBuilder,
  context,
  selection,
  onSelectNode,
  onSelectEdge,
  onClearSelection,
}: {
  result?: ReasoningResult;
  graphBuilder?: (mode: GraphMode, selection: GraphSelection) => GraphModel;
  context?: GraphNavigatorContext;
  selection: GraphSelection;
  onSelectNode: (nodeId: string) => void;
  onSelectEdge: (edgeId: string) => void;
  onClearSelection: () => void;
}) {
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined);
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const autoFittedRef = useRef(false);
  const layoutPlanRef = useRef<TraceLayoutPlan | null>(null);
  const [canvasSize, setCanvasSize] = useState<{ width: number; height: number } | null>(null);
  const [mode, setMode] = useState<GraphMode>("focused-route");
  const [layout, setLayout] = useState<GraphLayout>("trace");
  const [routeEmphasis, setRouteEmphasis] = useState<GraphRouteEmphasis>("all");
  const [showContext, setShowContext] = useState(true);
  const [classificationFilters, setClassificationFilters] = useState<Set<ReasoningEdgeClassification>>(new Set(DEFAULT_CLASSIFICATIONS));
  const [stabilized, setStabilized] = useState(false);
  const classificationFilterKey = [...classificationFilters].sort().join("|");
  const selectionFilterKey = selection ? `${selection.kind}:${selection.id}` : "none";
  const viewKey = `${layout}|${routeEmphasis}|${showContext}`;
  const mitigationMode = mode === "mitigation-path";

  useEffect(() => {
    setStabilized(false);
  }, [result, graphBuilder, context, mode, classificationFilterKey, selectionFilterKey, viewKey]);

  // Re-frame the route once per data/mode/layout change so the graph fills the stage.
  useEffect(() => {
    autoFittedRef.current = false;
  }, [result, graphBuilder, context, mode, classificationFilterKey, viewKey]);

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

  const graph = useMemo(() => {
    if (graphBuilder) return graphBuilder(mode, selection);
    if (result) return buildGraphModel(result, mode, selection);
    return {
      nodes: [],
      links: [],
      hiddenNodeCount: 0,
      hiddenLinkCount: 0,
      visibleNodeIds: new Set<string>(),
      visibleLinkIds: new Set<string>(),
      routeChain: [],
      routeConfidence: 0,
    };
  }, [graphBuilder, result, mode, selection]);
  const displayErrors = context?.errors ?? result?.errors ?? [];
  const reviewRequired = context?.reviewRequired ?? result?.human_review.required ?? false;
  const sourceMode = context?.sourceMode ?? result?.source_mode ?? "catalog-backed";
  const inspectorEdges = useMemo(() =>
    result?.edges ?? graph.links.map((link) => ({
      id: link.id,
      source: graphLinkSourceId(link),
      target: graphLinkTargetId(link),
      type: link.type,
      classification: link.classification,
      confidence: link.confidence,
      evidence: link.evidence,
      source_refs: link.sourceRefs,
      source_url: link.sourceUrl,
      note: link.note,
      deterministic: link.deterministic,
      inferred: link.inferred,
      conditional: link.conditional,
      weak_fit: link.weakFit,
    })),
  [graph.links, result?.edges]);
  const highlights = useMemo(() => buildHighlightState(graph, selection, mode), [graph, selection, mode]);
  const routeChainSet = useMemo(() => new Set(graph.routeChain), [graph.routeChain]);

  // Context cherry-picking: evidence/gap/candidate/context nodes can be parked
  // off-stage without losing the trace itself.
  const hiddenContextIds = useMemo(() => {
    if (showContext) return new Set<string>();
    const hidden = new Set<string>();
    graph.nodes.forEach((node) => {
      if (traceLayerIdForNode(node) !== "context") return;
      if (routeChainSet.has(node.id)) return;
      if (selection?.kind === "node" && selection.id === node.id) return;
      hidden.add(node.id);
    });
    return hidden;
  }, [graph.nodes, routeChainSet, selection, showContext]);

  const hiddenBranchIds = useMemo(() => {
    if (routeEmphasis === "all") return new Set<string>();
    const hidden = new Set<string>();
    graph.nodes.forEach((node) => {
      const secondaryBranch = node.routeRole === "conditional" || node.routeRole === "weak-fit";
      if (!secondaryBranch) return;
      if (routeChainSet.has(node.id)) return;
      if (selection?.kind === "node" && selection.id === node.id) return;
      hidden.add(node.id);
    });
    return hidden;
  }, [graph.nodes, routeChainSet, routeEmphasis, selection]);

  const hiddenStageIds = useMemo(() => new Set([...hiddenContextIds, ...hiddenBranchIds]), [hiddenBranchIds, hiddenContextIds]);

  const renderedLinks = useMemo(
    () =>
      graph.links
        .filter((link) => classificationFilters.has(link.classification))
        .filter((link) => routeEmphasis === "all" || !isSecondaryEmphasisLink(link) || (selection?.kind === "edge" && selection.id === link.id))
        .filter((link) => !hiddenStageIds.has(graphLinkSourceId(link)) && !hiddenStageIds.has(graphLinkTargetId(link)))
        .map((link) => ({
          ...link,
          highlighted: highlights.highlightedLinks.has(link.id),
          focused: highlights.focusedLinks.has(link.id),
          mitigation: highlights.mitigationLinks.has(link.id),
        })) as RenderedLink[],
    [classificationFilters, graph.links, hiddenStageIds, highlights.focusedLinks, highlights.highlightedLinks, highlights.mitigationLinks, routeEmphasis, selection]
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
      .filter((node) => visibleIds.has(node.id) && !hiddenStageIds.has(node.id))
      .map((node) => ({
        ...node,
        highlighted: highlights.highlightedNodes.has(node.id),
        focused: highlights.focusedNodes.has(node.id),
        mitigation: highlights.mitigationNodes.has(node.id),
      })) as RenderedNode[];
  }, [graph.nodes, hiddenStageIds, highlights.focusedNodes, highlights.highlightedNodes, highlights.mitigationNodes, renderedLinks]);

  // Trace layout: pin fresh node copies to semantic lanes (CVE → CWE → CAPEC →
  // ATT&CK → D3FEND → context) so the stage reads as an attack-to-defense trace
  // instead of a free-floating force cloud. Fresh copies per layout switch make
  // react-force-graph re-stage the route (it diffs nodes by object identity);
  // force layout stays available as an escape hatch.
  const stagedData = useMemo(() => {
    const nodes = renderedNodes.map((node) => ({ ...node }));
    // Re-normalize endpoints to ids so d3 re-resolves them against the fresh
    // node copies (react-force-graph mutates endpoints into object refs).
    const links = renderedLinks.map((link) => ({ ...link, source: graphLinkSourceId(link), target: graphLinkTargetId(link) }));
    if (layout === "trace") {
      layoutPlanRef.current = applyTraceLayout(nodes, graph.routeChain);
    } else {
      layoutPlanRef.current = null;
    }
    return { nodes, links };
  }, [graph.routeChain, layout, renderedLinks, renderedNodes]);

  const selectedNodeVisible = selection?.kind === "node" ? renderedNodes.some((node) => node.id === selection.id) : true;
  const selectedEdgeVisible = selection?.kind === "edge" ? renderedLinks.some((link) => link.id === selection.id) : true;
  const selectedHidden = Boolean(selection && (!selectedNodeVisible || !selectedEdgeVisible));
  const offStageNodeCount = graph.hiddenNodeCount + Math.max(0, graph.nodes.length - renderedNodes.length);
  const offStageLinkCount = graph.hiddenLinkCount + Math.max(0, graph.links.length - renderedLinks.length);
  const stateNotices = useMemo(() => {
    const notices: { tone: "info" | "warning"; text: string }[] = [];
    if (graph.nodes.length === 0 && displayErrors.length > 0) {
      notices.push({ tone: "warning", text: "Graph data is unavailable for this analysis. Review the API status and try Analyze again." });
    } else if (graph.nodes.length === 0) {
      notices.push({ tone: "info", text: context ? "No graphable route was produced for the active CVE projection." : "No graphable route was produced for this CVE." });
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
  }, [context, displayErrors.length, graph.links.length, graph.nodes, graph.routeChain, selectedHidden, selection?.kind]);

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
    const rootId = graph.routeChain[0] ?? context?.rootId ?? result?.normalized_input ?? result?.input;
    if (rootId) onSelectNode(rootId);
    else onClearSelection();
    setMode("focused-route");
    setRouteEmphasis("all");
    setShowContext(true);
    setClassificationFilters(new Set(DEFAULT_CLASSIFICATIONS));
    setStabilized(false);
    window.requestAnimationFrame(() => fitView());
  };

  const clearSelection = () => onClearSelection();
  const hasSelectionFocus = Boolean(selection);

  return (
    <section id="threat-defense-graph" className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl">
      <div className="border-b border-slate-800/80 bg-slate-950/90 px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">{context?.eyebrow ?? "Threat-Defense Trace Graph Navigator"}</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold text-slate-100">{context?.title ?? "CVE → D3FEND trace"}</h2>
              <span className="rounded-full border border-sky-500/40 bg-sky-950/40 px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.18em] text-sky-300">
                {context?.badge ?? "Trace Explorer"}
              </span>
            </div>
            {graph.routeChain.length > 0 ? (
              <div className="mt-2 flex flex-wrap items-center gap-1" title={graph.routeChain.join(" → ")} aria-label="Trace cherry picker">
                {graph.routeChain.map((id, index) => {
                  const active = selection?.kind === "node" && selection.id === id;
                  return (
                    <span key={id} className="flex items-center gap-1">
                      <button
                        type="button"
                        aria-label={`Trace step ${index + 1}: ${id}`}
                        aria-pressed={active}
                        onClick={() => {
                          onSelectNode(id);
                        }}
                        className={`rounded border px-1.5 py-0.5 font-mono text-[11px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                          active
                            ? "border-sky-400 bg-sky-950/70 text-sky-200 shadow-[0_0_8px_rgba(56,189,248,0.35)]"
                            : "border-slate-700 bg-slate-900 text-slate-300 hover:border-sky-500/60 hover:text-sky-200"
                        }`}
                      >
                        {id}
                      </button>
                      {index < graph.routeChain.length - 1 && (
                        <span className="text-slate-600" aria-hidden="true">
                          →
                        </span>
                      )}
                    </span>
                  );
                })}
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
            <span className={`rounded-full border px-2 py-1 ${reviewRequired ? "border-amber-400 bg-amber-50 text-amber-800" : "border-ok bg-green-50 text-ok"}`}>
              {reviewRequired ? "Human review required" : context?.status ?? "Route validated"}
            </span>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{sourceMode}</span>
            {context?.scopeLabel && <span className="rounded-full border border-violet-500/40 bg-violet-950/40 px-2 py-1 text-violet-200">{context.scopeLabel}</span>}
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
          layout={layout}
          onLayoutChange={setLayout}
          routeEmphasis={routeEmphasis}
          onRouteEmphasisChange={setRouteEmphasis}
          showContext={showContext}
          onToggleContext={() => setShowContext((current) => !current)}
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
          hiddenNodeCount={offStageNodeCount}
          hiddenLinkCount={offStageLinkCount}
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
              graphData={stagedData}
              backgroundColor="transparent"
              enableNodeDrag
              enableZoomInteraction
              enablePanInteraction
              cooldownTicks={120}
              d3AlphaDecay={0.045}
              d3VelocityDecay={0.35}
              onRenderFramePre={(ctx, globalScale) => {
                const plan = layoutPlanRef.current;
                if (!plan || layout !== "trace" || plan.lanes.length === 0) return;
                const labelSize = Math.min(22, Math.max(8, 11 / globalScale));
                ctx.save();
                plan.lanes.forEach((lane) => {
                  const defensive = lane.layer.defensive;
                  const contextLane = lane.layer.id === "context";
                  // Defensive destination band: D3FEND lane is tinted so the
                  // path toward defense is visually explicit, not decorative.
                  if (defensive) {
                    ctx.fillStyle = mitigationMode ? "rgba(21,128,61,0.16)" : "rgba(21,128,61,0.09)";
                    ctx.fillRect(lane.x - 72, plan.top - 26, 144, plan.bottom - plan.top + 38);
                  }
                  ctx.strokeStyle = defensive ? "rgba(34,197,94,0.35)" : "rgba(100,116,139,0.22)";
                  ctx.lineWidth = 1 / globalScale;
                  ctx.setLineDash(defensive ? [] : [4, 5]);
                  ctx.beginPath();
                  ctx.moveTo(lane.x, plan.top - 10);
                  ctx.lineTo(lane.x, plan.bottom + 6);
                  ctx.stroke();
                  ctx.setLineDash([]);
                  ctx.font = `700 ${labelSize}px Inter, system-ui, sans-serif`;
                  ctx.textAlign = "center";
                  ctx.textBaseline = "bottom";
                  ctx.fillStyle = defensive ? "rgba(134,239,172,0.95)" : contextLane ? "rgba(100,116,139,0.8)" : "rgba(148,163,184,0.9)";
                  ctx.fillText(lane.layer.label, lane.x, plan.top - 14);
                });
                ctx.restore();
              }}
              linkColor={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return COLORS.defense;
                if (mitigationMode) return `${classificationColor(typed.classification)}33`;
                if (typed.focused) return COLORS.ok;
                if (typed.highlighted) return classificationColor(typed.classification);
                return `${classificationColor(typed.classification)}${hasSelectionFocus ? "30" : "88"}`;
              }}
              linkWidth={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return typed.focused ? 4.2 : 3.4;
                const classificationWeight = classificationStrokeWeight(typed.classification);
                return (typed.focused ? 2.6 : typed.highlighted ? 1.8 : 1.0) * classificationWeight;
              }}
              linkLineDash={(link) => {
                const typed = link as RenderedLink;
                if (typed.mitigation && mitigationMode) return null;
                return classificationDash(typed.classification);
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
                  typed.cveIds.length > 0 ? `Related CVEs: ${typed.cveIds.join(", ")}` : null,
                  typed.routeIds.length > 0 ? `Routes: ${typed.routeIds.length}` : null,
                  typed.sharedCveCount > 1 ? `Shared by ${typed.sharedCveCount} CVEs` : null,
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
              nodeCanvasObject={(node, ctx, globalScale) => {
                const typed = node as RenderedNode;
                const x = typed.x ?? 0;
                const y = typed.y ?? 0;
                const radius = nodeRadius(typed);
                const fill = nodeColor(typed);
                const highlight = typed.focused || typed.highlighted || selection?.kind === "node" && selection.id === typed.id;
                const mitigation = typed.mitigation && mitigationMode;
                const defensive = isDefensiveGraphNode(typed);
                const onChain = routeChainSet.has(typed.id);
                const dimmed = (mitigationMode && !typed.mitigation && !highlight) || (!mitigationMode && hasSelectionFocus && !highlight && !onChain);

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
                // Defensive destination ring: D3FEND/control/mitigation nodes
                // carry a second ring so defense reads even when dimmed.
                if (defensive) {
                  ctx.beginPath();
                  ctx.arc(x, y, radius + 2.6, 0, Math.PI * 2);
                  ctx.lineWidth = 1;
                  ctx.strokeStyle = mitigation ? "#86efac" : `${COLORS.defense}AA`;
                  ctx.stroke();
                }
                if ((typed.kind === "attack" || typed.kind === "defend") && typed.sharedCveCount > 1) {
                  const badgeRadius = Math.max(4.5, 6 / globalScale);
                  const badgeX = x + radius * 0.78;
                  const badgeY = y - radius * 0.78;
                  ctx.beginPath();
                  ctx.arc(badgeX, badgeY, badgeRadius, 0, Math.PI * 2);
                  ctx.fillStyle = "#f8fafc";
                  ctx.fill();
                  ctx.lineWidth = Math.max(0.8, 1 / globalScale);
                  ctx.strokeStyle = typed.kind === "attack" ? COLORS.offense : COLORS.defense;
                  ctx.stroke();
                  ctx.font = `700 ${Math.max(5.5, 7 / globalScale)}px ui-monospace, SFMono-Regular, monospace`;
                  ctx.textAlign = "center";
                  ctx.textBaseline = "middle";
                  ctx.fillStyle = "#0f172a";
                  ctx.fillText(String(typed.sharedCveCount), badgeX, badgeY + 0.2);
                }
                // Trace readability: label the spine and any focused nodes
                // directly on the stage so the route reads without tooltips.
                const zoomLabel = defensive ? false : globalScale > 1.6;
                const showLabel = layout === "trace" ? onChain || (hasSelectionFocus && highlight) || (mitigationMode && mitigation) || zoomLabel : (highlight && globalScale > 1.2) || globalScale > 2.2;
                if (showLabel) {
                  const fontSize = Math.min(13, Math.max(6.5, 10 / globalScale));
                  ctx.font = `${onChain ? "700" : "400"} ${fontSize}px ui-monospace, SFMono-Regular, monospace`;
                  ctx.textAlign = "center";
                  ctx.textBaseline = "top";
                  ctx.fillStyle = dimmed ? "rgba(148,163,184,0.55)" : onChain ? "#e2e8f0" : "rgba(203,213,225,0.85)";
                  ctx.fillText(typed.shortLabel, x, y + radius + 3.5);
                }
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
                {layout === "trace" ? "Trace layout · CVE → D3FEND" : "Force layout"}
              </div>
              {routeEmphasis === "primary" && (
                <div className="rounded-full border border-sky-500/40 bg-sky-950/70 px-3 py-1 text-[11px] text-sky-200 backdrop-blur">
                  Primary route emphasis
                </div>
              )}
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
                resultEdges={inspectorEdges}
                routeChain={graph.routeChain}
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
