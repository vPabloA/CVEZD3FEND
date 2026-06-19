import { REASONING_CLASSIFICATION_ICONS, REASONING_CLASSIFICATION_LABELS, classificationClass } from "@/lib/colors";
import GraphModeSelector from "./GraphModeSelector";
import type { GraphLayout, GraphMode, GraphRouteEmphasis } from "./graphTypes";
import type { ReasoningEdgeClassification } from "@/lib/reasoningTypes";

const CLASSIFICATIONS: ReasoningEdgeClassification[] = [
  "official_explicit",
  "official_incomplete",
  "dataset_derived",
  "analytical_inferred",
  "conditional",
  "weak_fit",
  "unverified",
];

const ACTION_BUTTON =
  "rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-link";

const TOGGLE_BUTTON =
  "rounded-md px-2.5 py-1.5 text-xs font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-link";

export default function GraphControls({
  mode,
  onModeChange,
  layout,
  onLayoutChange,
  routeEmphasis,
  onRouteEmphasisChange,
  showContext,
  onToggleContext,
  classificationFilters,
  onToggleClassification,
  onFitView,
  onResetSelection,
  onClearSelection,
  hiddenNodeCount,
  hiddenLinkCount,
}: {
  mode: GraphMode;
  onModeChange: (mode: GraphMode) => void;
  layout: GraphLayout;
  onLayoutChange: (layout: GraphLayout) => void;
  routeEmphasis: GraphRouteEmphasis;
  onRouteEmphasisChange: (emphasis: GraphRouteEmphasis) => void;
  showContext: boolean;
  onToggleContext: () => void;
  classificationFilters: Set<ReasoningEdgeClassification>;
  onToggleClassification: (classification: ReasoningEdgeClassification) => void;
  onFitView: () => void;
  onResetSelection: () => void;
  onClearSelection: () => void;
  hiddenNodeCount: number;
  hiddenLinkCount: number;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <GraphModeSelector mode={mode} onChange={onModeChange} />
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Graph view actions">
          <button type="button" onClick={onFitView} className={ACTION_BUTTON}>
            Fit view
          </button>
          <button type="button" onClick={onResetSelection} className={ACTION_BUTTON}>
            Reset route focus
          </button>
          <button type="button" onClick={onClearSelection} className={ACTION_BUTTON}>
            Clear selection
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Trace controls</span>
        <div className="inline-flex gap-0.5 rounded-lg border border-slate-800 bg-slate-900/80 p-0.5" role="group" aria-label="Stage layout">
          <button
            type="button"
            aria-pressed={layout === "trace"}
            title="Semantic lanes: CVE → CWE → CAPEC → ATT&CK → D3FEND"
            onClick={() => onLayoutChange("trace")}
            className={`${TOGGLE_BUTTON} ${layout === "trace" ? "bg-slate-800 text-sky-300 shadow-sm ring-1 ring-sky-500/40" : "text-slate-400 hover:text-slate-200"}`}
          >
            Trace layout
          </button>
          <button
            type="button"
            aria-pressed={layout === "force"}
            title="Free force simulation"
            onClick={() => onLayoutChange("force")}
            className={`${TOGGLE_BUTTON} ${layout === "force" ? "bg-slate-800 text-sky-300 shadow-sm ring-1 ring-sky-500/40" : "text-slate-400 hover:text-slate-200"}`}
          >
            Force layout
          </button>
        </div>
        <button
          type="button"
          aria-pressed={routeEmphasis === "primary"}
          title="Cherry-pick the primary trace: park weak-fit and condition-dependent relations off-stage"
          onClick={() => onRouteEmphasisChange(routeEmphasis === "primary" ? "all" : "primary")}
          className={`${TOGGLE_BUTTON} border ${
            routeEmphasis === "primary"
              ? "border-sky-500/60 bg-sky-950/60 text-sky-200"
              : "border-slate-700 bg-slate-900 text-slate-300 hover:border-sky-400 hover:text-sky-300"
          }`}
        >
          Primary route
        </button>
        <button
          type="button"
          aria-pressed={showContext}
          title="Show or park evidence, gaps and context nodes that are not on the trace"
          onClick={onToggleContext}
          className={`${TOGGLE_BUTTON} border ${
            showContext
              ? "border-slate-700 bg-slate-900 text-slate-300 hover:border-sky-400 hover:text-sky-300"
              : "border-amber-500/50 bg-amber-950/40 text-amber-200"
          }`}
        >
          {showContext ? "Hide context" : "Show context"}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Evidence filters</span>
        {CLASSIFICATIONS.map((classification) => {
          const active = classificationFilters.has(classification);
          return (
            <button
              key={classification}
              type="button"
              aria-pressed={active}
              onClick={() => onToggleClassification(classification)}
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                active ? classificationClass(classification) : "border-slate-700 bg-slate-900 text-slate-500 line-through opacity-70"
              }`}
            >
              <span aria-hidden="true">{REASONING_CLASSIFICATION_ICONS[classification]}</span>
              {REASONING_CLASSIFICATION_LABELS[classification]}
            </button>
          );
        })}
        {(hiddenNodeCount > 0 || hiddenLinkCount > 0) && (
          <span className="ml-auto rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-400" title="Capped for readability — switch modes or focus a node to surface more">
            {hiddenNodeCount} nodes · {hiddenLinkCount} edges off-stage
          </span>
        )}
      </div>
    </div>
  );
}
