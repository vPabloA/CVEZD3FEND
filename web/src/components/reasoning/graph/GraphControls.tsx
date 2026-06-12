import { REASONING_CLASSIFICATION_ICONS, REASONING_CLASSIFICATION_LABELS, classificationClass } from "@/lib/colors";
import GraphModeSelector from "./GraphModeSelector";
import type { GraphMode } from "./graphTypes";
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

export default function GraphControls({
  mode,
  onModeChange,
  classificationFilters,
  onToggleClassification,
  onFitView,
  onResetSelection,
  onClearSelection,
  stabilized,
  hiddenNodeCount,
  hiddenLinkCount,
}: {
  mode: GraphMode;
  onModeChange: (mode: GraphMode) => void;
  classificationFilters: Set<ReasoningEdgeClassification>;
  onToggleClassification: (classification: ReasoningEdgeClassification) => void;
  onFitView: () => void;
  onResetSelection: () => void;
  onClearSelection: () => void;
  stabilized: boolean;
  hiddenNodeCount: number;
  hiddenLinkCount: number;
}) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/80 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <GraphModeSelector mode={mode} onChange={onModeChange} />
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{stabilized ? "Stabilized" : "Stabilizing…"}</span>
          <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{hiddenNodeCount} hidden nodes</span>
          <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{hiddenLinkCount} hidden edges</span>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onFitView}
          className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          Fit view
        </button>
        <button
          type="button"
          onClick={onResetSelection}
          className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          Reset route focus
        </button>
        <button
          type="button"
          onClick={onClearSelection}
          className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          Clear selection
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {CLASSIFICATIONS.map((classification) => {
          const active = classificationFilters.has(classification);
          return (
            <button
              key={classification}
              type="button"
              aria-pressed={active}
              onClick={() => onToggleClassification(classification)}
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[11px] font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                active ? classificationClass(classification) : "border-slate-700 bg-slate-900 text-slate-500 line-through opacity-70"
              }`}
            >
              <span aria-hidden="true">{REASONING_CLASSIFICATION_ICONS[classification]}</span>
              {REASONING_CLASSIFICATION_LABELS[classification]}
            </button>
          );
        })}
      </div>
    </div>
  );
}
