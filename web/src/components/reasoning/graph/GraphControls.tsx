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

const ACTION_BUTTON =
  "rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-link";

export default function GraphControls({
  mode,
  onModeChange,
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
