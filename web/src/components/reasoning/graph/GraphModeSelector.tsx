import type { GraphMode } from "./graphTypes";

const MODES: { value: GraphMode; label: string; hint: string }[] = [
  { value: "focused-route", label: "Focused Route", hint: "clear path" },
  { value: "reasoning-neighborhood", label: "Reasoning Neighborhood", hint: "local context" },
  { value: "mitigation-path", label: "Mitigation Path", hint: "defensive flow" },
  { value: "full-traceability", label: "Full Traceability", hint: "complete trail" },
  { value: "evidence-view", label: "Evidence View", hint: "supporting facts" },
];

export default function GraphModeSelector({ mode, onChange }: { mode: GraphMode; onChange: (mode: GraphMode) => void }) {
  return (
    <div className="flex flex-wrap gap-2" role="tablist" aria-label="Graph mode">
      {MODES.map((item) => {
        const active = item.value === mode;
        return (
          <button
            key={item.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(item.value)}
            className={`rounded-full border px-3 py-1.5 text-xs font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
              active ? "border-link bg-blue-50 text-link" : "border-slate-700 bg-slate-900/80 text-slate-300 hover:border-slate-500"
            }`}
          >
            <span>{item.label}</span>
            <span className="ml-1.5 text-[10px] uppercase tracking-wide opacity-70">{item.hint}</span>
          </button>
        );
      })}
    </div>
  );
}
