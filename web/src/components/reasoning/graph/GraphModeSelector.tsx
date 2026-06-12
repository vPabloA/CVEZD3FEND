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
    <div className="inline-flex flex-wrap gap-0.5 rounded-lg border border-slate-800 bg-slate-900/80 p-0.5" role="tablist" aria-label="Graph mode">
      {MODES.map((item) => {
        const active = item.value === mode;
        const mitigation = item.value === "mitigation-path";
        return (
          <button
            key={item.value}
            type="button"
            role="tab"
            aria-selected={active}
            title={`${item.label} — ${item.hint}`}
            onClick={() => onChange(item.value)}
            className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
              active
                ? mitigation
                  ? "bg-green-950/80 text-green-300 shadow-sm ring-1 ring-defense/60"
                  : "bg-slate-800 text-sky-300 shadow-sm ring-1 ring-sky-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
