import type { BatchNarrative } from "@/lib/reasoningTypes";

const PANELS = [
  ["Executive", "executive_summary_es"],
  ["Operational", "operational_summary_es"],
  ["Technical", "technical_summary_es"],
] as const;

export default function BatchNarrativePanel({ narrative }: { narrative: BatchNarrative }) {
  return (
    <section id="batch-narrative" aria-labelledby="batch-narrative-title" className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-sky-400">Backend-authored narrative</p>
      <h2 id="batch-narrative-title" className="mt-1 text-lg font-semibold text-slate-100">Executive, operational and technical reading</h2>
      <div className="mt-4 grid gap-3 lg:grid-cols-3">
        {PANELS.map(([label, key]) => (
          <article key={key} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="text-sm font-semibold text-slate-200">{label}</h3>
            <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-slate-400">{narrative[key] || "No narrative was returned for this audience."}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
