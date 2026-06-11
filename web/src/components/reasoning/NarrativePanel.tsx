import type { ReasoningNarrative } from "@/lib/reasoningTypes";

const SECTIONS: { key: keyof ReasoningNarrative; label: string }[] = [
  { key: "executive_summary_es", label: "Executive summary" },
  { key: "summary_es", label: "Summary" },
  { key: "decision_context_es", label: "Decision context" },
  { key: "risk_rationale_es", label: "Risk rationale" },
  { key: "tier1_conclusion_es", label: "Tier 1 conclusion" },
];

/**
 * The reasoning engine's narrative is generated in Spanish (NARRATIVE_CONTRACT).
 * Section labels stay in the workbench's UI language; content is shown verbatim
 * — this is the visible "Reasoning Summary", not a hidden chain-of-thought.
 */
export default function NarrativePanel({ narrative }: { narrative: ReasoningNarrative }) {
  const sections = SECTIONS.filter(({ key }) => narrative[key]?.trim());
  if (sections.length === 0) {
    return (
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-sm font-semibold text-slate-700">Reasoning summary</h2>
        <p className="mt-2 text-sm italic text-slate-400">No narrative available for this CVE.</p>
      </section>
    );
  }
  return (
    <section className="flex flex-col gap-3 rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-slate-700">Reasoning summary</h2>
      <div className="flex flex-col gap-3">
        {sections.map(({ key, label }) => (
          <div key={key}>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</h3>
            <p className="whitespace-pre-line text-sm leading-relaxed text-slate-700" lang="es">
              {narrative[key]}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
