import ReasoningEdgesList from "./ReasoningEdgesList";
import type { ReasoningEdge } from "@/lib/reasoningTypes";

/**
 * Provenance ledger — edges grouped by the source/framework that produced
 * them (`/api/reason` `provenance` map). Each group is a collapsible,
 * independently-bounded edge list (UIX_CONTRACT §1/§2).
 */
export default function ProvenancePanel({ provenance }: { provenance: Record<string, ReasoningEdge[]> }) {
  const groups = Object.entries(provenance).filter(([, edges]) => edges.length > 0);

  return (
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-slate-700">Provenance ledger</h2>
      {groups.length === 0 ? (
        <p className="mt-2 text-sm italic text-slate-400">No provenance data available for this CVE.</p>
      ) : (
        <div className="mt-2 flex flex-col gap-2">
          {groups.map(([source, edges], i) => (
            <details key={source} open={i === 0} className="rounded border border-slate-100">
              <summary className="cursor-pointer select-none rounded bg-slate-50 px-2 py-1.5 text-sm font-medium text-slate-700">
                {source} <span className="font-normal text-slate-400">({edges.length})</span>
              </summary>
              <div className="p-2">
                <ReasoningEdgesList edges={edges} />
              </div>
            </details>
          ))}
        </div>
      )}
    </section>
  );
}
