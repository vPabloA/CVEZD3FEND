import type { RankedRoute, SelectionBasis } from "@/lib/reasoningTypes";

const BASIS_LABELS: Record<SelectionBasis, string> = {
  coverage_floor: "Cobertura mínima por CVE",
  contextual_utility: "Utilidad contextual",
  top_k_constraint: "Priorizada por restricción Top-K",
  ai_rerank: "Refinada por IA",
};

export default function BatchRouteRanking({ routes, selectedRouteId, onSelect }: { routes: RankedRoute[]; selectedRouteId: string | null; onSelect: (routeId: string) => void }) {
  const ordered = routes.slice().sort((a, b) => (a.selection_rank ?? Number.MAX_SAFE_INTEGER) - (b.selection_rank ?? Number.MAX_SAFE_INTEGER));
  return (
    <section id="ranked-routes" aria-labelledby="ranked-routes-title" className="rounded-xl border border-slate-800 bg-slate-950 p-3">
      <h3 id="ranked-routes-title" className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Ranked routes</h3>
      {ordered.length === 0 ? (
        <p className="mt-3 rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm text-slate-400">No selected routes were produced. Review warnings, missing CVEs and candidate limits.</p>
      ) : (
        <ol className="mt-3 grid gap-2">
          {ordered.map((route) => {
            const active = selectedRouteId === route.route_id;
            const cweIds = route.node_ids.filter((id) => id.startsWith("CWE-"));
            const capecIds = route.node_ids.filter((id) => id.startsWith("CAPEC-"));
            return (
              <li key={route.route_id}>
                <button
                  type="button"
                  aria-pressed={active}
                  onClick={() => onSelect(route.route_id)}
                  className={`w-full rounded-xl border p-3 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${active ? "border-sky-400 bg-sky-950/50" : "border-slate-800 bg-slate-900/60 hover:border-slate-600"}`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="flex h-7 w-7 items-center justify-center rounded-full bg-slate-800 text-xs font-bold text-slate-100">#{route.selection_rank ?? "–"}</span>
                      <span className="font-mono text-xs font-semibold text-slate-100">{route.cve_id}</span>
                    </div>
                    <span className="text-xs text-slate-400">Score {route.score.toFixed(3)}</span>
                  </div>
                  <p className="mt-2 text-xs font-medium text-sky-300">{route.selection_basis ? BASIS_LABELS[route.selection_basis] : "Selected route"}</p>
                  <p className="mt-2 break-words font-mono text-[11px] leading-relaxed text-slate-400">{route.node_ids.join(" → ")}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] text-slate-300">
                    <span className="rounded border border-slate-700 px-1.5 py-0.5">CWE {cweIds.join(", ") || "gap"}</span>
                    <span className="rounded border border-slate-700 px-1.5 py-0.5">CAPEC {capecIds.join(", ") || "gap"}</span>
                    <span className="rounded border border-slate-700 px-1.5 py-0.5">ATT&CK {route.attack_ids.join(", ") || "gap"}</span>
                    <span className="rounded border border-emerald-700/60 px-1.5 py-0.5">D3FEND {route.defend_ids.join(", ") || "gap"}</span>
                    <span className="rounded border border-slate-700 px-1.5 py-0.5">Shared CVEs {route.shared_cve_count}</span>
                    <span className="rounded border border-slate-700 px-1.5 py-0.5">Defense reuse {route.defensive_reuse_count}</span>
                    <span className="rounded border border-slate-700 px-1.5 py-0.5">Complete {(route.completeness * 100).toFixed(0)}%</span>
                  </div>
                  {route.selection_reasons.length > 0 && <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-400">{route.selection_reasons.slice(0, 4).map((reason) => <li key={reason}>{reason}</li>)}</ul>}
                  {route.gaps.length > 0 && <p className="mt-2 rounded border border-amber-500/30 bg-amber-950/20 p-2 text-xs text-amber-200">Gaps: {route.gaps.join(", ")}</p>}
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
