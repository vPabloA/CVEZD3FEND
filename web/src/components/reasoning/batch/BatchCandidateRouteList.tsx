import { useEffect, useMemo, useState } from "react";
import type { RankedRoute } from "@/lib/reasoningTypes";

const PAGE_SIZE = 50;

export default function BatchCandidateRouteList({
  routes,
  onFocus,
}: {
  routes: RankedRoute[];
  onFocus: (routeId: string) => void;
}) {
  const [limit, setLimit] = useState(PAGE_SIZE);
  useEffect(() => setLimit(PAGE_SIZE), [routes]);
  const ordered = useMemo(
    () => routes.slice().sort((a, b) => b.score - a.score || a.cve_id.localeCompare(b.cve_id) || a.route_id.localeCompare(b.route_id)),
    [routes]
  );
  const visible = ordered.slice(0, limit);
  return (
    <details id="candidate-route-universe" className="rounded-xl border border-slate-800 bg-slate-950">
      <summary className="cursor-pointer select-none px-3 py-3 text-xs font-semibold uppercase tracking-[0.18em] text-slate-400 hover:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">
        Candidate route universe ({ordered.length})
      </summary>
      <div className="border-t border-slate-800 p-3">
        <p className="text-xs leading-relaxed text-slate-500">All candidate records remain available. The list and graph use progressive disclosure; no candidate mapping is reconstructed in the browser.</p>
        <ul className="mt-3 max-h-[28rem] space-y-1.5 overflow-auto">
          {visible.map((route) => (
            <li key={route.route_id}>
              <button type="button" onClick={() => onFocus(route.route_id)} className="w-full rounded-lg border border-slate-800 bg-slate-900/60 p-2 text-left hover:border-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-slate-200">{route.cve_id} · {route.route_id}</span>
                  <span className="text-[11px] text-slate-500">score {route.score.toFixed(3)}</span>
                </div>
                <p className="mt-1 truncate font-mono text-[10px] text-slate-500">{route.node_ids.join(" → ")}</p>
              </button>
            </li>
          ))}
        </ul>
        {visible.length < ordered.length && (
          <button type="button" onClick={() => setLimit((current) => Math.min(current + PAGE_SIZE, ordered.length))} className="mt-3 rounded-lg border border-violet-500/40 px-3 py-2 text-xs font-semibold text-violet-200 hover:bg-violet-950/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-300">
            Show {Math.min(PAGE_SIZE, ordered.length - visible.length)} more routes
          </button>
        )}
        {visible.length < ordered.length && <p className="mt-2 text-[11px] text-slate-500">Showing {visible.length} of {ordered.length} candidate records.</p>}
      </div>
    </details>
  );
}
