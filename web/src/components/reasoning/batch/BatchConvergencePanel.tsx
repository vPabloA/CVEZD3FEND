import { useMemo } from "react";
import type { RankedRoute } from "@/lib/reasoningTypes";

interface ConvergenceRecord {
  id: string;
  cves: string[];
  routeCount: number;
  related: string[];
}

function deriveRecords(values: string[], routes: RankedRoute[], kind: "attack" | "defense"): ConvergenceRecord[] {
  return values.map((id) => {
    const matching = routes.filter((route) => (kind === "attack" ? route.attack_ids : route.defend_ids).includes(id));
    return {
      id,
      cves: [...new Set(matching.map((route) => route.cve_id))].sort(),
      routeCount: matching.length,
      related: [
        ...new Set(
          matching.flatMap((route) => (kind === "attack" ? route.defend_ids : route.attack_ids))
        ),
      ].sort(),
    };
  });
}

export default function BatchConvergencePanel({
  title,
  values,
  routes,
  kind,
}: {
  title: string;
  values: string[];
  routes: RankedRoute[];
  kind: "attack" | "defense";
}) {
  const records = useMemo(() => deriveRecords(values, routes, kind), [kind, routes, values]);
  return (
    <section aria-label={title} className="rounded-xl border border-slate-800 bg-slate-950 p-3">
      <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{title}</h3>
      {records.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">No cross-CVE convergence in this view.</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {records.map((record) => (
            <li key={record.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className={`rounded-full border px-2.5 py-1 font-mono text-xs ${kind === "attack" ? "border-rose-500/40 bg-rose-950/30 text-rose-200" : "border-emerald-500/40 bg-emerald-950/30 text-emerald-200"}`}>{record.id}</span>
                <span className="text-[11px] text-slate-400">{record.cves.length} CVE · {record.routeCount} route{record.routeCount === 1 ? "" : "s"}</span>
              </div>
              <p className="mt-2 text-xs text-slate-400">CVEs: {record.cves.join(", ")}</p>
              <p className="mt-1 text-xs text-slate-500">{kind === "attack" ? "Associated D3FEND" : "Mitigated ATT&CK"}: {record.related.join(", ") || "No downstream relation in this view"}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
