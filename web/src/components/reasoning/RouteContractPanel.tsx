import { Link } from "react-router-dom";
import type { ReasoningRouteContract } from "@/lib/reasoningTypes";

const BUCKETS: { key: keyof ReasoningRouteContract; label: string; hint: string; classes: string }[] = [
  { key: "canonical_chain", label: "Canonical chain", hint: "CVE → CWE → CAPEC → ATT&CK → D3FEND", classes: "border-ok bg-green-50 text-ok" },
  { key: "primary_nodes", label: "Primary nodes", hint: "Directly relevant to this route", classes: "border-link bg-blue-50 text-link" },
  { key: "secondary_nodes", label: "Secondary nodes", hint: "Supporting context", classes: "border-template bg-slate-100 text-template" },
  { key: "conditional_nodes", label: "Conditional nodes", hint: "Apply only under a specific precondition", classes: "border-conditional bg-cyan-50 text-conditional" },
  { key: "defensive_nodes", label: "Defensive nodes", hint: "Controls, detections and mitigations", classes: "border-defense bg-green-50 text-defense" },
  { key: "weak_fit_nodes", label: "Weak-fit nodes", hint: "Low-confidence, likely not applicable", classes: "border-template bg-slate-100 text-template border-dashed" },
];

/** The reasoning engine's classified route contract — 6 node buckets, each linking into the existing node-detail view. */
export default function RouteContractPanel({ route }: { route: ReasoningRouteContract }) {
  const populated = BUCKETS.filter(({ key }) => route[key]?.length > 0);
  if (populated.length === 0) {
    return (
      <section className="rounded-md border border-slate-200 bg-white p-4">
        <h2 className="text-sm font-semibold text-slate-700">Route contract</h2>
        <p className="mt-2 text-sm italic text-slate-400">No route contract was produced for this CVE.</p>
      </section>
    );
  }
  return (
    <section className="flex flex-col gap-3 rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-slate-700">Route contract</h2>
      <div className="flex flex-col gap-3">
        {populated.map(({ key, label, hint, classes }) => (
          <div key={key}>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              {label} <span className="font-normal normal-case text-slate-400">— {hint}</span>
            </h3>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {route[key].map((nodeId) => (
                <Link
                  key={nodeId}
                  to={`/node/${encodeURIComponent(nodeId)}`}
                  className={`rounded border px-1.5 py-0.5 font-mono text-xs hover:opacity-80 ${classes}`}
                >
                  {nodeId}
                </Link>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
