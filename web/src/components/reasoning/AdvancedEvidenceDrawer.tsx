import { useState } from "react";
import ActionListPanel from "./ActionListPanel";
import CtemPanel from "./CtemPanel";
import ExportsPanel from "./ExportsPanel";
import ProvenancePanel from "./ProvenancePanel";
import ReasoningEdgesList from "./ReasoningEdgesList";
import RouteContractPanel from "./RouteContractPanel";
import type { ReasoningResult } from "@/lib/reasoningTypes";

function uniqueEvidence(result: ReasoningResult): string[] {
  const evidence = new Set<string>();
  result.edges.forEach((edge) => edge.evidence.forEach((item) => evidence.add(item)));
  return [...evidence];
}

function provenanceCount(result: ReasoningResult): number {
  return Object.values(result.provenance).reduce((total, edges) => total + edges.length, 0);
}

export default function AdvancedEvidenceDrawer({ result, cveId }: { result: ReasoningResult; cveId: string }) {
  const [rawOpen, setRawOpen] = useState(false);
  const evidence = uniqueEvidence(result);
  const warningsAndErrors = [...result.warnings.map((message) => ({ type: "Warning", message })), ...result.errors.map((message) => ({ type: "Error", message }))];

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-xl">
      <details className="group">
        <summary className="flex cursor-pointer select-none flex-wrap items-center justify-between gap-3 px-4 py-3 transition hover:bg-slate-900/60">
          <span className="flex items-center gap-3">
            <span
              className="text-slate-500 transition-transform duration-150 group-open:rotate-90 motion-reduce:transition-none"
              aria-hidden="true"
            >
              ▸
            </span>
            <span>
              <span className="block text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">Evidence dock</span>
              <span className="block text-sm font-semibold text-slate-100">Evidencia / Advanced details</span>
              <span className="text-xs text-slate-400">Provenance, reasoning trace, SOC/detection/hunting/CTEM, exports and raw details.</span>
            </span>
          </span>
          <span className="flex flex-wrap gap-1.5 text-[11px]">
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{result.edges.length} edges</span>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{provenanceCount(result)} provenance refs</span>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{evidence.length} evidence points</span>
            {warningsAndErrors.length > 0 && (
              <span className="rounded-full border border-amber-500/50 bg-amber-950/40 px-2 py-1 text-amber-200">{warningsAndErrors.length} data notice(s)</span>
            )}
          </span>
        </summary>

        <div className="border-t border-slate-800 bg-slate-100 p-4">
          <div className="grid gap-4 xl:grid-cols-2">
            <section className="rounded-md border border-slate-200 bg-white p-4 xl:col-span-2">
              <h2 className="text-sm font-semibold text-slate-700">Evidence reasoning</h2>
              {evidence.length === 0 ? (
                <p className="mt-2 text-sm italic text-slate-400">No edge-level evidence was produced for this CVE.</p>
              ) : (
                <ul className="mt-2 grid gap-2 text-sm text-slate-700 md:grid-cols-2">
                  {evidence.map((item) => (
                    <li key={item} className="rounded border border-slate-100 bg-slate-50 px-2 py-1.5">
                      {item}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {warningsAndErrors.length > 0 && (
              <section className="rounded-md border border-amber-200 bg-amber-50 p-4 xl:col-span-2">
                <h2 className="text-sm font-semibold text-amber-900">Data quality notices</h2>
                <ul className="mt-2 grid gap-2 text-sm text-amber-900 md:grid-cols-2">
                  {warningsAndErrors.map((item, index) => (
                    <li key={`${item.type}-${index}`} className="rounded border border-amber-200 bg-white/60 px-2 py-1.5">
                      <span className="font-semibold">{item.type}:</span> {item.message}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            <RouteContractPanel route={result.route} />

            <section className="rounded-md border border-slate-200 bg-white p-4">
              <h2 className="text-sm font-semibold text-slate-700">
                Reasoning trace <span className="font-normal text-slate-400">({result.edges.length} edges)</span>
              </h2>
              <p className="mt-1 text-xs text-slate-500">Reviewer-readable edge ledger. Promotion is governed from the AI Review panel, not repeated here.</p>
              <div className="mt-3">
                <ReasoningEdgesList edges={result.edges} emptyMessage="No edges were produced for this CVE." />
              </div>
            </section>

            <ProvenancePanel provenance={result.provenance} />

            <ActionListPanel
              title="SOC Action Pack"
              sections={[
                { label: "Validations", items: result.soc_action_pack.validations },
                { label: "Detections", items: result.soc_action_pack.detections },
                { label: "Containment", items: result.soc_action_pack.containment },
                { label: "Owners", items: result.soc_action_pack.owners },
                { label: "Evidence expected", items: result.soc_action_pack.evidence_expected },
              ]}
            />

            <ActionListPanel
              title="Detection engineering"
              sections={[
                { label: "Hypotheses", items: result.detection_engineering.hypotheses },
                { label: "Log sources", items: result.detection_engineering.log_sources },
                { label: "Rule ideas", items: result.detection_engineering.rule_ideas },
                { label: "Gaps", items: result.detection_engineering.gaps },
              ]}
            />

            <ActionListPanel
              title="Threat hunting"
              sections={[
                { label: "Hypotheses", items: result.threat_hunting.hypotheses },
                { label: "Queries", items: result.threat_hunting.queries },
                { label: "Pivot points", items: result.threat_hunting.pivot_points },
              ]}
            />

            <CtemPanel ctem={result.ctem} />

            <div className="xl:col-span-2">
              <ExportsPanel exports={result.exports} cveId={cveId} />
            </div>

            <details className="rounded-md border border-slate-200 bg-white xl:col-span-2" onToggle={(event) => setRawOpen(event.currentTarget.open)}>
              <summary className="cursor-pointer select-none px-4 py-3 text-sm font-semibold text-slate-700">Raw details</summary>
              {rawOpen && (
                <pre className="max-h-96 overflow-auto border-t border-slate-100 bg-slate-950 p-4 text-xs text-slate-100">
                  {JSON.stringify(result, null, 2)}
                </pre>
              )}
            </details>
          </div>
        </div>
      </details>
    </section>
  );
}
