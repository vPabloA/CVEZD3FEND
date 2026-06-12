import { riskLevelClass } from "@/lib/colors";
import type { Ctem } from "@/lib/reasoningTypes";

const PRIORITY_LEVEL: Record<string, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

/** CTEM (Continuous Threat Exposure Management) plan: priority, remediation, validation, residual risk. */
export default function CtemPanel({ ctem }: { ctem: Ctem }) {
  const hasContent = ctem.priority || ctem.remediation_actions.length > 0 || ctem.validation_steps.length > 0 || ctem.residual_risk;
  const level = PRIORITY_LEVEL[ctem.priority?.toLowerCase()] ?? "unknown";

  return (
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-700">CTEM plan</h2>
        {ctem.priority && (
          <span className={`rounded border px-2 py-0.5 text-xs font-semibold capitalize ${riskLevelClass(level)}`}>
            Priority: {ctem.priority}
          </span>
        )}
      </div>
      {!hasContent ? (
        <p className="mt-2 text-sm italic text-slate-400">No CTEM plan was produced for this CVE.</p>
      ) : (
        <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {ctem.remediation_actions.length > 0 && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Remediation actions</h3>
              <ul className="list-inside list-disc text-sm text-slate-700">
                {ctem.remediation_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}
          {ctem.validation_steps.length > 0 && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Validation steps</h3>
              <ul className="list-inside list-disc text-sm text-slate-700">
                {ctem.validation_steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          )}
          {ctem.residual_risk && (
            <div className="sm:col-span-2">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Residual risk</h3>
              <p className="text-sm text-slate-700">{ctem.residual_risk}</p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
