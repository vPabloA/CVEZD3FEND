import { RISK_LEVEL_LABELS, riskLevelClass, riskLevelFromScore } from "@/lib/colors";
import KeyFacts from "./KeyFacts";
import type { RiskSummary } from "@/lib/reasoningTypes";

function num(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function baseScore(cvss: Record<string, unknown> | null): number | undefined {
  if (!cvss) return undefined;
  return num(cvss.base_score) ?? num(cvss.baseScore) ?? num(cvss.score);
}

function kevListed(kev: Record<string, unknown> | null): boolean {
  if (!kev) return false;
  if (typeof kev.listed === "boolean") return kev.listed;
  if (typeof kev.in_kev === "boolean") return kev.in_kev;
  return Object.keys(kev).length > 0;
}

/** RiskSummary — CVSS/EPSS/KEV/exploitability evidence with a derived overall risk level. */
export default function RiskSummaryPanel({ risk }: { risk: RiskSummary }) {
  const level = riskLevelFromScore(baseScore(risk.cvss), kevListed(risk.kev));
  const hasAny = risk.cvss || risk.epss || risk.kev || risk.exploitability;

  return (
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-700">Risk summary</h2>
        <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${riskLevelClass(level)}`} aria-label={`Overall risk level: ${RISK_LEVEL_LABELS[level]}`}>
          {RISK_LEVEL_LABELS[level]}
        </span>
      </div>
      {!hasAny ? (
        <p className="mt-2 text-sm italic text-slate-400">No CVSS/EPSS/KEV/exploitability evidence available for this CVE.</p>
      ) : (
        <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {risk.cvss && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">CVSS</h3>
              <KeyFacts data={risk.cvss} />
            </div>
          )}
          {risk.epss && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">EPSS</h3>
              <KeyFacts data={risk.epss} />
            </div>
          )}
          {risk.kev && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Known Exploited Vulnerabilities</h3>
              <KeyFacts data={risk.kev} />
            </div>
          )}
          {risk.exploitability && (
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Exploitability</h3>
              <KeyFacts data={risk.exploitability} />
            </div>
          )}
        </div>
      )}
    </section>
  );
}
