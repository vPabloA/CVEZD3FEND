import ClampedText from "./ClampedText";
import { RISK_LEVEL_LABELS, riskLevelClass, type RiskLevel } from "@/lib/colors";
import { nodeKindForId } from "@/components/reasoning/graph/graphAdapter";
import type { ReasoningResult } from "@/lib/reasoningTypes";

function meanConfidence(result: ReasoningResult): number | null {
  if (result.edges.length === 0) return null;
  return result.edges.reduce((sum, edge) => sum + edge.confidence, 0) / result.edges.length;
}

function officialShare(result: ReasoningResult): { official: number; total: number } {
  const official = result.edges.filter(
    (edge) => edge.classification === "official_explicit" || edge.classification === "official_incomplete"
  ).length;
  return { official, total: result.edges.length };
}

/**
 * Decision-first head of the briefing rail: executive conclusion, priority +
 * confidence/provenance signal, the immediate Tier 1 action and the defensive
 * direction — all sourced verbatim from the reasoning contract.
 */
export default function Tier1BriefingCard({
  result,
  riskLevel,
  onFocusNode,
}: {
  result: ReasoningResult;
  riskLevel: RiskLevel;
  onFocusNode: (nodeId: string) => void;
}) {
  const confidence = meanConfidence(result);
  const { official, total } = officialShare(result);
  const defensiveNodes = result.route.defensive_nodes;
  const mitigationEdges = result.edges.filter((edge) => {
    const targetKind = nodeKindForId(edge.target);
    return targetKind === "defend" || targetKind === "mitigation" || targetKind === "control";
  });

  return (
    // shrink-0: overflow-hidden would otherwise let this card collapse inside the max-height briefing rail
    <section className="shrink-0 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 bg-slate-50/80 px-4 py-3">
        <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-400">Intelligence briefing</p>
        <h2 className="mt-0.5 text-sm font-semibold text-slate-800">Tier 1 conclusion</h2>
      </div>

      <div className="flex flex-col gap-3 p-4">
        {result.narrative.executive_summary_es?.trim() ? (
          <ClampedText text={result.narrative.executive_summary_es} lang="es" className="text-sm font-medium leading-relaxed text-slate-800" />
        ) : (
          <p className="text-sm italic text-slate-400">No executive conclusion was produced for this CVE.</p>
        )}

        <div className="flex flex-wrap gap-1.5 text-[11px]">
          <span className={`rounded border px-2 py-0.5 font-semibold ${riskLevelClass(riskLevel)}`}>
            Priority: {RISK_LEVEL_LABELS[riskLevel]}
          </span>
          {confidence !== null && (
            <span className="rounded border border-slate-300 bg-slate-50 px-2 py-0.5 font-medium text-slate-600" title="Mean confidence across all reasoning edges">
              Confidence {confidence.toFixed(2)}
            </span>
          )}
          {total > 0 && (
            <span className="rounded border border-slate-300 bg-slate-50 px-2 py-0.5 font-medium text-slate-600" title="Edges backed by an official source mapping">
              {official}/{total} official edges
            </span>
          )}
          <span
            className={`rounded border px-2 py-0.5 font-semibold ${
              result.human_review.required ? "border-inferred bg-amber-50 text-inferred" : "border-ok bg-green-50 text-ok"
            }`}
          >
            {result.human_review.required ? "Human review required" : "No review gate"}
          </span>
        </div>

        {result.narrative.risk_rationale_es?.trim() && (
          <ClampedText text={result.narrative.risk_rationale_es} lang="es" className="text-xs leading-relaxed text-slate-500" lines={3} />
        )}

        <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
          <h3 className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">Acción recomendada</h3>
          <p className="mt-1.5 text-sm leading-relaxed text-slate-700" lang="es">
            {result.narrative.tier1_conclusion_es?.trim() || "No Tier 1 conclusion was produced for this CVE."}
          </p>
          {result.soc_action_pack.validations.length > 0 && (
            <ul className="mt-2 flex flex-col gap-1 text-sm text-slate-700">
              {result.soc_action_pack.validations.slice(0, 2).map((item) => (
                <li key={item} className="flex gap-2">
                  <span className="mt-0.5 select-none text-link" aria-hidden="true">
                    ▸
                  </span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-xl border border-defense/30 bg-green-50/50 p-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-[11px] font-semibold uppercase tracking-wide text-defense">Defensive direction</h3>
            {mitigationEdges.length > 0 && (
              <span className="rounded-full border border-defense/40 bg-white px-2 py-0.5 text-[11px] font-medium text-defense">
                {mitigationEdges.length} defensive edge{mitigationEdges.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
          {defensiveNodes.length === 0 ? (
            <p className="mt-1.5 text-sm italic text-slate-500">No D3FEND/defensive nodes were derived for this route.</p>
          ) : (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {defensiveNodes.map((id) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => onFocusNode(id)}
                  title={`Focus ${id} on the graph stage`}
                  className="rounded-full border border-defense/40 bg-white px-2 py-1 font-mono text-[11px] text-defense transition hover:border-defense hover:bg-green-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-defense"
                >
                  {id}
                </button>
              ))}
            </div>
          )}
          {result.narrative.decision_context_es?.trim() && (
            <div className="mt-2">
              <ClampedText text={result.narrative.decision_context_es} lang="es" className="text-xs leading-relaxed text-slate-600" lines={3} />
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
