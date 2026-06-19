import type { BatchReasoningResult } from "@/lib/reasoningTypes";
import type { BatchView } from "@/hooks/useReasoning";

function Metric({ label, value, detail }: { label: string; value: number | string; detail?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-1 text-xl font-semibold text-slate-100">{value}</p>
      {detail && <p className="mt-1 text-xs text-slate-500">{detail}</p>}
    </div>
  );
}

export default function BatchDecisionSummary({
  result,
  activeView,
  allAvailable,
  loadingAll,
  onViewChange,
}: {
  result: BatchReasoningResult;
  activeView: BatchView;
  allAvailable: boolean;
  loadingAll: boolean;
  onViewChange: (view: BatchView) => void;
}) {
  const selectedAttack = activeView === "all" ? result.shared_attack_techniques_all_candidates.length : result.shared_attack_techniques_selected.length;
  const selectedDefense = activeView === "all" ? result.shared_defenses_all_candidates.length : result.shared_defenses_selected.length;
  const statusPresentation = result.status === "ok"
    ? { title: "Contextual route selection ready", className: "border-slate-800 bg-slate-950" }
    : result.status === "partial"
      ? { title: "Partial analysis — usable results with declared gaps", className: "border-amber-500/40 bg-amber-950/20" }
      : result.status === "unavailable"
        ? { title: "Galeax data unavailable — no complete analysis was asserted", className: "border-rose-500/40 bg-rose-950/20" }
        : result.status === "not_found"
          ? { title: "No requested CVE was found", className: "border-amber-500/40 bg-amber-950/20" }
          : result.status === "invalid"
            ? { title: "No valid CVE identifier was supplied", className: "border-rose-500/40 bg-rose-950/20" }
            : { title: `Analysis status: ${result.status}`, className: "border-amber-500/40 bg-amber-950/20" };
  return (
    <section id="decision-summary" aria-labelledby="decision-summary-title" role="status" aria-live="polite" className={`rounded-2xl border p-4 shadow-lg ${statusPresentation.className}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-sky-400">Decision summary</p>
          <h2 id="decision-summary-title" className="mt-1 text-lg font-semibold text-slate-100">{statusPresentation.title}</h2>
          <p className="mt-1 text-sm text-slate-400">
            {activeView === "all"
              ? `Showing complete universe: ${result.available_route_count} routes.`
              : `Showing ${result.selected_route_count} selected route${result.selected_route_count === 1 ? "" : "s"} from ${result.available_route_count} available.`}
          </p>
        </div>
        <div role="tablist" aria-label="Graph universe" className="inline-flex rounded-xl border border-slate-700 bg-slate-900 p-1">
          <button type="button" role="tab" aria-selected={activeView === "selected"} onClick={() => onViewChange("selected")} className={`rounded-lg px-3 py-2 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${activeView === "selected" ? "bg-sky-500 text-white" : "text-slate-300 hover:text-white"}`}>Selected</button>
          <button type="button" role="tab" aria-selected={activeView === "all"} aria-busy={loadingAll} onClick={() => onViewChange("all")} className={`rounded-lg px-3 py-2 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${activeView === "all" ? "bg-violet-500 text-white" : "text-slate-300 hover:text-white"}`}>
            {loadingAll ? "Loading All…" : allAvailable ? "All candidates" : "Load all candidates"}
          </button>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-6">
        <Metric label="Requested CVEs" value={result.requested_cves.length} />
        <Metric label="Found" value={result.found_cves.length} />
        <Metric label="Missing" value={result.missing_cves.length} detail={result.missing_cves.slice(0, 2).join(", ") || "None"} />
        <Metric label="Invalid" value={result.invalid_inputs.length} detail={result.invalid_inputs.slice(0, 2).join(", ") || "None"} />
        <Metric label="Available routes" value={result.available_route_count} />
        <Metric label="Selected routes" value={result.selected_route_count} />
        <Metric label="Represented CVEs" value={result.selection_summary.represented_cves.length} />
        <Metric label="Outside Top-K" value={result.selection_summary.unrepresented_cves.length} />
        <Metric label="Shared ATT&CK" value={selectedAttack} />
        <Metric label="Reusable D3FEND" value={selectedDefense} />
        <Metric label="Selection mode" value={result.selection_summary.selection_mode === "ai_reranked" ? "AI reranked" : "Deterministic"} />
        <Metric label="AI fallback" value={result.selection_summary.fallback_used ? "Used" : "No"} />
      </div>

      {(result.missing_cves.length > 0 || result.invalid_inputs.length > 0 || result.selection_summary.unrepresented_cves.length > 0) && (
        <div className="mt-4 grid gap-2 text-sm md:grid-cols-3" aria-live="polite">
          {result.missing_cves.length > 0 && <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 p-3 text-amber-100"><strong>Not found:</strong> {result.missing_cves.join(", ")}</div>}
          {result.invalid_inputs.length > 0 && <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 p-3 text-rose-100"><strong>Invalid:</strong> {result.invalid_inputs.join(", ")}</div>}
          {result.selection_summary.unrepresented_cves.length > 0 && <div className="rounded-lg border border-violet-500/40 bg-violet-950/30 p-3 text-violet-100"><strong>Outside Top-K:</strong> {result.selection_summary.unrepresented_cves.join(", ")}</div>}
        </div>
      )}
    </section>
  );
}
