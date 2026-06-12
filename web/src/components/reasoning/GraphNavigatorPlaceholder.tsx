import { downloadText } from "@/lib/export";

/**
 * Reserved position for the Threat-Defense Knowledge Graph Navigator (next
 * iteration). This pass intentionally does not build the graph view — it
 * documents what will live here and, when the reasoning engine already emits
 * a `navigator_layer` export, exposes that data so the next iteration has a
 * concrete artifact to build against.
 */
export default function GraphNavigatorPlaceholder({ navigatorLayer, cveId }: { navigatorLayer: string | null; cveId: string }) {
  return (
    <section className="flex flex-col gap-2 rounded-md border border-dashed border-link bg-blue-50/40 p-4">
      <div className="flex items-center gap-2">
        <span className="inline-block h-2.5 w-2.5 rounded-sm border border-link bg-blue-100" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-link">Architectural graph navigator</h2>
        <span className="rounded border border-link bg-white px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-link">Next iteration</span>
      </div>
      <p className="text-xs text-slate-600">
        This panel is reserved for the semantic graph navigator: an interactive view of the CVE → CWE → CAPEC → ATT&CK → D3FEND → ATLAS →
        Controls → Detections → Evidence route, with provenance and classification overlaid directly on the graph. The reasoning data on
        this page (route contract, edges, provenance) is the data source that view will render — this iteration prepares it.
      </p>
      {navigatorLayer ? (
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-xs text-slate-500">A navigator-layer export is already available for this CVE.</p>
          <button
            type="button"
            onClick={() => downloadText(`${cveId}-navigator-layer.json`, navigatorLayer, "application/json")}
            className="rounded border border-link bg-white px-2 py-1 text-xs font-medium text-link hover:bg-blue-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Download navigator layer
          </button>
        </div>
      ) : (
        <p className="text-xs italic text-slate-400">No navigator-layer export yet for this CVE.</p>
      )}
    </section>
  );
}
