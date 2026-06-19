import type { BatchReasoningResult, GraphSlice, RankedRoute } from "@/lib/reasoningTypes";

function safeUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

export default function BatchEvidencePanel({
  result,
  route,
  graph,
}: {
  result: BatchReasoningResult;
  route: RankedRoute | null;
  graph: GraphSlice | null;
}) {
  const routeSources = route?.provenance ?? [];
  const sourceRecords = Object.entries(result.provenance);
  const edgeById = new Map((graph?.edges ?? []).map((edge) => [edge.id, edge] as const));
  const routeEdges = route?.edge_ids.map((edgeId) => edgeById.get(edgeId)).filter((edge): edge is NonNullable<typeof edge> => Boolean(edge)) ?? [];

  return (
    <section id="batch-evidence" aria-labelledby="evidence-title" className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-sky-400">Evidence, provenance, warnings and gaps</p>
      <h2 id="evidence-title" className="mt-1 text-lg font-semibold text-slate-100">Catalog proof behind the focused route</h2>
      <div className="mt-4 grid gap-3 xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.8fr)]">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h3 className="text-sm font-semibold text-slate-200">Edge-by-edge proof</h3>
          {route ? (
            <>
              <p className="mt-2 font-mono text-xs text-slate-400">{route.route_id}</p>
              <ol className="mt-3 space-y-2">
                {routeEdges.map((edge, index) => {
                  const url = safeUrl(edge.source_url);
                  return (
                    <li key={edge.id} className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-xs text-slate-200">{index + 1}. {edge.source} → {edge.target}</span>
                        <span className="text-[10px] uppercase tracking-wide text-slate-500">{edge.type.replace(/_/g, " ")}</span>
                      </div>
                      <p className="mt-2 text-xs text-slate-400">{edge.evidence.length ? edge.evidence.join(" · ") : "No evidence note returned for this edge."}</p>
                      <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-slate-500">
                        {edge.source_ref && <span>Source: {edge.source_ref}</span>}
                        <span>Confidence {edge.confidence.toFixed(2)}</span>
                        {url && <a href={url} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">Open evidence source</a>}
                      </div>
                    </li>
                  );
                })}
              </ol>
              {routeEdges.length !== route.edge_ids.length && (
                <div role="alert" className="mt-3 rounded-lg border border-rose-500/40 bg-rose-950/30 p-3 text-sm text-rose-100">The active graph projection does not contain every edge referenced by this route.</div>
              )}
              <div className="mt-3 flex flex-wrap gap-2">{routeSources.length ? routeSources.map((source) => <span key={source} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300">{source}</span>) : <span className="text-sm text-slate-500">No route-level provenance labels returned.</span>}</div>
              {route.gaps.length > 0 && <div className="mt-3 rounded-lg border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-100">Gaps: {route.gaps.join(", ")}</div>}
            </>
          ) : <p className="mt-2 text-sm text-slate-500">Select a ranked route to inspect its evidence.</p>}
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h3 className="text-sm font-semibold text-slate-200">Source ledger</h3>
          <div className="mt-3 max-h-[30rem] space-y-2 overflow-auto">
            {sourceRecords.length ? sourceRecords.map(([sourceId, record]) => {
              const recordObject = typeof record === "object" && record !== null ? record as Record<string, unknown> : {};
              const url = safeUrl(recordObject.url ?? recordObject.source_url);
              return <div key={sourceId} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-xs text-slate-200">{sourceId}</span>{url && <a href={url} target="_blank" rel="noreferrer" className="text-xs text-sky-400 hover:underline">Open source</a>}</div><pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words text-[10px] leading-relaxed text-slate-500">{JSON.stringify(record, null, 2)}</pre></div>;
            }) : <p className="text-sm text-slate-500">No provenance records returned.</p>}
          </div>
        </div>
      </div>
      {(result.warnings.length > 0 || result.errors.length > 0) && (
        <div className="mt-3 grid gap-2 md:grid-cols-2" aria-live="polite">
          {result.warnings.length > 0 && <div className="rounded-xl border border-amber-500/40 bg-amber-950/30 p-3"><h3 className="text-sm font-semibold text-amber-100">Warnings</h3><ul className="mt-2 list-disc space-y-1 pl-4 text-sm text-amber-200">{result.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div>}
          {result.errors.length > 0 && <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3"><h3 className="text-sm font-semibold text-rose-100">Errors</h3><ul className="mt-2 list-disc space-y-1 pl-4 text-sm text-rose-200">{result.errors.map((error) => <li key={error}>{error}</li>)}</ul></div>}
        </div>
      )}
    </section>
  );
}
