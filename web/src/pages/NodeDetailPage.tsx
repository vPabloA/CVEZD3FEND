import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import { ConfidenceBadge, ProvenanceBadge, TypeBadge } from "@/components/NodeBadge";
import RelationList from "@/components/RelationList";
import { useBundle } from "@/hooks/useBundle";
import { getEdgesFor, getNode, routesForCve } from "@/lib/bundle";
import { downloadJson } from "@/lib/export";
import { nodeColorClass } from "@/lib/colors";

export default function NodeDetailPage() {
  const { nodeId = "" } = useParams();
  const { bundle, promotedEdges, loading, error, reload } = useBundle();

  const node = bundle ? getNode(bundle, nodeId) : undefined;
  const relations = useMemo(() => (bundle && node ? getEdgesFor(bundle, node.id, promotedEdges) : { incoming: [], outgoing: [] }), [bundle, node, promotedEdges]);
  const cveRoutes = useMemo(() => (bundle && node?.type === "cve" ? routesForCve(bundle, node.id) : []), [bundle, node]);
  const sources = useMemo(() => {
    if (!bundle || !node) return [];
    return node.source_refs.map((ref) => bundle.provenance[ref]).filter(Boolean);
  }, [bundle, node]);

  if (loading) return <LoadingState label="Loading knowledge bundle…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reload} />;
  if (!node) {
    return (
      <EmptyState title={`No node found for "${nodeId}"`} hint="Check the id, or go back and search again.">
        <Link to="/" className="mt-2 text-sm text-link hover:underline">
          ← Back to search
        </Link>
      </EmptyState>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className={`font-mono text-xl font-bold ${nodeColorClass(node)}`}>{node.id}</h1>
            <TypeBadge type={node.type} />
            <ProvenanceBadge canonical={node.canonical} inferred={node.inferred} />
            <ConfidenceBadge confidence={node.confidence} />
          </div>
          <p className="mt-1 text-lg text-slate-700">{node.name}</p>
        </div>
        <button
          type="button"
          onClick={() => downloadJson(`${node.id}.json`, node)}
          className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          Download JSON
        </button>
      </div>

      {node.description && <p className="text-sm text-slate-600">{node.description}</p>}

      {(node.aliases.length > 0 || node.tags.length > 0) && (
        <div className="flex flex-wrap gap-4 text-sm">
          {node.aliases.length > 0 && (
            <div>
              <span className="mr-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Aliases:</span>
              {node.aliases.map((a) => (
                <span key={a} className="mr-1 rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 font-mono text-xs text-slate-600">
                  {a}
                </span>
              ))}
            </div>
          )}
          {node.tags.length > 0 && (
            <div>
              <span className="mr-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Tags:</span>
              {node.tags.map((t) => (
                <span key={t} className="mr-1 rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 text-xs text-slate-600">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {node.external_refs.length > 0 && (
        <div>
          <h2 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">External references</h2>
          <ul className="flex flex-col gap-0.5">
            {node.external_refs.map((ref) => (
              <li key={ref}>
                <a href={ref} target="_blank" rel="noreferrer" className="text-sm text-link hover:underline">
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Related actions */}
      {(cveRoutes.length > 0 || node.type === "attack" || node.type === "gap") && (
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">Related actions</h2>
          <div className="flex flex-wrap gap-2 text-sm">
            {cveRoutes.map((r) => (
              <Link key={r.route_id} to={`/route/${encodeURIComponent(r.route_id)}`} className="rounded border border-link bg-white px-2 py-1 text-link hover:bg-blue-50">
                Route → {r.end_node} (conf {r.confidence.toFixed(2)})
              </Link>
            ))}
            {node.type === "attack" && (
              <>
                <Link to={`/soc-action-pack/${encodeURIComponent(node.id)}`} className="rounded border border-link bg-white px-2 py-1 text-link hover:bg-blue-50">
                  SOC Action Pack
                </Link>
                <Link to={`/coverage?q=${encodeURIComponent(node.id)}`} className="rounded border border-link bg-white px-2 py-1 text-link hover:bg-blue-50">
                  Defensive coverage
                </Link>
              </>
            )}
            {node.type === "gap" && typeof node.metadata.target === "string" && (
              <Link to={`/node/${encodeURIComponent(node.metadata.target as string)}`} className="rounded border border-gap bg-white px-2 py-1 text-gap hover:bg-red-50">
                Gap target: {String(node.metadata.target)} ({String(node.metadata.reason ?? "")})
              </Link>
            )}
          </div>
        </div>
      )}

      {sources.length > 0 && (
        <div>
          <h2 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Sources</h2>
          <div className="flex flex-wrap gap-1.5">
            {sources.map((s) => (
              <span key={s.source_id} className="rounded border border-slate-300 bg-white px-1.5 py-0.5 text-xs text-slate-600" title={s.url}>
                <span className="font-mono">{s.source_id}</span> — {s.name}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div>
          <h2 className="mb-2 text-sm font-semibold text-slate-700">
            Incoming relations <span className="text-xs font-normal text-slate-400">({relations.incoming.length})</span>
          </h2>
          <RelationList bundle={bundle} edges={relations.incoming} direction="incoming" />
        </div>
        <div>
          <h2 className="mb-2 text-sm font-semibold text-slate-700">
            Outgoing relations <span className="text-xs font-normal text-slate-400">({relations.outgoing.length})</span>
          </h2>
          <RelationList bundle={bundle} edges={relations.outgoing} direction="outgoing" />
        </div>
      </div>
    </div>
  );
}
