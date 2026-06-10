import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import RouteGraph from "@/components/RouteGraph";
import RouteSteps from "@/components/RouteSteps";
import { useBundle } from "@/hooks/useBundle";
import { explainRoute, type AiContextResult, ApiError } from "@/lib/api";
import { getNode, resolveRoute, routesForCve } from "@/lib/bundle";
import { downloadJson, downloadText, routeToMarkdown } from "@/lib/export";
import { nodeColorClass } from "@/lib/colors";

export default function RoutePage() {
  const { routeId = "" } = useParams();
  const { bundle, promotedEdges, loading, error, reload } = useBundle();
  const [explanation, setExplanation] = useState<AiContextResult | null>(null);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);

  const route = bundle ? resolveRoute(bundle, routeId) : undefined;
  const startNode = bundle && route ? getNode(bundle, route.start_node) : undefined;
  const siblingRoutes =
    bundle && route && startNode?.type === "cve"
      ? routesForCve(bundle, startNode.id).filter((r) => r.route_id !== route.route_id)
      : [];

  useEffect(() => {
    setExplanation(null);
    setExplainError(null);
  }, [routeId]);

  if (loading) return <LoadingState label="Loading knowledge bundle…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reload} />;
  if (!route) {
    return (
      <EmptyState title={`No route found for "${routeId}"`} hint="Provide a route id (ROUTE-...) or a CVE id with at least one route.">
        <Link to="/" className="mt-2 text-sm text-link hover:underline">
          ← Back to search
        </Link>
      </EmptyState>
    );
  }

  const handleExplain = () => {
    setExplainLoading(true);
    setExplainError(null);
    explainRoute(route.route_id)
      .then(setExplanation)
      .catch((err: ApiError) => setExplainError(err.message))
      .finally(() => setExplainLoading(false));
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-slate-800">
            Route {route.route_id}
            <span className="ml-2 text-sm font-normal text-slate-400">{route.path.join(" → ")}</span>
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            <Link to={`/node/${encodeURIComponent(route.start_node)}`} className={`font-mono hover:underline ${nodeColorClass(getNode(bundle, route.start_node)!)}`}>
              {route.start_node}
            </Link>{" "}
            →{" "}
            <Link to={`/node/${encodeURIComponent(route.end_node)}`} className={`font-mono hover:underline ${nodeColorClass(getNode(bundle, route.end_node)!)}`}>
              {route.end_node}
            </Link>
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => downloadText(`${route.route_id}.md`, routeToMarkdown(bundle, route), "text/markdown")}
            className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Download Markdown
          </button>
          <button
            type="button"
            onClick={() => downloadJson(`${route.route_id}.json`, route)}
            className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Download JSON
          </button>
        </div>
      </div>

      {siblingRoutes.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-400">Other routes for {startNode?.id}:</span>
          {routesForCve(bundle, startNode!.id).map((r) => (
            <Link
              key={r.route_id}
              to={`/route/${encodeURIComponent(r.route_id)}`}
              className={`rounded border px-1.5 py-0.5 font-mono ${
                r.route_id === route.route_id ? "border-link bg-blue-50 text-link" : "border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
              }`}
            >
              → {r.end_node}
            </Link>
          ))}
        </div>
      )}

      <section>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Graph</h2>
        <RouteGraph bundle={bundle} promotedEdges={promotedEdges} route={route} siblingRoutes={siblingRoutes} />
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Steps</h2>
        <RouteSteps bundle={bundle} route={route} />
      </section>

      <section className="rounded-md border border-slate-200 bg-white p-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">AI explanation</h2>
          <button
            type="button"
            onClick={handleExplain}
            disabled={explainLoading}
            className="rounded border border-slate-300 px-2 py-1 text-xs font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:opacity-50"
          >
            {explainLoading ? "Explaining…" : explanation ? "Re-explain" : "Explain this route"}
          </button>
        </div>
        {explainError && <p className="mt-2 text-sm text-gap">{explainError} (template-based explanations require `CVEzD3FEND api` running)</p>}
        {explanation && (
          <div className="mt-2 text-sm text-slate-600">
            <p className="whitespace-pre-line">{explanation.text}</p>
            {explanation.citations.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {explanation.citations.map((c) => (
                  <span key={c.ref} className="rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 font-mono text-xs text-slate-500">
                    {c.ref} (conf {c.confidence.toFixed(2)})
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
        {!explanation && !explainError && <p className="mt-2 text-xs text-slate-400">Always-available, citation-backed context (AI_ASSISTANCE_CONTRACT). Falls back to a deterministic template if AI is disabled.</p>}
      </section>
    </div>
  );
}
