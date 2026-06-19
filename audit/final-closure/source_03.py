from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"Unexpected source shape: {path} :: {old[:50]}")
    p.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "web/src/pages/AnalyzePage.tsx",
    'import type { BatchAnalysisRequest, RankedRoute } from "@/lib/reasoningTypes";',
    'import type { BatchAnalysisRequest, GraphSlice, RankedRoute } from "@/lib/reasoningTypes";',
)
replace_once(
    "web/src/pages/AnalyzePage.tsx",
    "function WorkbenchIdle() {",
    '''function routeRequiresHumanReview(route: RankedRoute | null, slice: GraphSlice | null): boolean {
  if (!route || !slice) return false;
  if (route.completeness < 1 || route.gaps.length > 0) return true;
  const routeNodeIds = new Set(route.node_ids);
  const routeEdgeIds = new Set(route.edge_ids);
  const nodeReview = slice.nodes.some((node) => routeNodeIds.has(node.id) && (node.inferred || node.type === "gap"));
  const edgeReview = slice.edges.some((edge) => {
    if (!routeEdgeIds.has(edge.id)) return false;
    const resolution = typeof edge.resolution_state === "string"
      ? edge.resolution_state
      : typeof edge.metadata?.resolution_state === "string"
        ? edge.metadata.resolution_state
        : undefined;
    return edge.inferred || resolution === "unresolved" || resolution === "invalid";
  });
  return nodeReview || edgeReview;
}

function WorkbenchIdle() {''',
)
replace_once(
    "web/src/pages/AnalyzePage.tsx",
    "  const graphBuilder = useCallback(",
    "  const focusedRouteReviewRequired = useMemo(() => routeRequiresHumanReview(focusedRoute, activeSlice), [activeSlice, focusedRoute]);\n\n  const graphBuilder = useCallback(",
)
replace_once(
    "web/src/pages/AnalyzePage.tsx",
    '''    status: activeResult?.status === "partial" ? "Partial result" : "Catalog-backed",
    sourceMode: "Galeax + catalogs",
    reviewRequired: activeResult?.selection_summary.fallback_used ?? false,''',
    '''    status: "Catalog-backed",
    sourceMode: "Galeax + catalogs",
    reviewRequired: focusedRouteReviewRequired,
    fallbackUsed: activeResult?.selection_summary.fallback_used ?? false,
    selectionMode: activeResult?.selection_summary.selection_mode,''',
)
replace_once(
    "web/src/pages/AnalyzePage.tsx",
    "  }), [activeResult, focusedRoute?.node_ids, workbench.activeView]);",
    "  }), [activeResult, focusedRoute?.node_ids, focusedRouteReviewRequired, workbench.activeView]);",
)

for old, new in [
    ("border border-amber-500/40 bg-amber-950/20 p-4 text-sm text-amber-100", "border border-amber-500/70 bg-amber-950 p-4 text-sm text-amber-50"),
    ("mt-1 text-amber-200", "mt-1 text-amber-100"),
    ("border border-rose-500/40 bg-rose-950/30 p-3 text-sm text-rose-100", "border border-rose-500/70 bg-rose-950 p-3 text-sm text-rose-50"),
    ("border border-amber-500/40 bg-amber-950/20 p-8 text-center text-amber-100", "border border-amber-500/70 bg-amber-950 p-8 text-center text-amber-50"),
    ("mt-2 text-sm text-amber-200", "mt-2 text-sm text-amber-100"),
    ("border border-violet-500/40 bg-violet-950/30 p-3 text-sm text-violet-100", "border border-violet-500/70 bg-violet-950 p-3 text-sm text-violet-50"),
]:
    replace_once("web/src/pages/AnalyzePage.tsx", old, new)

for old, new in [
    ("rounded-xl border border-slate-800 bg-slate-950/70 p-3", "rounded-xl border border-slate-700 bg-slate-900 p-3"),
    ('text-slate-500">{label}', 'text-slate-300">{label}'),
    ('text-xs text-slate-500">{detail}', 'text-xs text-slate-300">{detail}'),
    ("border-amber-500/40 bg-amber-950/20", "border-amber-500/70 bg-amber-950"),
    ("border-rose-500/40 bg-rose-950/20", "border-rose-500/70 bg-rose-950"),
    ("mt-1 text-sm text-slate-400", "mt-1 text-sm text-slate-300"),
    ("border border-amber-500/40 bg-amber-950/30 p-3 text-amber-100", "border border-amber-500/70 bg-amber-950 p-3 text-amber-50"),
    ("border border-rose-500/40 bg-rose-950/30 p-3 text-rose-100", "border border-rose-500/70 bg-rose-950 p-3 text-rose-50"),
    ("border border-violet-500/40 bg-violet-950/30 p-3 text-violet-100", "border border-violet-500/70 bg-violet-950 p-3 text-violet-50"),
]:
    replace_once("web/src/components/reasoning/batch/BatchDecisionSummary.tsx", old, new)
