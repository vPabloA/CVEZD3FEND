from pathlib import Path


def replace_once(old: str, new: str) -> None:
    path = Path("web/src/pages/AnalyzePage.tsx")
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Unexpected AnalyzePage source shape ({count}): {old[:80]}")
    path.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    'import type { BatchAnalysisRequest, RankedRoute } from "@/lib/reasoningTypes";',
    'import type { BatchAnalysisRequest, GraphSlice, RankedRoute } from "@/lib/reasoningTypes";',
)
replace_once(
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
    "  const graphBuilder = useCallback(",
    "  const focusedRouteReviewRequired = useMemo(() => routeRequiresHumanReview(focusedRoute, activeSlice), [activeSlice, focusedRoute]);\n\n  const graphBuilder = useCallback(",
)
replace_once(
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
    "  }), [activeResult, focusedRoute?.node_ids, workbench.activeView]);",
    "  }), [activeResult, focusedRoute?.node_ids, focusedRouteReviewRequired, workbench.activeView]);",
)
