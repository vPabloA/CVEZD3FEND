from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"Unexpected source shape: {path}")
    p.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "web/src/components/reasoning/graph/graphAdapter.ts",
    '''  const orderedIds = prioritizeBatchIds(nodes, links, selection);
  const cap = visibleCap(mode);
  const visibleNodeIds = new Set(orderedIds.slice(0, cap));
  if (selection?.kind === "node") visibleNodeIds.add(selection.id);
  if (selection?.kind === "edge") {
    const selectedEdge = links.find((link) => link.id === selection.id);
    if (selectedEdge) {
      visibleNodeIds.add(graphLinkSourceId(selectedEdge));
      visibleNodeIds.add(graphLinkTargetId(selectedEdge));
    }
  }
  const visibleLinks = links.filter((link) => visibleNodeIds.has(graphLinkSourceId(link)) && visibleNodeIds.has(graphLinkTargetId(link)));
  const visibleNodes = nodes.filter((node) => visibleNodeIds.has(node.id));
''',
    '''  const orderedIds = prioritizeBatchIds(nodes, links, selection);
  const cap = visibleCap(mode);
  const sourceNodeIds = new Set(nodes.map((node) => node.id));
  const visibleNodeIds = new Set((focusedRoute?.node_ids ?? []).filter((id) => sourceNodeIds.has(id)));

  // Preserve every backend-delivered focused-route edge and endpoint. Missing
  // source edges remain explicit gaps and are never synthesized in React.
  const focusedEdgeIds = new Set(focusedRoute?.edge_ids ?? []);
  links.filter((link) => focusedEdgeIds.has(link.id)).forEach((link) => {
    visibleNodeIds.add(graphLinkSourceId(link));
    visibleNodeIds.add(graphLinkTargetId(link));
  });
  if (selection?.kind === "node" && sourceNodeIds.has(selection.id)) visibleNodeIds.add(selection.id);
  if (selection?.kind === "edge") {
    const selectedEdge = links.find((link) => link.id === selection.id);
    if (selectedEdge) {
      visibleNodeIds.add(graphLinkSourceId(selectedEdge));
      visibleNodeIds.add(graphLinkTargetId(selectedEdge));
    }
  }

  orderedIds.filter((id) => !visibleNodeIds.has(id)).slice(0, Math.max(0, cap - visibleNodeIds.size)).forEach((id) => visibleNodeIds.add(id));

  const visibleLinks = links.filter((link) => visibleNodeIds.has(graphLinkSourceId(link)) && visibleNodeIds.has(graphLinkTargetId(link)));
  const visibleNodes = nodes.filter((node) => visibleNodeIds.has(node.id));
  const integrity = batchRouteIntegrity(focusedRoute, nodes, links);
''',
)
replace_once(
    "web/src/components/reasoning/graph/graphAdapter.ts",
    "    routeChain,\n    routeConfidence: focusedRoute?.confidence ?? 0,\n  };\n}",
    "    routeChain,\n    routeConfidence: focusedRoute?.confidence ?? 0,\n    focusedRouteComplete: integrity.complete,\n    focusedRouteGaps: integrity.gaps,\n  };\n}",
)

replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    '''function hasFullRoute(chain: string[], nodes: GraphNodeData[]): boolean {
  if (chain.length < 5) return false;
  const routeKinds = new Set(nodes.filter((node) => chain.includes(node.id)).map((node) => node.kind));
  return ["cve", "cwe", "capec", "attack", "defend"].every((kind) => routeKinds.has(kind as GraphNodeData["kind"]));
}

''',
    "",
)
replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    "  reviewRequired?: boolean;\n  errors?: string[];",
    "  reviewRequired?: boolean;\n  fallbackUsed?: boolean;\n  selectionMode?: string;\n  errors?: string[];",
)
replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    "      routeChain: [],\n      routeConfidence: 0,\n    };",
    "      routeChain: [],\n      routeConfidence: 0,\n      focusedRouteComplete: false,\n      focusedRouteGaps: [\"No focused route\"],\n    };",
)
replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    '''    if (graph.nodes.length > 0 && !hasFullRoute(graph.routeChain, graph.nodes)) {
      notices.push({ tone: "info", text: "This route is partial. Defensive intent is available, but no canonical CWE/CAPEC chain was found." });
    }''',
    '''    if (graph.nodes.length > 0 && !graph.focusedRouteComplete) {
      const gapSummary = graph.focusedRouteGaps.slice(0, 2).join("; ");
      notices.push({ tone: "info", text: `This route is partial${gapSummary ? `: ${gapSummary}` : ""}.` });
    }''',
)
replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    "  }, [context, displayErrors.length, graph.links.length, graph.nodes, graph.routeChain, selectedHidden, selection?.kind]);",
    "  }, [context, displayErrors.length, graph.focusedRouteComplete, graph.focusedRouteGaps, graph.links.length, graph.nodes.length, selectedHidden, selection?.kind]);",
)
replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    '''            <span className={`rounded-full border px-2 py-1 ${reviewRequired ? "border-amber-400 bg-amber-50 text-amber-800" : "border-ok bg-green-50 text-ok"}`}>
              {reviewRequired ? "Human review required" : context?.status ?? "Route validated"}
            </span>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{sourceMode}</span>''',
    '''            <span className={`rounded-full border px-2 py-1 ${reviewRequired ? "border-amber-400 bg-amber-950 text-amber-50" : "border-emerald-500/50 bg-emerald-950 text-emerald-100"}`}>
              {reviewRequired ? "Human review required" : context?.status ?? "Route validated"}
            </span>
            {context?.fallbackUsed && (
              <span title="AI unavailable or rejected; deterministic ranking remains authoritative." className="rounded-full border border-amber-500/60 bg-amber-950 px-2 py-1 text-amber-50">Deterministic fallback</span>
            )}
            {!context?.fallbackUsed && context?.selectionMode === "ai_reranked" && (
              <span className="rounded-full border border-violet-500/60 bg-violet-950 px-2 py-1 text-violet-50">AI reranked</span>
            )}
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-300">{sourceMode}</span>''',
)
replace_once(
    "web/src/components/reasoning/graph/ThreatDefenseGraphNavigator.tsx",
    '? "border-amber-400/50 bg-amber-950/30 text-amber-100"\n                    : "border-sky-500/30 bg-sky-950/30 text-sky-100"',
    '? "border-amber-400/70 bg-amber-950 text-amber-50"\n                    : "border-sky-500/50 bg-sky-950 text-sky-50"',
)
