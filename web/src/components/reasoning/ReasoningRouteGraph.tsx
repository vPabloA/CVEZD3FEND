import { useEffect, useState } from "react";
import ThreatDefenseGraphNavigator from "./graph/ThreatDefenseGraphNavigator";
import type { ReasoningResult } from "@/lib/reasoningTypes";

/**
 * Compatibility wrapper for the legacy `ReasoningRouteGraph` import path.
 * The actual product surface is now the Threat-Defense Knowledge Graph
 * Navigator. This adapter preserves the older prop shape while delegating the
 * graph rendering to the new component.
 */
export default function ReasoningRouteGraph({
  result,
  selectedNode,
  onSelectNode,
}: {
  result: ReasoningResult;
  selectedNode: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);

  useEffect(() => {
    setSelectedEdge(null);
  }, [result]);

  return (
    <ThreatDefenseGraphNavigator
      result={result}
      selection={selectedEdge ? { kind: "edge", id: selectedEdge } : selectedNode ? { kind: "node", id: selectedNode } : null}
      onSelectNode={(nodeId) => {
        onSelectNode(nodeId);
        setSelectedEdge(null);
      }}
      onSelectEdge={(edgeId) => setSelectedEdge(edgeId || null)}
      onClearSelection={() => {
        onSelectNode(result.route.canonical_chain[0] ?? result.normalized_input ?? result.input);
        setSelectedEdge(null);
      }}
    />
  );
}
