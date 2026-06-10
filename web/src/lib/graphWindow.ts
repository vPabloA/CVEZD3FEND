// Enforces UIX_CONTRACT §1: never render more than 40 nodes on initial load,
// expand in bounded increments of 20 via an explicit user action.
export const INITIAL_NODE_CAP = 40;
export const EXPAND_INCREMENT = 20;

export interface WindowedNodes {
  /** Node ids to render this round (core + revealed siblings). */
  visible: string[];
  /** Sibling ids not yet shown. */
  remainingCount: number;
}

/**
 * `coreIds` (a route's own nodes/edges) are always shown in full. `siblingIds`
 * (e.g. alternative-route nodes for the same CVE) fill the remaining budget,
 * `expandSteps` more increments at a time after "Show more" clicks.
 */
export function windowNodes(coreIds: string[], siblingIds: string[], expandSteps: number): WindowedNodes {
  const seen = new Set(coreIds);
  const deduped = siblingIds.filter((id) => !seen.has(id));
  const capacity = Math.max(0, INITIAL_NODE_CAP - coreIds.length) + expandSteps * EXPAND_INCREMENT;
  const shown = deduped.slice(0, capacity);
  return { visible: [...coreIds, ...shown], remainingCount: deduped.length - shown.length };
}
