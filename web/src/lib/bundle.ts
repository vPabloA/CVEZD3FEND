// Loads & caches data/knowledge-bundle.json (BUNDLE_CONTRACT), exposes typed
// accessors. Same-origin fetch only (UIX_CONTRACT §8) — never a third-party
// API origin.
import type { BundleEdge, BundleNode, KnowledgeBundle, Route } from "./types";

const BUNDLE_URL = "/data/knowledge-bundle.json";
const PROMOTED_EDGES_URL = "/data/promoted-edges.json";

let bundlePromise: Promise<KnowledgeBundle> | null = null;
let promotedEdgesPromise: Promise<BundleEdge[]> | null = null;

export function loadBundle(force = false): Promise<KnowledgeBundle> {
  if (force) bundlePromise = null;
  if (!bundlePromise) {
    bundlePromise = fetch(BUNDLE_URL).then((res) => {
      if (!res.ok) {
        throw new Error(
          `Failed to load knowledge bundle (${res.status} ${res.statusText}). ` +
            "Run `make build && make web-build` (or `CVEzD3FEND build`) first."
        );
      }
      return res.json() as Promise<KnowledgeBundle>;
    });
  }
  return bundlePromise;
}

/** AI-promoted overlay edges (data/dist/promoted-edges.json). Never merged into bundle.edges on disk. */
export function loadPromotedEdges(force = false): Promise<BundleEdge[]> {
  if (force) promotedEdgesPromise = null;
  if (!promotedEdgesPromise) {
    promotedEdgesPromise = fetch(PROMOTED_EDGES_URL)
      .then((res) => (res.ok ? (res.json() as Promise<BundleEdge[]>) : []))
      .catch(() => []);
  }
  return promotedEdgesPromise;
}

export function getNode(bundle: KnowledgeBundle, id: string): BundleNode | undefined {
  const idx = bundle.indexes.by_id[id];
  if (idx === undefined) return undefined;
  return bundle.nodes[idx];
}

export function getNodes(bundle: KnowledgeBundle, ids: string[]): BundleNode[] {
  return ids.map((id) => getNode(bundle, id)).filter((n): n is BundleNode => Boolean(n));
}

export interface NodeRelations {
  incoming: BundleEdge[];
  outgoing: BundleEdge[];
}

/**
 * Edges touching `nodeId`, including AI-promoted overlay edges (always
 * appended last so they read as additive, never replacing canonical edges).
 */
export function getEdgesFor(
  bundle: KnowledgeBundle,
  nodeId: string,
  promotedEdges: BundleEdge[] = []
): NodeRelations {
  const all = [...bundle.edges, ...promotedEdges];
  return {
    incoming: all.filter((e) => e.target === nodeId),
    outgoing: all.filter((e) => e.source === nodeId),
  };
}

export function getRoute(bundle: KnowledgeBundle, routeId: string): Route | undefined {
  return bundle.routes.find((r) => r.route_id === routeId);
}

/** Resolve a route id, or fall back to the top route for a CVE id. */
export function resolveRoute(bundle: KnowledgeBundle, ref: string): Route | undefined {
  const direct = getRoute(bundle, ref);
  if (direct) return direct;
  const routeIds = bundle.indexes.cve_routes[ref];
  if (routeIds && routeIds.length > 0) {
    return getRoute(bundle, routeIds[0]);
  }
  return undefined;
}

/** All routes anchored on a CVE id, in bundle order (first is the recommended/top route). */
export function routesForCve(bundle: KnowledgeBundle, cveId: string): Route[] {
  const routeIds = bundle.indexes.cve_routes[cveId] ?? [];
  return routeIds.map((id) => getRoute(bundle, id)).filter((r): r is Route => Boolean(r));
}

/** Resolve a CVE id or route id to the ATT&CK technique id it passes through, if any. */
export function resolveAttackId(bundle: KnowledgeBundle, ref: string): string | undefined {
  const direct = getNode(bundle, ref);
  if (direct?.type === "attack") return direct.id;
  const route = resolveRoute(bundle, ref);
  if (route) {
    for (const nodeId of route.nodes) {
      const n = getNode(bundle, nodeId);
      if (n?.type === "attack") return n.id;
    }
  }
  return undefined;
}

const TOKEN_RE = /[a-z0-9]+/g;

/** Token + alias scored search, mirroring CVEzD3FEND.lookup.search_nodes. */
export function search(bundle: KnowledgeBundle, query: string, limit = 20): BundleNode[] {
  const stripped = query.trim();
  if (!stripped) return [];

  const direct = getNode(bundle, stripped);
  if (direct) return [direct];

  const tokens = stripped.toLowerCase().match(TOKEN_RE)?.filter((t) => t.length >= 2) ?? [];
  const scores = new Map<string, number>();
  for (const token of tokens) {
    for (const id of bundle.indexes.by_text[token] ?? []) {
      scores.set(id, (scores.get(id) ?? 0) + 1);
    }
    for (const id of bundle.indexes.by_alias[token] ?? []) {
      scores.set(id, (scores.get(id) ?? 0) + 2);
    }
  }

  if (scores.size === 0) {
    const needle = stripped.toLowerCase();
    for (const node of bundle.nodes) {
      if (node.id.toLowerCase().includes(needle) || node.name.toLowerCase().includes(needle)) {
        scores.set(node.id, (scores.get(node.id) ?? 0) + 1);
      }
    }
  }

  return Array.from(scores.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([id]) => getNode(bundle, id))
    .filter((n): n is BundleNode => Boolean(n));
}

export const EXAMPLE_QUERIES = ["T1059", "CWE-79", "CAPEC-66", "D3-FA", "CVE-2025-0168", "AML.T0000"];
