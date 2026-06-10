import { useCallback, useEffect, useState } from "react";
import { loadBundle, loadPromotedEdges } from "@/lib/bundle";
import type { BundleEdge, KnowledgeBundle } from "@/lib/types";

export interface BundleState {
  bundle: KnowledgeBundle | null;
  promotedEdges: BundleEdge[];
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/** Loads the static knowledge bundle + AI-promoted edge overlay once, with retry. */
export function useBundle(): BundleState {
  const [bundle, setBundle] = useState<KnowledgeBundle | null>(null);
  const [promotedEdges, setPromotedEdges] = useState<BundleEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([loadBundle(attempt > 0), loadPromotedEdges(attempt > 0)])
      .then(([b, edges]) => {
        if (cancelled) return;
        setBundle(b);
        setPromotedEdges(edges);
      })
      .catch((err: Error) => {
        if (cancelled) return;
        setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { bundle, promotedEdges, loading, error, reload };
}
