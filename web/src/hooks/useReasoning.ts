import { useEffect, useState } from "react";
import { ApiError, apiHealth, getMeta, reasonCve, type ApiMeta } from "@/lib/api";
import type { ReasoningResult } from "@/lib/reasoningTypes";

export interface ApiAvailability {
  /** null while the initial health check is in flight. */
  available: boolean | null;
  error: string | null;
  meta: ApiMeta | null;
  recheck: () => void;
}

/**
 * Checks the CVEzD3FEND API sidecar (`CVEzD3FEND api`) once on mount, and
 * fetches `/api/meta` (enrichment source list, reasoning availability) when
 * it's reachable. Every reasoning-plane view gates on `available` before
 * issuing live requests (UIX_CONTRACT §3 — degraded states must be honest).
 */
export function useApiAvailability(): ApiAvailability {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<ApiMeta | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setAvailable(null);
    setError(null);
    apiHealth()
      .then(() => {
        if (cancelled) return;
        setAvailable(true);
        getMeta()
          .then((m) => !cancelled && setMeta(m))
          .catch(() => undefined);
      })
      .catch((err: ApiError) => {
        if (cancelled) return;
        setAvailable(false);
        setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  return { available, error, meta, recheck: () => setAttempt((n) => n + 1) };
}

export interface ReasoningState {
  result: ReasoningResult | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Fetches `/api/reason/{cveId}` — the full classified route contract, risk
 * summary, narrative and SOC/detection/hunting/CTEM outputs for one CVE.
 * Pass an empty `cveId` (or `enabled=false`) to skip the request, e.g. while
 * the API sidecar hasn't been confirmed reachable yet.
 */
export function useReasoning(cveId: string, enabled: boolean): ReasoningState {
  const [result, setResult] = useState<ReasoningResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!enabled || !cveId.trim()) {
      setResult(null);
      setError(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    reasonCve(cveId.trim())
      .then((r) => {
        if (!cancelled) setResult(r);
      })
      .catch((err: ApiError) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [cveId, enabled, attempt]);

  return { result, loading, error, reload: () => setAttempt((n) => n + 1) };
}
