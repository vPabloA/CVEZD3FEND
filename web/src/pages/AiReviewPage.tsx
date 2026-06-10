import { useCallback, useEffect, useState } from "react";
import AiCandidateCard from "@/components/AiCandidateCard";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import { useBundle } from "@/hooks/useBundle";
import {
  apiHealth,
  generateCandidates,
  listCandidates,
  promoteCandidate,
  rejectCandidate,
  validateCandidates,
  ApiError,
} from "@/lib/api";
import type { AICandidate, FinalStatus } from "@/lib/types";

const REVIEWER_KEY = "cvezd3fend:reviewer";
const TABS: { value: FinalStatus | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "candidate", label: "Pending" },
  { value: "validated_candidate", label: "Validated" },
  { value: "rejected", label: "Rejected" },
  { value: "canonical", label: "Promoted" },
];

export default function AiReviewPage() {
  const { bundle, loading: bundleLoading, error: bundleError, reload: reloadBundle } = useBundle();
  const [apiAvailable, setApiAvailable] = useState<boolean | null>(null);
  const [candidates, setCandidates] = useState<AICandidate[]>([]);
  const [queueLoading, setQueueLoading] = useState(false);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [tab, setTab] = useState<FinalStatus | "all">("all");
  const [reviewer, setReviewer] = useState(() => localStorage.getItem(REVIEWER_KEY) ?? "");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [genLimit, setGenLimit] = useState(10);
  const [genBusy, setGenBusy] = useState(false);
  const [validateBusy, setValidateBusy] = useState(false);

  const refreshQueue = useCallback(() => {
    setQueueLoading(true);
    setQueueError(null);
    listCandidates()
      .then((res) => {
        setCandidates(res.candidates);
        setApiAvailable(true);
      })
      .catch((err: ApiError) => {
        setApiAvailable(false);
        setQueueError(err.message);
      })
      .finally(() => setQueueLoading(false));
  }, []);

  useEffect(() => {
    apiHealth()
      .then(() => refreshQueue())
      .catch(() => setApiAvailable(false));
  }, [refreshQueue]);

  useEffect(() => {
    localStorage.setItem(REVIEWER_KEY, reviewer);
  }, [reviewer]);

  const handlePromote = (candidateId: string) => {
    setBusyId(candidateId);
    setActionMessage(null);
    promoteCandidate(candidateId, reviewer.trim())
      .then(() => {
        setActionMessage(`Promoted ${candidateId}. The edge now appears in data/dist/promoted-edges.json.`);
        refreshQueue();
      })
      .catch((err: ApiError) => setActionMessage(`Failed to promote ${candidateId}: ${err.message}`))
      .finally(() => setBusyId(null));
  };

  const handleReject = (candidateId: string) => {
    setBusyId(candidateId);
    setActionMessage(null);
    rejectCandidate(candidateId, reviewer.trim())
      .then(() => {
        setActionMessage(`Rejected ${candidateId}.`);
        refreshQueue();
      })
      .catch((err: ApiError) => setActionMessage(`Failed to reject ${candidateId}: ${err.message}`))
      .finally(() => setBusyId(null));
  };

  const handleGenerate = () => {
    setGenBusy(true);
    setActionMessage(null);
    generateCandidates(genLimit)
      .then((res) => {
        setActionMessage(`Generated ${res.generated} new candidate(s).`);
        refreshQueue();
      })
      .catch((err: ApiError) => setActionMessage(`Failed to generate candidates: ${err.message}`))
      .finally(() => setGenBusy(false));
  };

  const handleValidate = () => {
    setValidateBusy(true);
    setActionMessage(null);
    validateCandidates()
      .then((res) => {
        setActionMessage(`Validated ${res.total} candidate(s): ${res.validated} now validated, ${res.rejected} rejected.`);
        refreshQueue();
      })
      .catch((err: ApiError) => setActionMessage(`Failed to validate candidates: ${err.message}`))
      .finally(() => setValidateBusy(false));
  };

  if (bundleLoading) return <LoadingState label="Loading knowledge bundle…" />;
  if (bundleError) return <ErrorState message={bundleError} onRetry={reloadBundle} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reloadBundle} />;

  const filtered = tab === "all" ? candidates : candidates.filter((c) => c.final_status === tab);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-800">AI review queue</h1>
        <p className="text-sm text-slate-500">
          AI-proposed candidates from <code className="rounded bg-slate-100 px-1 py-0.5 text-xs">data/review/ai-candidates.jsonl</code>. Determinism
          first: nothing here is canonical until a human promotes it (AI_ASSISTANCE_CONTRACT).
        </p>
      </div>

      {apiAvailable === false && (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm text-amber-800">
          <p className="font-medium">API sidecar not reachable{queueError ? ` (${queueError})` : ""}.</p>
          <p className="mt-1">The review queue is read-only without it. From the project root:</p>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-100">
{`CVEzD3FEND api                           # start the sidecar (default http://127.0.0.1:8000)
CVEzD3FEND ai generate-candidates --limit 10
CVEzD3FEND ai validate-candidates
CVEzD3FEND ai list-candidates
CVEzD3FEND ai promote-candidate <candidate_id> --reviewer "<name>"
CVEzD3FEND ai reject-candidate <candidate_id> --reviewer "<name>"`}
          </pre>
          <button
            type="button"
            onClick={() => {
              setApiAvailable(null);
              apiHealth()
                .then(() => refreshQueue())
                .catch(() => setApiAvailable(false));
            }}
            className="mt-3 rounded border border-amber-400 px-3 py-1.5 text-sm font-medium text-amber-800 hover:bg-amber-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500"
          >
            Check again
          </button>
        </div>
      )}

      {apiAvailable === null && <LoadingState label="Checking API sidecar…" />}

      {apiAvailable && (
        <>
          <div className="flex flex-wrap items-end gap-3 rounded-md border border-slate-200 bg-white p-3">
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Reviewer name</span>
              <input
                type="text"
                value={reviewer}
                onChange={(e) => setReviewer(e.target.value)}
                placeholder="your name"
                className="rounded border border-slate-300 px-2 py-1 text-sm focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Generate limit</span>
              <input
                type="number"
                min={1}
                max={100}
                value={genLimit}
                onChange={(e) => setGenLimit(Number(e.target.value))}
                className="w-20 rounded border border-slate-300 px-2 py-1 text-sm focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              />
            </label>
            <button
              type="button"
              onClick={handleGenerate}
              disabled={genBusy}
              className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:opacity-50"
            >
              {genBusy ? "Generating…" : "Generate candidates"}
            </button>
            <button
              type="button"
              onClick={handleValidate}
              disabled={validateBusy}
              className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:opacity-50"
            >
              {validateBusy ? "Validating…" : "Validate all"}
            </button>
            <button
              type="button"
              onClick={refreshQueue}
              disabled={queueLoading}
              className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:opacity-50"
            >
              {queueLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          {actionMessage && <p className="rounded border border-slate-200 bg-slate-50 p-2 text-sm text-slate-600">{actionMessage}</p>}

          <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Filter by status">
            {TABS.map((t) => {
              const count = t.value === "all" ? candidates.length : candidates.filter((c) => c.final_status === t.value).length;
              return (
                <button
                  key={t.value}
                  type="button"
                  role="tab"
                  aria-selected={tab === t.value}
                  onClick={() => setTab(t.value)}
                  className={`rounded border px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                    tab === t.value ? "border-link bg-blue-50 text-link" : "border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
                  }`}
                >
                  {t.label} ({count})
                </button>
              );
            })}
          </div>

          {queueLoading ? (
            <LoadingState label="Loading candidate queue…" />
          ) : filtered.length === 0 ? (
            <EmptyState title="No candidates in this view" hint="Generate candidates above, or switch tabs." />
          ) : (
            <div className="flex max-h-[640px] flex-col gap-2 overflow-y-auto pr-1">
              {filtered.map((c) => (
                <AiCandidateCard
                  key={c.candidate_id}
                  bundle={bundle}
                  candidate={c}
                  apiAvailable={Boolean(apiAvailable)}
                  reviewer={reviewer}
                  busy={busyId === c.candidate_id}
                  onPromote={handlePromote}
                  onReject={handleReject}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
