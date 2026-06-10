import { useState } from "react";
import { Link } from "react-router-dom";
import { getNode } from "@/lib/bundle";
import type { AICandidate, KnowledgeBundle } from "@/lib/types";

const STATUS_CLASSES: Record<string, string> = {
  candidate: "border-template bg-slate-100 text-template",
  validated_candidate: "border-ok bg-green-50 text-ok",
  rejected: "border-gap bg-red-50 text-gap",
  canonical: "border-ok bg-green-50 text-ok",
};

interface AiCandidateCardProps {
  bundle: KnowledgeBundle;
  candidate: AICandidate;
  apiAvailable: boolean;
  reviewer: string;
  busy: boolean;
  onPromote: (candidateId: string) => void;
  onReject: (candidateId: string) => void;
}

/** One AI candidate with diff-vs-bundle and promote/reject actions (AI_ASSISTANCE_CONTRACT). */
export default function AiCandidateCard({ bundle, candidate, apiAvailable, reviewer, busy, onPromote, onReject }: AiCandidateCardProps) {
  const [expanded, setExpanded] = useState(false);
  const actionable = candidate.final_status === "candidate" || candidate.final_status === "validated_candidate";
  const disabled = !apiAvailable || !actionable || busy || !reviewer.trim();

  return (
    <div className="rounded-md border border-slate-200 bg-white p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-semibold text-slate-800">{candidate.candidate_id}</span>
          <span className={`rounded border px-1.5 py-0.5 text-xs font-medium ${STATUS_CLASSES[candidate.final_status] ?? STATUS_CLASSES.candidate}`}>
            {candidate.final_status}
          </span>
          <span className="rounded border border-slate-300 px-1.5 py-0.5 text-xs font-mono text-slate-500">
            conf {candidate.confidence.toFixed(2)}
          </span>
          <span className="text-xs text-slate-400">{candidate.provider}</span>
          {candidate.validation_status === "rejected" && (
            <span className="rounded border border-gap bg-red-50 px-1.5 py-0.5 text-xs font-medium text-gap">validation: rejected</span>
          )}
        </div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="rounded border border-slate-300 px-2 py-1 text-xs font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          aria-expanded={expanded}
        >
          {expanded ? "Hide diff" : "Show diff"}
        </button>
      </div>

      <p className="mt-2 text-sm text-slate-600">{candidate.rationale}</p>

      {candidate.validation_errors.length > 0 && (
        <ul className="mt-2 list-inside list-disc text-xs text-gap">
          {candidate.validation_errors.map((err, i) => (
            <li key={i}>{err}</li>
          ))}
        </ul>
      )}

      {expanded && (
        <div className="mt-3 flex flex-col gap-2 rounded border border-slate-100 bg-slate-50 p-2 text-xs">
          {candidate.proposed_edges.length > 0 && (
            <div>
              <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Proposed edges (+)</p>
              <ul className="flex flex-col gap-1">
                {candidate.proposed_edges.map((edge, i) => {
                  const e = edge as { source?: string; target?: string; type?: string; confidence?: number };
                  const source = e.source ? getNode(bundle, e.source) : undefined;
                  const target = e.target ? getNode(bundle, e.target) : undefined;
                  return (
                    <li key={i} className="font-mono text-emerald-700">
                      + {e.source} ({source?.name ?? "?"}) —[{e.type}]→ {e.target} ({target?.name ?? "?"}) conf{" "}
                      {e.confidence?.toFixed(2)}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
          {candidate.proposed_nodes.length > 0 && (
            <div>
              <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Proposed nodes (+)</p>
              <ul className="flex flex-col gap-1">
                {candidate.proposed_nodes.map((node, i) => {
                  const n = node as { id?: string; type?: string; name?: string };
                  return (
                    <li key={i} className="font-mono text-emerald-700">
                      + {n.id} [{n.type}] {n.name}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
          <div>
            <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Inputs</p>
            <div className="flex flex-wrap gap-1">
              {candidate.input_refs.map((ref) => {
                const n = getNode(bundle, ref);
                return n ? (
                  <Link key={ref} to={`/node/${encodeURIComponent(ref)}`} className="rounded border border-slate-300 bg-white px-1.5 py-0.5 font-mono hover:bg-slate-100">
                    {ref}
                  </Link>
                ) : (
                  <span key={ref} className="rounded border border-slate-300 bg-white px-1.5 py-0.5 font-mono text-slate-400">
                    {ref}
                  </span>
                );
              })}
            </div>
          </div>
          {candidate.reviewer && (
            <p className="text-slate-500">
              Reviewed by <span className="font-medium">{candidate.reviewer}</span>
              {candidate.policy_decision && ` — ${candidate.policy_decision}`}
            </p>
          )}
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={disabled}
          onClick={() => onPromote(candidate.candidate_id)}
          className="rounded border border-ok bg-green-50 px-2 py-1 text-xs font-medium text-ok hover:bg-green-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-ok disabled:cursor-not-allowed disabled:opacity-50"
        >
          Promote
        </button>
        <button
          type="button"
          disabled={disabled}
          onClick={() => onReject(candidate.candidate_id)}
          className="rounded border border-gap bg-red-50 px-2 py-1 text-xs font-medium text-gap hover:bg-red-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-gap disabled:cursor-not-allowed disabled:opacity-50"
        >
          Reject
        </button>
        {!apiAvailable && <span className="text-xs text-slate-400">API offline — start `CVEzD3FEND api` to act on candidates</span>}
        {apiAvailable && !actionable && <span className="text-xs text-slate-400">Already {candidate.final_status}</span>}
        {apiAvailable && actionable && !reviewer.trim() && <span className="text-xs text-slate-400">Enter a reviewer name to act</span>}
      </div>
    </div>
  );
}
