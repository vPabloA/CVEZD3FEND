import { nodeTypeLabel } from "@/lib/colors";
import type { NodeType } from "@/lib/types";

/** Type chip + canonical/inferred badge. Color is never the only signal (UIX_CONTRACT §7). */
export function TypeBadge({ type }: { type: NodeType }) {
  return (
    <span className="inline-flex items-center rounded border border-slate-300 bg-slate-100 px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-slate-600">
      {nodeTypeLabel(type)}
    </span>
  );
}

export function ProvenanceBadge({ canonical, inferred }: { canonical: boolean; inferred: boolean }) {
  if (inferred) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded border border-inferred bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-inferred"
        aria-label="AI-inferred, not yet promoted to canonical"
      >
        <span aria-hidden="true">~</span> Inferred
      </span>
    );
  }
  if (canonical) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded border border-ok bg-green-50 px-1.5 py-0.5 text-xs font-medium text-ok"
        aria-label="Canonical, framework-asserted"
      >
        <span aria-hidden="true">✓</span> Canonical
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-template bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-template">
      Non-canonical
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: number }) {
  return (
    <span
      className="inline-flex items-center rounded border border-slate-300 px-1.5 py-0.5 text-xs font-mono text-slate-600"
      aria-label={`Confidence ${confidence.toFixed(2)}`}
    >
      conf {confidence.toFixed(2)}
    </span>
  );
}

export function AiPromotedBadge() {
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-dashed border-inferred bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-inferred"
      aria-label="AI-promoted edge, human-reviewed"
    >
      AI-promoted
    </span>
  );
}
