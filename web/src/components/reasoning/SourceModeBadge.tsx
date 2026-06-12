import { SOURCE_MODE_LABELS, sourceModeClass } from "@/lib/colors";

/**
 * Live/cached/offline indicator for the reasoning plane (UIX_CONTRACT §3 —
 * degraded states must be visible, never silently substituted).
 */
export default function SourceModeBadge({
  mode,
  fallbackUsed,
  fromCache,
}: {
  mode: string;
  fallbackUsed?: boolean;
  fromCache?: boolean;
}) {
  const label = SOURCE_MODE_LABELS[mode as keyof typeof SOURCE_MODE_LABELS] ?? mode;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span
        className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-medium ${sourceModeClass(mode)}`}
        aria-label={`Source mode: ${label}`}
      >
        <span aria-hidden="true">●</span> {label}
      </span>
      {fromCache && (
        <span className="rounded border border-template bg-slate-100 px-1.5 py-0.5 font-medium text-template">From cache</span>
      )}
      {fallbackUsed && (
        <span className="rounded border border-inferred bg-amber-50 px-1.5 py-0.5 font-medium text-inferred">Fallback used</span>
      )}
    </span>
  );
}
