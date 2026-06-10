// UIX_CONTRACT §3: every async fetch shows a skeleton/spinner, never a blank screen.
export default function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-slate-500" role="status" aria-live="polite">
      <div
        className="h-8 w-8 animate-spin rounded-full border-2 border-slate-300 border-t-link"
        aria-hidden="true"
      />
      <p className="text-sm">{label}</p>
    </div>
  );
}
