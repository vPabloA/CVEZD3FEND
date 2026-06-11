import { useEffect, useState } from "react";

/** CVE id input + analyze action. The committed value drives `useReasoning`; typing alone does not trigger a fetch. */
export default function CveAnalyzeForm({ value, onSubmit, busy }: { value: string; onSubmit: (cveId: string) => void; busy: boolean }) {
  const [draft, setDraft] = useState(value);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(draft.trim());
      }}
      className="flex flex-col gap-2 sm:flex-row sm:items-end"
    >
      <label className="flex flex-1 flex-col gap-1 text-sm">
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">CVE ID</span>
        <input
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="e.g. CVE-2021-44228"
          className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm shadow-sm focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          aria-label="CVE ID to analyze"
        />
      </label>
      <button
        type="submit"
        disabled={busy || !draft.trim()}
        className="rounded-md border border-link bg-link px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? "Analyzing…" : "Analyze"}
      </button>
    </form>
  );
}
