import { useEffect, useState } from "react";

/**
 * CVE id command input + analyze action, styled as a workbench command
 * control (dark, mono) rather than a generic form field. The committed
 * value drives `useReasoning`; typing alone does not trigger a fetch.
 */
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
      className="flex w-full items-stretch overflow-hidden rounded-lg border border-slate-700 bg-slate-900 shadow-inner focus-within:border-link focus-within:ring-2 focus-within:ring-link/60"
    >
      <span className="flex select-none items-center pl-3 pr-1 font-mono text-sm text-sky-400" aria-hidden="true">
        ❯
      </span>
      <input
        type="text"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="CVE-YYYY-NNNNN"
        className="min-w-0 flex-1 bg-transparent px-2 py-2 font-mono text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none"
        aria-label="CVE ID to analyze"
        spellCheck={false}
        autoComplete="off"
      />
      <button
        type="submit"
        disabled={busy || !draft.trim()}
        className="border-l border-slate-700 bg-link px-4 text-sm font-semibold text-white transition hover:bg-blue-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? "Analyzing…" : "Analyze"}
      </button>
    </form>
  );
}
