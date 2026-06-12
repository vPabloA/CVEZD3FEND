import { useState } from "react";
import { downloadText } from "@/lib/export";
import type { ReasoningExports } from "@/lib/reasoningTypes";

interface ExportEntry {
  key: string;
  label: string;
  hint: string;
  content: string;
  filename: string;
  mime: string;
}

/** Markdown / tree / Mermaid exports for the current reasoning result (EXPORT_CONTRACT). */
export default function ExportsPanel({ exports: result, cveId }: { exports: ReasoningExports; cveId: string }) {
  const [open, setOpen] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const entries: ExportEntry[] = [
    { key: "markdown", label: "Markdown report", hint: "Full reasoning report, ready to paste into a ticket or wiki.", content: result.markdown, filename: `${cveId}-reasoning.md`, mime: "text/markdown" },
    { key: "tree", label: "Tree view", hint: "Plain-text route tree for terminals and logs.", content: result.tree, filename: `${cveId}-route-tree.txt`, mime: "text/plain" },
    { key: "mermaid", label: "Mermaid diagram", hint: "Paste into a Mermaid renderer to visualize the route.", content: result.mermaid, filename: `${cveId}-route.mmd`, mime: "text/plain" },
  ].filter((e) => e.content?.trim());

  const handleCopy = async (entry: ExportEntry) => {
    try {
      await navigator.clipboard.writeText(entry.content);
      setCopied(entry.key);
      setTimeout(() => setCopied((c) => (c === entry.key ? null : c)), 1500);
    } catch {
      /* clipboard unavailable — copy button silently no-ops, download still works */
    }
  };

  return (
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-slate-700">Exports</h2>
      {entries.length === 0 ? (
        <p className="mt-2 text-sm italic text-slate-400">No export output was produced for this CVE.</p>
      ) : (
        <div className="mt-3 flex flex-col gap-2">
          {entries.map((entry) => {
            const isOpen = open === entry.key;
            return (
              <div key={entry.key} className="rounded border border-slate-200">
                <div className="flex flex-wrap items-center justify-between gap-2 p-2">
                  <div>
                    <p className="text-sm font-medium text-slate-700">{entry.label}</p>
                    <p className="text-xs text-slate-400">{entry.hint}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setOpen(isOpen ? null : entry.key)}
                      className="rounded border border-slate-300 px-2 py-1 text-xs font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                      aria-expanded={isOpen}
                    >
                      {isOpen ? "Hide" : "Preview"}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy(entry)}
                      className="rounded border border-slate-300 px-2 py-1 text-xs font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                    >
                      {copied === entry.key ? "Copied!" : "Copy"}
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadText(entry.filename, entry.content, entry.mime)}
                      className="rounded border border-slate-300 px-2 py-1 text-xs font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                    >
                      Download
                    </button>
                  </div>
                </div>
                {isOpen && (
                  <pre className="max-h-64 overflow-auto border-t border-slate-100 bg-slate-50 p-2 text-xs text-slate-700">{entry.content}</pre>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
