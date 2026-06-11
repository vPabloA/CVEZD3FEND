import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import FilterPanel, { type ProvenanceFilter } from "@/components/FilterPanel";
import LoadingState from "@/components/LoadingState";
import ResultList from "@/components/ResultList";
import SearchBar from "@/components/SearchBar";
import { useBundle } from "@/hooks/useBundle";
import { search } from "@/lib/bundle";
import { useQueryListParam, useQueryParam } from "@/lib/url";
import type { NodeType } from "@/lib/types";

const RECENT_KEY = "cvezd3fend:recent-searches";
const RECENT_LIMIT = 8;

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function saveRecent(query: string) {
  const recent = loadRecent().filter((q) => q !== query);
  recent.unshift(query);
  localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, RECENT_LIMIT)));
}

export default function HomePage() {
  const { bundle, loading, error, reload } = useBundle();
  const [q, setQ] = useQueryParam("q");
  const [typesRaw, setTypesRaw] = useQueryListParam("types");
  const [provenance, setProvenance] = useQueryParam("provenance", "all");
  const [recent, setRecent] = useState<string[]>([]);

  const types = typesRaw as NodeType[];

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  useEffect(() => {
    if (q.trim()) saveRecent(q.trim());
  }, [q]);

  const results = useMemo(() => {
    if (!bundle || !q.trim()) return [];
    let nodes = search(bundle, q, 200);
    if (types.length > 0) nodes = nodes.filter((n) => types.includes(n.type));
    if (provenance === "canonical") nodes = nodes.filter((n) => n.canonical);
    if (provenance === "inferred") nodes = nodes.filter((n) => n.inferred);
    return nodes;
  }, [bundle, q, types, provenance]);

  if (loading) return <LoadingState label="Loading knowledge bundle…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reload} />;

  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-[16rem_1fr]">
      <aside className="md:sticky md:top-4 md:self-start">
        <FilterPanel
          selectedTypes={types}
          onTypesChange={(t) => setTypesRaw(t)}
          provenance={provenance as ProvenanceFilter}
          onProvenanceChange={(v) => setProvenance(v)}
        />
        <div className="mt-4 rounded-md border border-slate-200 bg-white p-3 text-xs text-slate-500">
          <p className="font-semibold uppercase tracking-wide text-slate-400">Bundle</p>
          <p className="mt-1">{bundle.nodes.length.toLocaleString()} nodes</p>
          <p>{bundle.edges.length.toLocaleString()} edges</p>
          <p>{bundle.routes.length.toLocaleString()} routes</p>
          <p className="mt-1 text-[11px]">Generated {bundle.generated_at}</p>
        </div>
      </aside>

      <section className="flex flex-col gap-4">
        <SearchBar value={q} onChange={setQ} autoFocus />

        {!q.trim() && recent.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
            <span>Recent:</span>
            {recent.map((r) => (
              <button
                key={r}
                type="button"
                onClick={() => setQ(r)}
                className="rounded border border-slate-300 bg-white px-1.5 py-0.5 font-mono hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                {r}
              </button>
            ))}
          </div>
        )}

        {!q.trim() ? (
          <EmptyState title="Search the knowledge bundle" hint="Try a CVE id, CWE-XXX, T1059, D3-FA, or any free text — or pick an example above.">
            <div className="mt-2 flex flex-wrap items-center justify-center gap-2 text-sm">
              <Link to="/analyze" className="text-link hover:underline">
                Reasoning workbench
              </Link>
              <span aria-hidden="true">·</span>
              <Link to="/coverage" className="text-link hover:underline">
                Browse defensive coverage
              </Link>
              <span aria-hidden="true">·</span>
              <Link to="/ai-review" className="text-link hover:underline">
                AI review queue
              </Link>
            </div>
          </EmptyState>
        ) : (
          <>
            <p className="text-sm text-slate-500">
              {results.length} result{results.length === 1 ? "" : "s"} for <span className="font-mono">"{q}"</span>
            </p>
            <ResultList nodes={results} emptyTitle={`No results for "${q}"`} emptyHint="Try a CVE id, CWE-XXX, T1059, D3-FA, or clear filters." />
          </>
        )}
      </section>
    </div>
  );
}
