import { useMemo } from "react";
import CoverageTable from "@/components/CoverageTable";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import SearchBar from "@/components/SearchBar";
import { useBundle } from "@/hooks/useBundle";
import { getNode } from "@/lib/bundle";
import { coverageBgClass } from "@/lib/colors";
import { useQueryParam } from "@/lib/url";
import type { CoverageStatus } from "@/lib/types";

const STATUSES: CoverageStatus[] = ["covered", "partial", "gap", "unknown", "not_applicable"];

export default function CoveragePage() {
  const { bundle, loading, error, reload } = useBundle();
  const [status, setStatus] = useQueryParam("status", "");
  const [q, setQ] = useQueryParam("q");

  const filtered = useMemo(() => {
    if (!bundle) return [];
    let techniques = bundle.coverage.techniques;
    if (status) techniques = techniques.filter((t) => t.coverage_status === status);
    if (q.trim()) {
      const needle = q.trim().toLowerCase();
      techniques = techniques.filter((t) => {
        if (t.attack_technique.toLowerCase().includes(needle)) return true;
        const node = getNode(bundle, t.attack_technique);
        return node ? node.name.toLowerCase().includes(needle) : false;
      });
    }
    return techniques;
  }, [bundle, status, q]);

  if (loading) return <LoadingState label="Loading knowledge bundle…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reload} />;

  const summary = bundle.coverage.summary;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-800">Defensive coverage</h1>
        <p className="text-sm text-slate-500">{bundle.coverage.techniques.length.toLocaleString()} ATT&CK techniques tracked.</p>
      </div>

      <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by coverage status">
        {STATUSES.map((s) => {
          const count = summary[s as keyof typeof summary] ?? 0;
          const active = status === s;
          return (
            <button
              key={s}
              type="button"
              onClick={() => setStatus(active ? "" : s)}
              className={`rounded border px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                active ? "ring-2 ring-link" : ""
              } ${coverageBgClass(s)}`}
              aria-pressed={active}
            >
              {s} ({count.toLocaleString()})
            </button>
          );
        })}
        {status && (
          <button type="button" onClick={() => setStatus("")} className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-500 hover:bg-slate-50">
            Clear
          </button>
        )}
      </div>

      <SearchBar value={q} onChange={setQ} placeholder="Filter by technique id or name (e.g. T1059, Command)" />

      <p className="text-sm text-slate-500">
        Showing {filtered.length.toLocaleString()} of {bundle.coverage.techniques.length.toLocaleString()} techniques
      </p>

      <CoverageTable bundle={bundle} techniques={filtered} />
    </div>
  );
}
