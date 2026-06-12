import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
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
  const navigate = useNavigate();
  const { bundle, loading, error, reload } = useBundle();
  const [q, setQ] = useQueryParam("q");
  const [typesRaw, setTypesRaw] = useQueryListParam("types");
  const [provenance, setProvenance] = useQueryParam("provenance", "all");
  const [recent, setRecent] = useState<string[]>([]);

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  useEffect(() => {
    if (q.trim()) saveRecent(q.trim());
  }, [q]);

  const results = useMemo(() => {
    if (!bundle || !q.trim()) return [];
    let nodes = search(bundle, q, 200);
    if (typesRaw.length > 0) nodes = nodes.filter((n) => typesRaw.includes(n.type));
    if (provenance === "canonical") nodes = nodes.filter((n) => n.canonical);
    if (provenance === "inferred") nodes = nodes.filter((n) => n.inferred);
    return nodes;
  }, [bundle, q, provenance, typesRaw]);

  const handleSubmit = () => {
    const query = q.trim();
    if (!query) return;
    if (/^CVE-\d{4}-\d+/i.test(query)) {
      navigate(`/analyze?cve=${encodeURIComponent(query.toUpperCase())}`);
      return;
    }
    setQ(query);
  };

  if (loading) return <LoadingState label="Loading knowledge bundle…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!bundle) return <ErrorState message="Bundle failed to load." onRetry={reload} />;

  return (
    <div className="flex flex-col gap-6">
      <section className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
        <div className="grid gap-6 bg-[radial-gradient(circle_at_top_left,rgba(31,111,235,0.12),transparent_26%),linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.95))] px-6 py-8 lg:grid-cols-[1.2fr_0.8fr] lg:px-8">
          <div className="flex flex-col gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-400">CVEzD3FEND</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">Analiza una CVE y sigue la ruta defensiva.</h1>
              <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-600">
                Una entrada, una ruta, una narrativa. Escribe una CVE para abrir el workbench de razonamiento, o usa la búsqueda para explorar el
                bundle con detalles avanzados cuando de verdad los necesites.
              </p>
            </div>

            <SearchBar
              value={q}
              onChange={setQ}
              autoFocus
              placeholder="Escribe una CVE para analizarla, o busca CWE / ATT&CK / D3FEND…"
              onSubmit={handleSubmit}
              submitLabel={/^CVE-\d{4}-\d+/i.test(q.trim()) ? "Analizar CVE" : "Buscar en bundle"}
            />

            {!q.trim() && recent.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
                <span>Recientes:</span>
                {recent.map((r) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setQ(r)}
                    className="rounded-full border border-slate-300 bg-white px-2 py-1 font-mono hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                  >
                    {r}
                  </button>
                ))}
              </div>
            )}

            <div className="flex flex-wrap gap-2 text-sm">
              <Link
                to="/analyze"
                className="rounded-full border border-link bg-link px-4 py-2 font-medium text-white hover:bg-blue-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Abrir workbench
              </Link>
              <details className="group rounded-full border border-slate-300 bg-white px-4 py-2">
                <summary className="cursor-pointer list-none text-slate-600">Acceso avanzado</summary>
                <div className="mt-2 flex flex-wrap gap-2 text-sm">
                  <Link to="/coverage" className="text-link hover:underline">
                    Coverage
                  </Link>
                  <Link to="/ai-review" className="text-link hover:underline">
                    AI Review
                  </Link>
                  <span className="text-slate-400">Route explorer lives in Analyze</span>
                </div>
              </details>
            </div>
          </div>

          <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white/85 p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Qué hace</p>
            <ul className="space-y-2 text-sm text-slate-600">
              <li>Ruta defensiva CVE → CWE → CAPEC → ATT&CK → D3FEND.</li>
              <li>Narrativa de Tier 1 y acción recomendada.</li>
              <li>Confianza, evidencia y revisión humana cuando hace falta.</li>
            </ul>
            <p className="text-xs text-slate-500">
              Los filtros, la cobertura y los detalles del bundle están disponibles en acceso avanzado.
            </p>
          </div>
        </div>
      </section>

      {q.trim() ? (
        /CVE-\d{4}-\d+/i.test(q.trim()) ? (
          <EmptyState title="Enter to analyze" hint="Press Enter or use the button above to open the reasoning workbench for this CVE.">
            <Link to={`/analyze?cve=${encodeURIComponent(q.trim().toUpperCase())}`} className="mt-2 text-sm text-link hover:underline">
              Open analysis
            </Link>
          </EmptyState>
        ) : (
          <section className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm text-slate-500">
                {results.length} result{results.length === 1 ? "" : "s"} for <span className="font-mono">"{q}"</span>
              </p>
              <details className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs text-slate-500">
                <summary className="cursor-pointer list-none">Filtros avanzados</summary>
                <div className="mt-3 max-w-sm">
                  <FilterPanel
                    selectedTypes={typesRaw as NodeType[]}
                    onTypesChange={(types) => setTypesRaw(types)}
                    provenance={provenance as ProvenanceFilter}
                    onProvenanceChange={(value) => setProvenance(value)}
                  />
                </div>
              </details>
            </div>
            <ResultList nodes={results} emptyTitle={`No results for "${q}"`} emptyHint="Try a CVE id, CWE-XXX, T1059, D3-FA, or clear filters." />
          </section>
        )
      ) : (
        <section className="grid gap-4 md:grid-cols-2">
          <EmptyState title="Empieza por una CVE" hint="Escribe una CVE para abrir el razonamiento o un término para explorar el bundle.">
            <Link to="/analyze" className="mt-2 text-sm text-link hover:underline">
              Ir al workbench
            </Link>
          </EmptyState>
          <div className="rounded-2xl border border-slate-200 bg-white p-4">
            <p className="text-sm font-semibold text-slate-700">Heurística rápida</p>
            <ul className="mt-2 space-y-2 text-sm text-slate-600">
              <li>1. CVE in, route out.</li>
              <li>2. Revisa la narrativa y la acción recomendada.</li>
              <li>3. Abre evidencia avanzada solo si hace falta.</li>
            </ul>
          </div>
        </section>
      )}
    </div>
  );
}
