export default function BatchCveFilters({
  found,
  represented,
  selected,
  onChange,
}: {
  found: string[];
  represented: string[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const allSelected = selected.length === 0 || found.every((cve) => selected.includes(cve));
  const toggle = (cve: string) => {
    const next = selected.includes(cve) ? selected.filter((item) => item !== cve) : [...selected, cve];
    onChange(next.length === found.length ? [] : next);
  };
  return (
    <section aria-labelledby="cve-filter-title" className="rounded-xl border border-slate-800 bg-slate-950 p-3">
      <div className="flex items-center justify-between gap-2">
        <h3 id="cve-filter-title" className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">CVE filters</h3>
        <div className="flex items-center gap-2">
          <button type="button" onClick={() => onChange(represented.length === found.length ? [] : represented)} className="text-xs text-violet-300 hover:text-violet-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-300">Represented only</button>
          <button type="button" onClick={() => onChange([])} className="text-xs text-sky-400 hover:text-sky-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">All</button>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {found.map((cve) => {
          const active = allSelected || selected.includes(cve);
          const representedHere = represented.includes(cve);
          return (
            <button
              key={cve}
              type="button"
              aria-pressed={active}
              onClick={() => toggle(cve)}
              className={`rounded-full border px-2.5 py-1.5 font-mono text-[11px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${active ? "border-sky-400 bg-sky-950/60 text-sky-200" : "border-slate-700 bg-slate-900 text-slate-500"}`}
            >
              {cve} <span className="font-sans">{representedHere ? "represented" : "outside Top-K"}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
