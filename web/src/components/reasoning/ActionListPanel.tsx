export interface ActionListSection {
  label: string;
  items: string[];
}

/**
 * Generic labeled-list-of-strings panel. Used for the SOC Action Pack,
 * Detection Engineering brief and Threat Hunting brief — each is a set of
 * named string[] sections returned by `/api/reason/{cve_id}`.
 */
export default function ActionListPanel({ title, sections }: { title: string; sections: ActionListSection[] }) {
  const populated = sections.filter((s) => s.items.length > 0);
  return (
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-slate-700">{title}</h2>
      {populated.length === 0 ? (
        <p className="mt-2 text-sm italic text-slate-400">No {title.toLowerCase()} content was produced for this CVE.</p>
      ) : (
        <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {populated.map(({ label, items }) => (
            <div key={label}>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</h3>
              <ul className="list-inside list-disc text-sm text-slate-700">
                {items.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
