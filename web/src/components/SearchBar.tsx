import { EXAMPLE_QUERIES } from "@/lib/bundle";

export default function SearchBar({
  value,
  onChange,
  placeholder = "Search CVE, CWE, CAPEC, ATT&CK, D3FEND, ATLAS, control, detection, gap…",
  autoFocus = false,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
}) {
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor="cvezd3fend-search" className="sr-only">
        Search the knowledge bundle
      </label>
      <input
        id="cvezd3fend-search"
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
      />
      {!value && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
          <span>Try:</span>
          {EXAMPLE_QUERIES.map((ex) => (
            <button
              key={ex}
              type="button"
              onClick={() => onChange(ex)}
              className="rounded border border-slate-300 bg-white px-1.5 py-0.5 font-mono hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
            >
              {ex}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
