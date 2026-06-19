import { useMemo, useState } from "react";
import type { AnalysisContext, BatchAnalysisRequest } from "@/lib/reasoningTypes";
import { parseCveInput } from "./cveInput";
const EXPOSURE_OPTIONS = ["internet-facing", "internal", "production"] as const;
const PRIORITY_OPTIONS = ["initial access", "execution", "credential theft", "ransomware", "service continuity"] as const;
const AUDIENCE_OPTIONS = ["SOC", "Threat Hunting", "Detection Engineering", "CTEM", "Executive"] as const;

function toggleValue(values: string[], value: string): string[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

function ChoiceChip({
  value,
  checked,
  onChange,
  group,
}: {
  value: string;
  checked: boolean;
  onChange: () => void;
  group: string;
}) {
  return (
    <label className={`inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-2.5 py-1.5 text-xs font-medium transition focus-within:ring-2 focus-within:ring-sky-400 ${checked ? "border-sky-400 bg-sky-950/70 text-sky-200" : "border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-500"}`}>
      <input type="checkbox" name={group} value={value} checked={checked} onChange={onChange} className="sr-only" />
      <span aria-hidden="true">{checked ? "✓" : "+"}</span>
      {value}
    </label>
  );
}

export default function CveAnalyzeForm({
  initialValue = "",
  busy,
  onSubmit,
  onClear,
}: {
  initialValue?: string;
  busy: boolean;
  onSubmit: (request: BatchAnalysisRequest) => void;
  onClear?: () => void;
}) {
  const [input, setInput] = useState(initialValue);
  const [technologies, setTechnologies] = useState("");
  const [exposure, setExposure] = useState<string[]>([]);
  const [priorities, setPriorities] = useState<string[]>([]);
  const [audience, setAudience] = useState<AnalysisContext["audience"]>("SOC");
  const [topK, setTopK] = useState(5);
  const [useAi, setUseAi] = useState(false);
  const parsed = useMemo(() => parseCveInput(input), [input]);
  const technologyTags = useMemo(
    () => [...new Set(technologies.split(",").map((item) => item.trim()).filter(Boolean))],
    [technologies]
  );

  const clear = () => {
    setInput("");
    setTechnologies("");
    setExposure([]);
    setPriorities([]);
    setAudience("SOC");
    setTopK(5);
    setUseAi(false);
    onClear?.();
  };

  return (
    <form
      id="multi-cve-analysis-form"
      aria-label="Multi-CVE contextual analysis"
      onSubmit={(event) => {
        event.preventDefault();
        if (parsed.tokens.length === 0) return;
        onSubmit({
          cve_ids: parsed.tokens,
          context: { technologies: technologyTags, exposure, priorities, audience },
          top_k: topK,
          include_all_candidates: false,
          use_ai: useAi,
        });
      }}
      className="grid gap-5 rounded-2xl border border-slate-800 bg-slate-950 p-5 shadow-xl"
    >
      <div>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-sky-400">Multi-CVE contextual analysis</p>
            <h1 className="mt-1 text-xl font-semibold text-slate-100">What should CVEzD3FEND prioritize?</h1>
            <p className="mt-1 max-w-3xl text-sm text-slate-400">Paste CVE identifiers from Excel, email or a ticket. Lines, commas and whitespace are accepted; invalid values remain visible and do not cancel valid CVEs.</p>
          </div>
          <button type="button" onClick={clear} disabled={busy} className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 hover:border-slate-500 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-40">Clear</button>
        </div>
        <label htmlFor="batch-cves" className="mt-4 block text-sm font-semibold text-slate-200">CVE identifiers</label>
        <p id="batch-cves-help" className="mt-1 text-xs text-slate-500">Example: CVE-2025-0168, CVE-2026-0544</p>
        <textarea
          id="batch-cves"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          rows={5}
          spellCheck={false}
          autoComplete="off"
          aria-describedby={`batch-cves-help${parsed.invalid.length ? " batch-cves-errors" : ""}`}
          aria-invalid={parsed.invalid.length > 0}
          placeholder={"CVE-2025-0168\nCVE-2026-0544\nCVE-2025-99999999, invalid"}
          className="mt-2 w-full resize-y rounded-xl border border-slate-700 bg-slate-900 px-3 py-3 font-mono text-sm text-slate-100 shadow-inner placeholder:text-slate-600 focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40"
        />
        <div className="mt-3 flex flex-wrap gap-2 text-xs" aria-live="polite">
          <span className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-slate-300">{parsed.tokens.length} detected</span>
          <span className="rounded-full border border-emerald-500/40 bg-emerald-950/40 px-2.5 py-1 text-emerald-200">{parsed.valid.length} valid</span>
          <span className={`rounded-full border px-2.5 py-1 ${parsed.invalid.length ? "border-amber-500/50 bg-amber-950/40 text-amber-200" : "border-slate-700 bg-slate-900 text-slate-400"}`}>{parsed.invalid.length} invalid</span>
          {parsed.duplicateCount > 0 && <span className="rounded-full border border-violet-500/40 bg-violet-950/40 px-2.5 py-1 text-violet-200">{parsed.duplicateCount} duplicate{parsed.duplicateCount === 1 ? "" : "s"} removed</span>}
        </div>
        {(parsed.valid.length > 0 || parsed.invalid.length > 0) && (
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Valid input</p>
              <div className="mt-2 flex flex-wrap gap-1.5">{parsed.valid.length ? parsed.valid.map((id) => <span key={id} className="rounded border border-emerald-500/30 bg-emerald-950/30 px-1.5 py-0.5 font-mono text-[11px] text-emerald-200">{id}</span>) : <span className="text-xs text-slate-500">No valid CVE yet.</span>}</div>
            </div>
            <div id="batch-cves-errors" className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Invalid input</p>
              <div className="mt-2 flex flex-wrap gap-1.5">{parsed.invalid.length ? parsed.invalid.map((id) => <span key={id} className="rounded border border-amber-500/40 bg-amber-950/30 px-1.5 py-0.5 font-mono text-[11px] text-amber-200">{id}</span>) : <span className="text-xs text-slate-500">None.</span>}</div>
            </div>
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <label htmlFor="technologies" className="block text-sm font-semibold text-slate-200">Technologies</label>
          <p id="technologies-help" className="mt-1 text-xs text-slate-500">Comma-separated tags, for example Windows, Active Directory, Kubernetes or AWS.</p>
          <input id="technologies" value={technologies} onChange={(event) => setTechnologies(event.target.value)} aria-describedby="technologies-help" placeholder="Windows, Active Directory" className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40" />
          {technologyTags.length > 0 && <div className="mt-2 flex flex-wrap gap-1.5" aria-label="Normalized technology tags">{technologyTags.map((tag) => <span key={tag} className="rounded-full border border-sky-500/30 bg-sky-950/30 px-2 py-1 text-xs text-sky-200">{tag}</span>)}</div>}
        </div>
        <fieldset>
          <legend className="text-sm font-semibold text-slate-200">Exposure</legend>
          <p className="mt-1 text-xs text-slate-500">Select every environment property that applies.</p>
          <div className="mt-2 flex flex-wrap gap-2">{EXPOSURE_OPTIONS.map((option) => <ChoiceChip key={option} group="exposure" value={option} checked={exposure.includes(option)} onChange={() => setExposure(toggleValue(exposure, option))} />)}</div>
        </fieldset>
        <fieldset>
          <legend className="text-sm font-semibold text-slate-200">Priorities</legend>
          <p className="mt-1 text-xs text-slate-500">These signals influence deterministic contextual utility.</p>
          <div className="mt-2 flex flex-wrap gap-2">{PRIORITY_OPTIONS.map((option) => <ChoiceChip key={option} group="priorities" value={option} checked={priorities.includes(option)} onChange={() => setPriorities(toggleValue(priorities, option))} />)}</div>
        </fieldset>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="audience" className="block text-sm font-semibold text-slate-200">Audience</label>
            <select id="audience" value={audience} onChange={(event) => setAudience(event.target.value as AnalysisContext["audience"])} className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40">{AUDIENCE_OPTIONS.map((option) => <option key={option}>{option}</option>)}</select>
            <p className="mt-1 text-[11px] text-slate-500">Presentation only; scoring is unchanged.</p>
          </div>
          <div>
            <label htmlFor="top-k" className="block text-sm font-semibold text-slate-200">Top-K routes</label>
            <select id="top-k" value={topK} onChange={(event) => setTopK(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-400/40">{[5, 10, 20].map((value) => <option key={value} value={value}>{value}</option>)}</select>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4 border-t border-slate-800 pt-4">
        <label className="flex max-w-2xl cursor-pointer items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3 focus-within:ring-2 focus-within:ring-sky-400">
          <input type="checkbox" checked={useAi} onChange={(event) => setUseAi(event.target.checked)} className="mt-0.5 h-4 w-4 accent-sky-500" />
          <span>
            <span className="block text-sm font-semibold text-slate-200">AI-assisted reranking</span>
            <span className="mt-0.5 block text-xs leading-relaxed text-slate-500">Off by default. Deterministic selection always works. AI can only reorder validated shortlist route IDs; it cannot create nodes, mappings or edges.</span>
          </span>
        </label>
        <button type="submit" disabled={busy || parsed.tokens.length === 0} className="rounded-xl bg-sky-500 px-5 py-3 text-sm font-semibold text-white shadow-lg transition hover:bg-sky-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-white disabled:cursor-not-allowed disabled:opacity-50">{busy ? "Analyzing…" : "Analyze CVEs"}</button>
      </div>
    </form>
  );
}
