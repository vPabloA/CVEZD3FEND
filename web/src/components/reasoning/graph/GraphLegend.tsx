import { COLORS, REASONING_CLASSIFICATION_LABELS, classificationClass } from "@/lib/colors";
import type { GraphNodeKind } from "./graphTypes";
import type { ReasoningEdgeClassification } from "@/lib/reasoningTypes";

const NODE_KINDS: { kind: GraphNodeKind; label: string; color: string }[] = [
  { kind: "cve", label: "CVE", color: COLORS.link },
  { kind: "cwe", label: "CWE", color: COLORS.link },
  { kind: "capec", label: "CAPEC", color: COLORS.offense },
  { kind: "attack", label: "ATT&CK", color: COLORS.offense },
  { kind: "defend", label: "D3FEND", color: COLORS.defense },
  { kind: "control", label: "Control", color: COLORS.defense },
  { kind: "detection", label: "Detection", color: COLORS.evidence },
  { kind: "evidence", label: "Evidence", color: COLORS.evidence },
  { kind: "gap", label: "Gap", color: COLORS.gap },
  { kind: "candidate", label: "AI candidate", color: COLORS.inferred },
  { kind: "context", label: "Context", color: COLORS.template },
];

// Stroke samples mirror the on-canvas encoding: classification is expressed
// with dash pattern + color, never color alone.
const EDGE_STYLES: { classification: ReasoningEdgeClassification; color: string; dash?: string }[] = [
  { classification: "official_explicit", color: COLORS.ok },
  { classification: "dataset_derived", color: COLORS.link },
  { classification: "analytical_inferred", color: COLORS.inferred, dash: "6 3" },
  { classification: "conditional", color: COLORS.conditional, dash: "5 4" },
  { classification: "weak_fit", color: COLORS.template, dash: "2 3" },
  { classification: "unverified", color: COLORS.gap, dash: "2 5" },
];

export default function GraphLegend() {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        {NODE_KINDS.map((item) => (
          <span key={item.kind} className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-900/80 px-2 py-1 text-[11px] text-slate-300">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }} aria-hidden="true" />
            {item.label}
          </span>
        ))}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1.5">
        {EDGE_STYLES.map((item) => (
          <span key={item.classification} className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-medium ${classificationClass(item.classification)}`}>
            <svg width="26" height="8" aria-hidden="true" className="shrink-0">
              <line x1="1" y1="4" x2="25" y2="4" stroke={item.color} strokeWidth="2" strokeDasharray={item.dash} />
            </svg>
            {REASONING_CLASSIFICATION_LABELS[item.classification]}
          </span>
        ))}
      </div>
      <p className="text-[11px] leading-relaxed text-slate-500">
        Trace layout reads left → right: CVE → CWE → CAPEC → ATT&CK → D3FEND, with evidence and context in the last lane. The tinted lane
        marks the defensive destination; dashed strokes mark relations that are inferred, conditional or unverified.
      </p>
    </div>
  );
}
