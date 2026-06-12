import { COLORS, REASONING_CLASSIFICATION_LABELS, classificationClass } from "@/lib/colors";
import type { GraphNodeKind } from "./graphTypes";

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
      <div className="flex flex-wrap gap-1.5">
        {(["official_explicit", "dataset_derived", "analytical_inferred", "conditional", "weak_fit", "unverified"] as const).map((classification) => (
          <span key={classification} className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${classificationClass(classification)}`}>
            {REASONING_CLASSIFICATION_LABELS[classification]}
          </span>
        ))}
      </div>
    </div>
  );
}
