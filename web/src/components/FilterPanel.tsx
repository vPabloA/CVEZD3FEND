import type { NodeType } from "@/lib/types";
import { nodeTypeLabel } from "@/lib/colors";

const ALL_TYPES: NodeType[] = [
  "cve",
  "cwe",
  "capec",
  "attack",
  "defend",
  "atlas",
  "control",
  "detection",
  "evidence",
  "gap",
  "mitigation",
  "ctem_action",
  "soc_action",
  "threat_hunt",
  "rule",
  "query",
  "data_source",
  "log_source",
  "playbook",
];

export type ProvenanceFilter = "all" | "canonical" | "inferred";

interface FilterPanelProps {
  selectedTypes: NodeType[];
  onTypesChange: (types: NodeType[]) => void;
  provenance: ProvenanceFilter;
  onProvenanceChange: (value: ProvenanceFilter) => void;
}

/** Node-type + canonical/inferred filters, synced to the URL via lib/url.ts. */
export default function FilterPanel({ selectedTypes, onTypesChange, provenance, onProvenanceChange }: FilterPanelProps) {
  const toggle = (type: NodeType) => {
    if (selectedTypes.includes(type)) {
      onTypesChange(selectedTypes.filter((t) => t !== type));
    } else {
      onTypesChange([...selectedTypes, type]);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <fieldset>
        <legend className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Provenance</legend>
        <div className="flex flex-col gap-1">
          {(["all", "canonical", "inferred"] as ProvenanceFilter[]).map((opt) => (
            <label key={opt} className="flex items-center gap-2 text-sm capitalize">
              <input
                type="radio"
                name="provenance"
                value={opt}
                checked={provenance === opt}
                onChange={() => onProvenanceChange(opt)}
                className="focus-visible:ring-2 focus-visible:ring-link"
              />
              {opt}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Node type</legend>
        <div className="flex max-h-64 flex-col gap-1 overflow-y-auto pr-1">
          {ALL_TYPES.map((type) => (
            <label key={type} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={selectedTypes.includes(type)}
                onChange={() => toggle(type)}
                className="focus-visible:ring-2 focus-visible:ring-link"
              />
              {nodeTypeLabel(type)}
            </label>
          ))}
        </div>
        {selectedTypes.length > 0 && (
          <button
            type="button"
            onClick={() => onTypesChange([])}
            className="mt-2 text-xs font-medium text-link hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Clear type filters
          </button>
        )}
      </fieldset>
    </div>
  );
}
