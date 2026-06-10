import { Link } from "react-router-dom";
import { getNode } from "@/lib/bundle";
import { coverageBgClass } from "@/lib/colors";
import type { CoverageTechnique, KnowledgeBundle, Route } from "@/lib/types";
import EmptyState from "./EmptyState";
import VirtualList from "./VirtualList";

const ROW_HEIGHT = 56;
const MAX_HEIGHT = 600;

/** Find the best route to drill into for a given ATT&CK technique. */
function routeForTechnique(bundle: KnowledgeBundle, attackId: string): Route | undefined {
  return bundle.routes.find((r) => r.nodes.includes(attackId));
}

/** Filterable, virtualized coverage table (UIX_CONTRACT "Defensive Coverage"). */
export default function CoverageTable({ bundle, techniques }: { bundle: KnowledgeBundle; techniques: CoverageTechnique[] }) {
  if (techniques.length === 0) {
    return <EmptyState title="No techniques match the current filters" hint="Try clearing the status filter." />;
  }

  return (
    <div className="overflow-hidden rounded-md border border-slate-200">
      <div className="grid grid-cols-[1fr_8rem_5rem_5rem_5rem_1fr] gap-2 border-b border-slate-200 bg-slate-100 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        <span>Technique</span>
        <span>Coverage</span>
        <span>D3FEND</span>
        <span>Controls</span>
        <span>Detections</span>
        <span>Gap reason</span>
      </div>
      <VirtualList
        items={techniques}
        itemHeight={ROW_HEIGHT}
        maxHeight={MAX_HEIGHT}
        ariaLabel="Defensive coverage table"
        renderItem={(t) => <CoverageRow bundle={bundle} technique={t} />}
      />
    </div>
  );
}

function CoverageRow({ bundle, technique }: { bundle: KnowledgeBundle; technique: CoverageTechnique }) {
  const node = getNode(bundle, technique.attack_technique);
  const route = routeForTechnique(bundle, technique.attack_technique);
  const target = route ? `/route/${encodeURIComponent(route.route_id)}` : `/node/${encodeURIComponent(technique.attack_technique)}`;

  return (
    <Link
      to={target}
      className="grid h-full grid-cols-[1fr_8rem_5rem_5rem_5rem_1fr] items-center gap-2 border-b border-slate-100 px-3 py-2 text-sm hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
    >
      <span className="truncate">
        <span className="font-mono font-semibold text-offense">{technique.attack_technique}</span>
        {node && <span className="ml-1.5 text-slate-500">{node.name}</span>}
      </span>
      <span className={`inline-flex w-fit items-center rounded border px-1.5 py-0.5 text-xs font-medium ${coverageBgClass(technique.coverage_status)}`}>
        {technique.coverage_status}
      </span>
      <span className="text-center text-xs text-slate-600">{technique.defend_techniques.length}</span>
      <span className="text-center text-xs text-slate-600">{technique.controls.length}</span>
      <span className="text-center text-xs text-slate-600">{technique.detections.length}</span>
      <span className="truncate text-xs text-slate-500">{technique.gap_reason ?? "—"}</span>
    </Link>
  );
}
