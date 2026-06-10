import { Link } from "react-router-dom";
import { getNode } from "@/lib/bundle";
import { downloadJson, downloadText, socActionPackToMarkdown } from "@/lib/export";
import type { KnowledgeBundle, SocActionPack } from "@/lib/types";
import { coverageBgClass, nodeColorClass } from "@/lib/colors";
import { TypeBadge } from "./NodeBadge";

const PRIORITY_CLASSES: Record<SocActionPack["priority"], string> = {
  Critical: "border-gap bg-red-100 text-gap",
  High: "border-gap bg-red-50 text-gap",
  Medium: "border-amber-300 bg-amber-50 text-amber-700",
  Low: "border-ok bg-green-50 text-ok",
  Info: "border-template bg-slate-100 text-template",
};

function RefList({ bundle, ids, emptyLabel = "None" }: { bundle: KnowledgeBundle; ids: string[]; emptyLabel?: string }) {
  if (ids.length === 0) return <p className="text-sm italic text-slate-400">{emptyLabel}</p>;
  return (
    <ul className="flex flex-col gap-1">
      {ids.map((id) => {
        const node = getNode(bundle, id);
        return (
          <li key={id}>
            <Link to={`/node/${encodeURIComponent(id)}`} className={`font-mono text-sm hover:underline ${node ? nodeColorClass(node) : "text-slate-500"}`}>
              {id}
            </Link>
            {node && <span className="ml-2 text-sm text-slate-600">{node.name}</span>}
            {node && <TypeBadge type={node.type} />}
          </li>
        );
      })}
    </ul>
  );
}

export default function SocActionPackView({ bundle, pack }: { bundle: KnowledgeBundle; pack: SocActionPack }) {
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">{pack.title}</h2>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${PRIORITY_CLASSES[pack.priority]}`}>{pack.priority} priority</span>
            <span className="rounded border border-slate-300 px-2 py-0.5 text-xs font-mono text-slate-500">conf {pack.confidence.toFixed(2)}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => downloadText(`${pack.id}.md`, socActionPackToMarkdown(bundle, pack), "text/markdown")}
            className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Download Markdown
          </button>
          <button
            type="button"
            onClick={() => downloadJson(`${pack.id}.json`, pack)}
            className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Download JSON
          </button>
        </div>
      </div>

      <section>
        <h3 className="mb-1 text-sm font-semibold uppercase tracking-wide text-slate-500">Executive summary</h3>
        <p className="text-sm text-slate-700">{pack.executive_summary}</p>
      </section>

      <section>
        <h3 className="mb-1 text-sm font-semibold uppercase tracking-wide text-slate-500">Technical summary</h3>
        <p className="text-sm text-slate-700">{pack.technical_summary}</p>
      </section>

      <section>
        <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Attack / defensive path</h3>
        <div className="flex flex-wrap items-center gap-2">
          {pack.attack_path.map((id, i) => {
            const node = getNode(bundle, id);
            return (
              <span key={id} className="flex items-center gap-2">
                {i > 0 && (
                  <span aria-hidden="true" className="text-slate-300">
                    →
                  </span>
                )}
                <Link to={`/node/${encodeURIComponent(id)}`} className={`font-mono text-sm hover:underline ${node ? nodeColorClass(node) : "text-slate-500"}`}>
                  {id}
                </Link>
              </span>
            );
          })}
        </div>
        {pack.defensive_path.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="text-xs uppercase tracking-wide text-slate-400">Defensive:</span>
            {pack.defensive_path.map((id) => {
              const node = getNode(bundle, id);
              return (
                <Link key={id} to={`/node/${encodeURIComponent(id)}`} className={`font-mono text-sm hover:underline ${node ? nodeColorClass(node) : "text-slate-500"}`}>
                  {id}
                </Link>
              );
            })}
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        <section>
          <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Recommended actions</h3>
          <RefList bundle={bundle} ids={pack.recommended_actions} />
        </section>
        <section>
          <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Hunting hypotheses</h3>
          <RefList bundle={bundle} ids={pack.hunting_hypotheses} emptyLabel="No threat hunt generated for this technique" />
        </section>
        <section>
          <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Detection opportunities</h3>
          <RefList bundle={bundle} ids={pack.detection_opportunities} />
        </section>
        <section>
          <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Required logs / evidence</h3>
          <RefList bundle={bundle} ids={[...pack.required_evidence, ...pack.required_logs]} />
        </section>
        <section>
          <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Mitigations</h3>
          <RefList bundle={bundle} ids={pack.mitigations} />
        </section>
        <section>
          <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Gaps</h3>
          {pack.gaps.length === 0 ? (
            <p className="text-sm italic text-slate-400">None</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {pack.gaps.map((id) => {
                const node = getNode(bundle, id);
                return (
                  <li key={id}>
                    <Link to={`/node/${encodeURIComponent(id)}`} className="font-mono text-sm text-gap hover:underline">
                      {id}
                    </Link>
                    {node?.metadata?.reason ? (
                      <span className={`ml-2 inline-flex rounded border px-1.5 py-0.5 text-xs ${coverageBgClass("gap")}`}>
                        {String(node.metadata.reason)}
                      </span>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>

      <section>
        <h3 className="mb-1.5 text-sm font-semibold uppercase tracking-wide text-slate-500">Sources</h3>
        <div className="flex flex-wrap gap-1.5">
          {pack.source_refs.map((ref) => (
            <span key={ref} className="rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 font-mono text-xs text-slate-600">
              {ref}
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}
