import ClampedText from "./ClampedText";
import { REASONING_CLASSIFICATION_LABELS, classificationClass } from "@/lib/colors";
import { nodeKindForId } from "@/components/reasoning/graph/graphAdapter";
import type { GraphNodeKind } from "@/components/reasoning/graph/graphTypes";
import type { ReasoningEdge, ReasoningResult } from "@/lib/reasoningTypes";

interface SkillLine {
  text: string;
  lang?: "es";
}

interface SkillCard {
  key: string;
  name: string;
  lens: string;
  body: SkillLine[];
  entities: string[];
  edges: ReasoningEdge[];
}

function routeEntityIds(result: ReasoningResult): string[] {
  return [
    ...new Set([
      ...result.route.canonical_chain,
      ...result.route.primary_nodes,
      ...result.route.secondary_nodes,
      ...result.route.conditional_nodes,
      ...result.route.defensive_nodes,
      ...result.route.weak_fit_nodes,
      ...result.edges.flatMap((edge) => [edge.source, edge.target]),
    ]),
  ];
}

function entitiesOfKind(ids: string[], kinds: GraphNodeKind[]): string[] {
  return ids.filter((id) => kinds.includes(nodeKindForId(id))).slice(0, 6);
}

function edgesTouchingKinds(edges: ReasoningEdge[], kinds: GraphNodeKind[]): ReasoningEdge[] {
  return edges.filter((edge) => kinds.includes(nodeKindForId(edge.source)) || kinds.includes(nodeKindForId(edge.target))).slice(0, 3);
}

function firstEvidence(edges: ReasoningEdge[]): SkillLine[] {
  const lines = new Set<string>();
  edges.forEach((edge) => {
    if (edge.evidence[0]) lines.add(edge.evidence[0]);
    else if (edge.note) lines.add(edge.note);
  });
  return [...lines].slice(0, 2).map((text) => ({ text }));
}

/**
 * "Threat-Defense Reasoning Skills" — the engine's visible narrative and
 * classified edges presented as specialized reasoning lenses over the
 * CVE→CWE→CAPEC→ATT&CK→D3FEND route. Every line is existing contract data
 * (narrative, route, edges, SOC pack); nothing here is fabricated reasoning
 * and no hidden chain-of-thought is exposed.
 */
export default function ReasoningSkillsPanel({ result }: { result: ReasoningResult }) {
  const ids = routeEntityIds(result);
  const { narrative } = result;

  const skills: SkillCard[] = [
    {
      key: "cve-interpreter",
      name: "CVE Interpreter",
      lens: "Vulnerability, affected behavior and exploitation context",
      body: narrative.summary_es?.trim() ? [{ text: narrative.summary_es, lang: "es" as const }] : [],
      entities: entitiesOfKind(ids, ["cve"]),
      edges: [],
    },
    {
      key: "weakness-mapper",
      name: "Weakness Mapper",
      lens: "Root weakness (CWE) behind the vulnerability",
      body: firstEvidence(edgesTouchingKinds(result.edges, ["cwe"])),
      entities: entitiesOfKind(ids, ["cwe"]),
      edges: edgesTouchingKinds(result.edges, ["cwe"]),
    },
    {
      key: "attack-pattern-mapper",
      name: "Attack Pattern Mapper",
      lens: "CAPEC attack patterns the weakness enables",
      body: firstEvidence(edgesTouchingKinds(result.edges, ["capec"])),
      entities: entitiesOfKind(ids, ["capec"]),
      edges: edgesTouchingKinds(result.edges, ["capec"]),
    },
    {
      key: "attck-mapper",
      name: "ATT&CK Mapper",
      lens: "Technique relationship — official, inferred, conditional or weak-fit",
      body: firstEvidence(edgesTouchingKinds(result.edges, ["attack"])),
      entities: entitiesOfKind(ids, ["attack"]),
      edges: edgesTouchingKinds(result.edges, ["attack"]),
    },
    {
      key: "d3fend-advisor",
      name: "D3FEND Advisor",
      lens: "Defensive direction and mitigation path",
      body: firstEvidence(edgesTouchingKinds(result.edges, ["defend", "mitigation", "control"])),
      entities: entitiesOfKind(ids, ["defend", "mitigation", "control"]),
      edges: edgesTouchingKinds(result.edges, ["defend", "mitigation", "control"]),
    },
    {
      key: "tier1-briefing",
      name: "Tier 1 Briefing",
      lens: "Immediate validation and containment path",
      body: [
        ...(narrative.tier1_conclusion_es?.trim() ? [{ text: narrative.tier1_conclusion_es, lang: "es" as const }] : []),
        ...result.soc_action_pack.containment.slice(0, 1).map((text) => ({ text })),
      ],
      entities: [],
      edges: [],
    },
  ].filter((skill) => skill.body.length > 0 || skill.entities.length > 0 || skill.edges.length > 0);

  return (
    <section className="rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-800">Threat-Defense Reasoning Skills</h2>
        <p className="mt-0.5 text-xs text-slate-500">
          Specialized reasoning lenses used to explain the route, evidence and defensive action.
        </p>
      </div>

      {skills.length === 0 ? (
        <p className="px-4 py-3 text-sm italic text-slate-400">No reasoning narrative is available for this CVE.</p>
      ) : (
        <ol className="divide-y divide-slate-100">
          {skills.map((skill) => (
            <li key={skill.key} className="px-4 py-3">
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <h3 className="text-xs font-semibold text-slate-700">{skill.name}</h3>
                <span className="text-[11px] text-slate-400">{skill.lens}</span>
              </div>
              {(skill.entities.length > 0 || skill.edges.length > 0) && (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  {skill.entities.map((id) => (
                    <span key={id} className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                      {id}
                    </span>
                  ))}
                  {[...new Set(skill.edges.map((edge) => edge.classification))].map((classification) => (
                    <span key={classification} className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${classificationClass(classification)}`}>
                      {REASONING_CLASSIFICATION_LABELS[classification]}
                    </span>
                  ))}
                </div>
              )}
              {skill.body.map((line) => (
                <div key={line.text} className="mt-1.5">
                  <ClampedText text={line.text} lang={line.lang} />
                </div>
              ))}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
