import { Fragment } from "react";

function labelize(key: string): string {
  return key
    .split("_")
    .map((part) => (part.length > 0 ? part.charAt(0).toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function renderValue(value: unknown, depth: number): React.ReactNode {
  if (value === null || value === undefined || value === "") {
    return <span className="text-slate-400">—</span>;
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-slate-400">—</span>;
    if (value.every((item) => !isPlainObject(item))) {
      return value.map((item) => String(item)).join(", ");
    }
    if (depth >= 2) return `${value.length} item(s)`;
    return (
      <ul className="flex flex-col gap-1">
        {value.map((item, i) => (
          <li key={i} className="rounded border border-slate-100 bg-slate-50 p-1.5">
            {isPlainObject(item) ? <KeyFacts data={item} depth={depth + 1} /> : String(item)}
          </li>
        ))}
      </ul>
    );
  }
  if (isPlainObject(value)) {
    if (depth >= 2) return "…";
    return <KeyFacts data={value} depth={depth + 1} />;
  }
  return String(value);
}

/**
 * Generic, recursive renderer for the `dict[str, Any]` shapes returned by the
 * reasoning plane (CVSS/EPSS/KEV blocks, raw evidence, AI propose/validate
 * responses). Skips empty fields, formats nested objects/arrays, and never
 * falls back to a raw JSON dump for the first two levels (UIX product brief —
 * "no raw JSON-first experience").
 */
export default function KeyFacts({ data, depth = 0 }: { data: Record<string, unknown> | null | undefined; depth?: number }) {
  if (!data) return <p className="text-sm italic text-slate-400">No data</p>;
  const entries = Object.entries(data).filter(([, v]) => {
    if (v === null || v === undefined || v === "") return false;
    if (Array.isArray(v) && v.length === 0) return false;
    if (isPlainObject(v) && Object.keys(v).length === 0) return false;
    return true;
  });
  if (entries.length === 0) return <p className="text-sm italic text-slate-400">No data</p>;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-sm">
      {entries.map(([key, value]) => (
        <Fragment key={key}>
          <dt className="font-medium text-slate-500">{labelize(key)}</dt>
          <dd className="text-slate-700">{renderValue(value, depth)}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
