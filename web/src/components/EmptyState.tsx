// UIX_CONTRACT §3: every list/search/detail view has a defined empty state with guidance.
export default function EmptyState({
  title = "No results",
  hint,
  children,
}: {
  title?: string;
  hint?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-md border border-dashed border-slate-300 bg-slate-50 px-6 py-10 text-center text-slate-500">
      <p className="font-medium text-slate-700">{title}</p>
      {hint && <p className="text-sm">{hint}</p>}
      {children}
    </div>
  );
}
