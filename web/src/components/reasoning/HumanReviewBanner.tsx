import type { HumanReview } from "@/lib/reasoningTypes";

/** Surfaces ReasoningResult.human_review — never hidden when `required` is true. */
export default function HumanReviewBanner({ review }: { review: HumanReview }) {
  if (!review.required) return null;
  return (
    <div role="alert" className="flex gap-3 rounded-2xl border border-inferred bg-amber-50 px-4 py-3 text-sm text-amber-900 shadow-sm">
      <span className="select-none text-base leading-5 text-inferred" aria-hidden="true">
        ⚠
      </span>
      <div className="flex flex-col gap-1">
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-inferred">Governed review gate</p>
        <p className="font-medium">Requiere revisión</p>
        {review.reason && <p>{review.reason}</p>}
      </div>
    </div>
  );
}
