import type { HumanReview } from "@/lib/reasoningTypes";

/** Surfaces ReasoningResult.human_review — never hidden when `required` is true. */
export default function HumanReviewBanner({ review }: { review: HumanReview }) {
  if (!review.required) return null;
  return (
    <div role="alert" className="flex flex-col gap-1 rounded-md border border-inferred bg-amber-50 px-4 py-3 text-sm text-amber-900">
      <p className="font-medium">
        <span aria-hidden="true">⚠</span> Human review required
      </p>
      {review.reason && <p>{review.reason}</p>}
    </div>
  );
}
