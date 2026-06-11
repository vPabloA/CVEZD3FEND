import { REASONING_CLASSIFICATION_ICONS, REASONING_CLASSIFICATION_LABELS, classificationClass } from "@/lib/colors";
import type { ReasoningEdgeClassification } from "@/lib/reasoningTypes";

/**
 * One of the 7 reasoning-edge classification levels (official_explicit ..
 * unverified). Pairs color with an icon + label so color is never the only
 * signal (UIX_CONTRACT §7).
 */
export default function EdgeClassificationBadge({ classification }: { classification: ReasoningEdgeClassification }) {
  const label = REASONING_CLASSIFICATION_LABELS[classification];
  const icon = REASONING_CLASSIFICATION_ICONS[classification];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${classificationClass(classification)}`}
      aria-label={`Classification: ${label}`}
    >
      <span aria-hidden="true">{icon}</span> {label}
    </span>
  );
}
