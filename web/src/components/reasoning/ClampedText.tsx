import { useState } from "react";

const CLAMP_THRESHOLD = 280;

/**
 * Long narrative passages stay scannable: clamp to a few lines by default
 * with an explicit disclosure. The full text is always available — nothing
 * is truncated away, only folded.
 */
export default function ClampedText({
  text,
  lang,
  className = "text-sm leading-relaxed text-slate-600",
  lines = 4,
}: {
  text: string;
  lang?: string;
  className?: string;
  lines?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const clampable = text.length > CLAMP_THRESHOLD;

  return (
    <div>
      <p
        className={`whitespace-pre-line ${className}`}
        lang={lang}
        style={
          clampable && !expanded
            ? { display: "-webkit-box", WebkitLineClamp: lines, WebkitBoxOrient: "vertical", overflow: "hidden" }
            : undefined
        }
      >
        {text}
      </p>
      {clampable && (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          aria-expanded={expanded}
          className="mt-1 text-xs font-medium text-link hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          {expanded ? "Show less" : "Read full interpretation"}
        </button>
      )}
    </div>
  );
}
