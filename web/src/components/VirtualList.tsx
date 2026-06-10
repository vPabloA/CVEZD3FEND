import { useRef, useState } from "react";

// UIX_CONTRACT §2: lists longer than ~50 items use windowing/virtualization.
// Fixed-height row virtualizer with a small overscan, scrolling inside a
// bounded max-height container (never page-level growth).
interface VirtualListProps<T> {
  items: T[];
  itemHeight: number;
  maxHeight: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  emptyMessage?: string;
  ariaLabel?: string;
}

export default function VirtualList<T>({
  items,
  itemHeight,
  maxHeight,
  renderItem,
  emptyMessage = "No items.",
  ariaLabel,
}: VirtualListProps<T>) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);

  if (items.length === 0) {
    return <p className="px-2 py-4 text-sm text-slate-500">{emptyMessage}</p>;
  }

  const overscan = 4;
  const visibleCount = Math.ceil(maxHeight / itemHeight) + overscan * 2;
  const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
  const endIndex = Math.min(items.length, startIndex + visibleCount);
  const totalHeight = items.length * itemHeight;
  const offsetY = startIndex * itemHeight;

  return (
    <div
      ref={containerRef}
      role="list"
      aria-label={ariaLabel}
      className="overflow-y-auto"
      style={{ maxHeight }}
      onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
    >
      <div style={{ height: totalHeight, position: "relative" }}>
        <div style={{ position: "absolute", top: offsetY, left: 0, right: 0 }}>
          {items.slice(startIndex, endIndex).map((item, i) => (
            <div role="listitem" key={startIndex + i} style={{ height: itemHeight }}>
              {renderItem(item, startIndex + i)}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
