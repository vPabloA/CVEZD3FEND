import EmptyState from "./EmptyState";
import NodeCard from "./NodeCard";
import VirtualList from "./VirtualList";
import type { BundleNode } from "@/lib/types";

const ITEM_HEIGHT = 84;
const VIRTUALIZE_THRESHOLD = 50;
const MAX_HEIGHT = 560;

/** Search/relation result list. Virtualized once it exceeds ~50 items (UIX_CONTRACT §2). */
export default function ResultList({
  nodes,
  emptyTitle = "No results",
  emptyHint,
}: {
  nodes: BundleNode[];
  emptyTitle?: string;
  emptyHint?: string;
}) {
  if (nodes.length === 0) {
    return <EmptyState title={emptyTitle} hint={emptyHint} />;
  }

  if (nodes.length > VIRTUALIZE_THRESHOLD) {
    return (
      <VirtualList
        items={nodes}
        itemHeight={ITEM_HEIGHT}
        maxHeight={MAX_HEIGHT}
        ariaLabel="Search results"
        renderItem={(node) => (
          <div className="pb-2 pr-1">
            <NodeCard node={node} />
          </div>
        )}
      />
    );
  }

  return (
    <div className="flex max-h-[560px] flex-col gap-2 overflow-y-auto pr-1">
      {nodes.map((node) => (
        <NodeCard key={node.id} node={node} />
      ))}
    </div>
  );
}
