import "@testing-library/jest-dom/vitest";
import React, { forwardRef, useEffect, useImperativeHandle } from "react";
import { vi } from "vitest";

interface MockGraphNode {
  id: string;
}

interface MockGraphLink {
  id: string;
}

interface MockForceGraphProps {
  graphData?: {
    nodes?: MockGraphNode[];
    links?: MockGraphLink[];
  };
  onNodeClick?: (node: MockGraphNode) => void;
  onLinkClick?: (link: MockGraphLink) => void;
  onEngineStop?: () => void;
}

vi.mock("react-force-graph-2d", () => {
  const MockForceGraph = forwardRef(function MockForceGraph(props: MockForceGraphProps, ref) {
    useImperativeHandle(ref, () => ({
      zoomToFit: vi.fn(),
    }));

    useEffect(() => {
      props.onEngineStop?.();
    }, [props]);

    return React.createElement(
      "div",
      { "data-testid": "force-graph-2d", className: "space-y-2 rounded border border-slate-300 p-2" },
      React.createElement("div", { className: "text-xs text-slate-500" }, "Mock force graph"),
      React.createElement(
        "div",
        { className: "flex flex-wrap gap-1" },
        ...(props.graphData?.nodes ?? []).map((node) =>
          React.createElement(
            "button",
            { key: node.id, type: "button", onClick: () => props.onNodeClick?.(node), className: "rounded border px-2 py-1 text-xs" },
            node.id
          )
        ),
        ...(props.graphData?.links ?? []).map((link) =>
          React.createElement(
            "button",
            { key: link.id, type: "button", onClick: () => props.onLinkClick?.(link), className: "rounded border px-2 py-1 text-xs" },
            link.id
          )
        )
      )
    );
  });

  return { __esModule: true, default: MockForceGraph };
});
