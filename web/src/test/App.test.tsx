import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { makeBundle } from "@/test/fixtures/bundle";

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      if (url.includes("knowledge-bundle.json")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(makeBundle()) } as Response);
      }
      if (url.includes("promoted-edges.json")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([]) } as Response);
      }
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    })
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("App", () => {
  it("renders the home page with navigation including the Reasoning workbench entry point", async () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    );

    const nav = screen.getByRole("navigation", { name: /main navigation/i });
    expect(nav).toHaveTextContent("Search");
    expect(nav).toHaveTextContent("Analyze");
    expect(nav).toHaveTextContent("Coverage");
    expect(nav).toHaveTextContent("AI Review");

    expect(await screen.findByText("Search the knowledge bundle", { selector: "p" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /reasoning workbench/i })).toHaveAttribute("href", "/analyze");
  });
});
