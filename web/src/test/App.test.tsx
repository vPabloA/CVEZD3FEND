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
  it("renders the simplified landing surface with a single primary analyze action", async () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole("heading", { name: /analiza una cve/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /analizar cve/i })).toHaveAttribute("href", "/analyze");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });
});
