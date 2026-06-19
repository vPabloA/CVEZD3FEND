import { describe, expect, it } from "vitest";
import { parseCveInput } from "@/components/reasoning/cveInput";

describe("parseCveInput", () => {
  it("parses CVEs separated by lines", () => {
    expect(parseCveInput("CVE-2025-0168\nCVE-2026-0544").valid).toEqual(["CVE-2025-0168", "CVE-2026-0544"]);
  });

  it("parses commas, semicolons and whitespace", () => {
    expect(parseCveInput("cve-2025-0168, CVE-2026-0544; CVE-2024-0001").valid).toEqual([
      "CVE-2025-0168",
      "CVE-2026-0544",
      "CVE-2024-0001",
    ]);
  });

  it("deduplicates while preserving first-seen order", () => {
    const parsed = parseCveInput("CVE-2026-0544 cve-2025-0168 CVE-2026-0544");
    expect(parsed.tokens).toEqual(["CVE-2026-0544", "CVE-2025-0168"]);
    expect(parsed.duplicateCount).toBe(1);
  });

  it("keeps invalid tokens visible without removing valid CVEs", () => {
    const parsed = parseCveInput("CVE-2025-0168 invalid CVE-20-1");
    expect(parsed.valid).toEqual(["CVE-2025-0168"]);
    expect(parsed.invalid).toEqual(["INVALID", "CVE-20-1"]);
  });
});
