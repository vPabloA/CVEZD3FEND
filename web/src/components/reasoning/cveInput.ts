const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

export interface ParsedCveInput {
  tokens: string[];
  valid: string[];
  invalid: string[];
  duplicateCount: number;
}

export function parseCveInput(value: string): ParsedCveInput {
  const raw = value
    .split(/[\s,;]+/)
    .map((token) => token.trim().toUpperCase())
    .filter(Boolean);
  const tokens = [...new Set(raw)];
  return {
    tokens,
    valid: tokens.filter((token) => CVE_RE.test(token)),
    invalid: tokens.filter((token) => !CVE_RE.test(token)),
    duplicateCount: raw.length - tokens.length,
  };
}
