const CVE_RE = /^CVE-\d{4}-\d+$/i;
const CWE_RE = /^CWE-(\d+)$/i;
const CAPEC_RE = /^CAPEC-(\d+)$/i;
const ATTACK_RE = /^T(\d{4})(?:\.(\d{3}))?$/i;
const TACTIC_RE = /^TA\d{4}$/i;
const D3FEND_SAFE_RE = /^d3f:[A-Za-z][A-Za-z0-9]+$/;
const D3FEND_URL_RE = /^https:\/\/d3fend\.mitre\.org\/technique\/d3f:[A-Za-z][A-Za-z0-9]+\/?$/i;

const D3FEND_OFFICIAL_ID_MAP: Record<string, string> = {};

export function isTrustedD3fendUrl(url: string | null | undefined): boolean {
  return Boolean(url && D3FEND_URL_RE.test(url));
}

export function buildOfficialUrl(id: string): string | null {
  if (CVE_RE.test(id)) return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`;

  const cwe = id.match(CWE_RE);
  if (cwe) return `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`;

  const capec = id.match(CAPEC_RE);
  if (capec) return `https://capec.mitre.org/data/definitions/${capec[1]}.html`;

  const attack = id.match(ATTACK_RE);
  if (attack) {
    const [, technique, sub] = attack;
    return sub ? `https://attack.mitre.org/techniques/T${technique}/${sub}/` : `https://attack.mitre.org/techniques/T${technique}/`;
  }

  if (TACTIC_RE.test(id)) return `https://attack.mitre.org/tactics/${id.toUpperCase()}/`;

  if (D3FEND_SAFE_RE.test(id)) return `https://d3fend.mitre.org/technique/${encodeURIComponent(id)}`;

  const mappedD3fendUrl = D3FEND_OFFICIAL_ID_MAP[id.toUpperCase()];
  if (mappedD3fendUrl) return mappedD3fendUrl;

  return null;
}

export function buildTrustedOfficialUrl(id: string, providedUrl?: string | null): string | null {
  if (isTrustedD3fendUrl(providedUrl)) return providedUrl ?? null;
  return buildOfficialUrl(id);
}
