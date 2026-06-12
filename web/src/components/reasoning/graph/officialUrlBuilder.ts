const CVE_RE = /^CVE-\d{4}-\d+$/i;
const CWE_RE = /^CWE-(\d+)$/i;
const CAPEC_RE = /^CAPEC-(\d+)$/i;
const ATTACK_RE = /^T(\d{4})(?:\.(\d{3}))?$/i;
const TACTIC_RE = /^TA\d{4}$/i;
const D3FEND_RE = /^(?:D3-|D3F:)(.+)$/i;

function toPascalCase(value: string): string {
  return value
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join("");
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

  const defend = id.match(D3FEND_RE);
  if (defend) {
    const pascal = toPascalCase(defend[1]);
    if (!pascal) return null;
    return `https://d3fend.mitre.org/technique/${encodeURIComponent(`d3f:${pascal}`)}`;
  }

  return null;
}
