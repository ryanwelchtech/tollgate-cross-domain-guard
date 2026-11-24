// Offline vulnerability snapshot. On the high side of an air gap there is no
// live NVD/KEV feed, so the guard ships with a dated snapshot that is itself
// imported through TOLLGATE (it is just another signed transfer package).

import type { VulnRecord } from './types.ts';

export const VULN_SNAPSHOT_DATE = '2026-11-01';

export const VULN_SNAPSHOT: VulnRecord[] = [
  { name: 'log4j-core', affected: '>=2.0.0,<2.15.0', cve: 'CVE-2021-44228', kev: true, summary: 'Log4Shell JNDI lookup RCE' },
  { name: 'spring-beans', affected: '>=5.3.0,<5.3.18|>=5.2.0,<5.2.20', cve: 'CVE-2022-22965', kev: true, summary: 'Spring4Shell data-binding RCE' },
  { name: 'struts2-core', affected: '>=2.3.5,<2.3.32|>=2.5.0,<2.5.10.1', cve: 'CVE-2017-5638', kev: true, summary: 'Jakarta multipart parser RCE' },
  { name: 'xz-utils', affected: '5.6.0|5.6.1', cve: 'CVE-2024-3094', kev: false, summary: 'Backdoored liblzma release tarballs' },
  { name: 'liblzma', affected: '5.6.0|5.6.1', cve: 'CVE-2024-3094', kev: false, summary: 'Backdoored liblzma release tarballs' },
  { name: 'openssl', affected: '>=3.0.0,<3.0.7', cve: 'CVE-2022-3602', kev: false, summary: 'X.509 email address buffer overflow' },
  { name: 'commons-text', affected: '>=1.5,<1.10.0', cve: 'CVE-2022-42889', kev: false, summary: 'Text4Shell variable interpolation RCE' },
];

function parts(v: string): number[] {
  return v.split(/[.\-+]/).map((p) => parseInt(p, 10)).map((n) => (Number.isNaN(n) ? 0 : n));
}

export function cmpVersion(a: string, b: string): number {
  const pa = parts(a), pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** "a|b" = alternatives, "x,y" = all constraints, ops: >= <= > < = or bare exact. */
export function versionMatches(version: string, spec: string): boolean {
  return spec.split('|').some((alt) =>
    alt.split(',').every((c) => {
      const m = c.trim().match(/^(>=|<=|>|<|=)?\s*(.+)$/);
      if (!m) return false;
      const op = m[1] ?? '=';
      const r = cmpVersion(version, m[2]);
      switch (op) {
        case '>=': return r >= 0;
        case '<=': return r <= 0;
        case '>': return r > 0;
        case '<': return r < 0;
        default: return r === 0;
      }
    }),
  );
}
