// The inspection stages. Each stage is a pure function of the package, the
// policy and the current (possibly already-sanitized) file set.

import type { Finding, Policy, Severity, TransferFile, TransferPackage, Verdict } from './types.ts';
import { canonical, extname, sha256, td, te, verify } from './encoding.ts';
import { EXTENSION_KINDS, identify } from './magic.ts';
import { readZipDirectory } from './zip.ts';
import { VULN_SNAPSHOT, versionMatches } from './vulns.ts';

export interface StageContext {
  pkg: TransferPackage;
  policy: Policy;
  files: TransferFile[];
}

export interface StageDef {
  id: string;
  title: string;
  control: string; // NIST 800-53 / guard requirement it implements
  run(ctx: StageContext, f: FindingSink): Promise<void>;
}

export type FindingSink = (sev: Severity, rule: string, message: string, file?: string, offset?: number) => void;

export function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((x) => x.severity === 'critical' || x.severity === 'high')) return 'block';
  if (findings.some((x) => x.severity === 'medium' || x.severity === 'low')) return 'warn';
  return 'pass';
}

const textOf = (f: TransferFile) => td.decode(f.bytes);

function isTextual(f: TransferFile): boolean {
  return identify(f.bytes).textual;
}

function lineCol(text: string, offset: number): string {
  const before = text.slice(0, offset);
  const line = before.split('\n').length;
  return `line ${line}`;
}

// ---------------------------------------------------------------- integrity
const integrity: StageDef = {
  id: 'integrity',
  title: 'Manifest integrity',
  control: 'SI-7 Software, Firmware & Information Integrity',
  async run({ pkg, policy, files }, f) {
    const m = pkg.manifest;
    const byName = new Map(files.map((x) => [x.name, x]));
    if (files.length > policy.maxFiles) f('high', 'max-files', `Package has ${files.length} files (limit ${policy.maxFiles})`);
    const total = files.reduce((a, x) => a + x.bytes.length, 0);
    if (total > policy.maxPackageBytes) f('high', 'max-package-size', `Package is ${total} bytes (limit ${policy.maxPackageBytes})`);
    const seen = new Set<string>();
    for (const x of files) {
      if (seen.has(x.name)) f('critical', 'duplicate-name', 'Duplicate file name in package', x.name);
      seen.add(x.name);
      // eslint-disable-next-line no-control-regex
      if (/(^|\/)\.\.(\/|$)|^\/|\\|:|[\x00-\x1f]/.test(x.name)) {
        f('critical', 'path-traversal', 'Unsafe path (traversal, absolute, or control characters)', x.name);
      }
      if (x.bytes.length > policy.maxFileBytes) f('high', 'max-file-size', `File is ${x.bytes.length} bytes (limit ${policy.maxFileBytes})`, x.name);
    }
    for (const e of m.files) {
      const x = byName.get(e.name);
      if (!x) { f('critical', 'missing-file', 'Listed in manifest but not present in package', e.name); continue; }
      if (x.bytes.length !== e.size) f('critical', 'size-mismatch', `Size ${x.bytes.length} does not match manifest ${e.size}`, e.name);
      const h = await sha256(x.bytes);
      if (h !== e.sha256) f('critical', 'hash-mismatch', `SHA-256 ${h.slice(0, 16)}… does not match manifest ${e.sha256.slice(0, 16)}…`, e.name);
    }
    const listed = new Set(m.files.map((e) => e.name));
    for (const x of files) if (!listed.has(x.name)) f('critical', 'unlisted-file', 'File present but not declared in manifest (smuggling)', x.name);
    if (m.direction !== 'low-to-high') f('critical', 'direction', `Direction ${m.direction} not permitted by this guard`);
  },
};

// ---------------------------------------------------------------- signature
const signature: StageDef = {
  id: 'signature',
  title: 'Publisher signature',
  control: 'SR-4 Provenance / SI-7(15) Code Authentication',
  async run({ pkg, policy }, f) {
    const m = pkg.manifest;
    if (!pkg.signature) {
      if (policy.requireSignature) f('high', 'unsigned', 'Package is unsigned; policy requires a trusted publisher signature');
      else f('low', 'unsigned', 'Package is unsigned');
      return;
    }
    if (!m.publisher || !policy.trustStore[m.publisher]) {
      f('high', 'untrusted-publisher', `Publisher "${m.publisher ?? '(none)'}" is not in the guard trust store`);
      return;
    }
    const ok = await verify(policy.trustStore[m.publisher], canonical(m), pkg.signature);
    if (!ok) f('critical', 'bad-signature', 'Ed25519 signature does not verify: manifest altered after signing, or signed with a different key');
    else f('info', 'signature-ok', `Ed25519 signature verified for publisher "${m.publisher}"`);
  },
};

// ---------------------------------------------------------------- file type
const filetype: StageDef = {
  id: 'filetype',
  title: 'True file type',
  control: 'SC-7 Boundary Protection / AC-4 Information Flow Enforcement',
  async run({ policy, files }, f) {
    for (const x of files) {
      const ext = extname(x.name);
      const zipNames = readZipDirectory(x.bytes)?.map((e) => e.name);
      const t = identify(x.bytes, zipNames);
      if (t.executable) { f('critical', 'executable', `Executable content detected (${t.label}); executables never cross this guard`, x.name); continue; }
      if (!policy.allowedExtensions.includes(ext)) { f('high', 'extension-denied', `Extension "${ext || '(none)'}" is not on the allow list`, x.name); continue; }
      const kinds = EXTENSION_KINDS[ext];
      if (kinds && !kinds.includes(t.kind)) {
        f('critical', 'masquerade', `Claims ${ext} but content is ${t.label}`, x.name);
      } else {
        f('info', 'type-ok', `${t.label}`, x.name);
      }
    }
  },
};

// ---------------------------------------------------------------- archives
const archive: StageDef = {
  id: 'archive',
  title: 'Archive & macro analysis',
  control: 'SI-3 Malicious Code Protection',
  async run({ policy, files }, f) {
    for (const x of files) {
      const entries = readZipDirectory(x.bytes);
      const k = identify(x.bytes, entries?.map((e) => e.name)).kind;
      if (k !== 'zip' && k !== 'ooxml') continue;
      if (!entries) { f('high', 'corrupt-archive', 'Archive directory unreadable', x.name); continue; }
      if (entries.length > policy.archive.maxEntries) f('high', 'archive-entries', `${entries.length} entries (limit ${policy.archive.maxEntries})`, x.name);
      const c = entries.reduce((a, e) => a + e.compressedSize, 0);
      const u = entries.reduce((a, e) => a + e.uncompressedSize, 0);
      const ratio = u / Math.max(1, c);
      if (ratio > policy.archive.maxRatio) f('critical', 'decompression-bomb', `Expansion ratio ${ratio.toFixed(0)}:1 (${(u / 1048576).toFixed(1)} MiB from ${(c / 1024).toFixed(1)} KiB) exceeds ${policy.archive.maxRatio}:1`, x.name);
      for (const e of entries) {
        if (e.encrypted) f('high', 'encrypted-entry', `Encrypted entry "${e.name}" cannot be inspected`, x.name);
        if (/(^|\/)\.\.(\/|$)|^\//.test(e.name)) f('critical', 'zip-slip', `Entry "${e.name}" escapes extraction root`, x.name);
        if (/vbaProject\.bin$|vbaData\.xml$/i.test(e.name)) f('critical', 'macro', `VBA macro project "${e.name}" present (macro-enabled document)`, x.name);
        if (/activeX|oleObject/i.test(e.name)) f('high', 'embedded-object', `Embedded OLE/ActiveX object "${e.name}"`, x.name);
        if (/\.(exe|dll|scr|js|vbs|ps1|bat|cmd|sh|hta|jar)$/i.test(e.name)) f('high', 'archive-executable', `Executable/script entry "${e.name}"`, x.name);
        if (/\.(zip|7z|rar|gz|tgz|iso)$/i.test(e.name) && !policy.archive.allowNested) f('medium', 'nested-archive', `Nested archive "${e.name}" requires separate submission`, x.name);
      }
    }
  },
};

// ---------------------------------------------------------------- CDR
// Content Disarm & Reconstruct: rebuild what can be rebuilt, block what can't.
const ZW = /[​-‍⁠᠎]/g;
const BIDI = /[‪-‮⁦-⁩]/g;

function stripPng(b: Uint8Array): { out: Uint8Array; removed: string[]; trailing: number } | null {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (!sig.every((v, i) => b[i] === v)) return null;
  const keep = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'sRGB']);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const parts: Uint8Array[] = [b.subarray(0, 8)];
  const removed: string[] = [];
  let p = 8;
  let trailing = 0;
  while (p + 12 <= b.length) {
    const len = dv.getUint32(p);
    const type = String.fromCharCode(b[p + 4], b[p + 5], b[p + 6], b[p + 7]);
    const end = p + 12 + len;
    if (end > b.length) return null;
    if (keep.has(type)) parts.push(b.subarray(p, end));
    else removed.push(type);
    p = end;
    if (type === 'IEND') { trailing = b.length - p; break; }
  }
  const out = new Uint8Array(parts.reduce((a, x) => a + x.length, 0));
  let o = 0;
  for (const x of parts) { out.set(x, o); o += x.length; }
  return { out, removed, trailing };
}

const cdr: StageDef = {
  id: 'cdr',
  title: 'Content disarm & reconstruct',
  control: 'SI-3 / SC-18 Mobile Code',
  async run(ctx, f) {
    const next: TransferFile[] = [];
    for (const x of ctx.files) {
      const t = identify(x.bytes);
      if (t.kind === 'pdf') {
        const s = td.decode(x.bytes);
        const hits = ['/JavaScript', '/JS', '/OpenAction', '/Launch', '/EmbeddedFile', '/AA', '/RichMedia', '/XFA'].filter((k) => new RegExp(k.replace('/', '\\/') + '\\b').test(s));
        if (hits.length) f('high', 'pdf-active-content', `Active PDF content (${hits.join(', ')}) cannot be safely reconstructed`, x.name);
        next.push(x);
        continue;
      }
      if (t.kind === 'png') {
        const r = stripPng(x.bytes);
        if (!r) { f('high', 'png-malformed', 'Malformed PNG chunk stream', x.name); next.push(x); continue; }
        if (r.trailing > 0) f('high', 'polyglot', `${r.trailing} bytes appended after IEND (polyglot / smuggled payload)`, x.name);
        if (r.removed.length) f('low', 'png-metadata', `Removed ancillary chunks: ${[...new Set(r.removed)].join(', ')}`, x.name);
        next.push({ name: x.name, bytes: r.out });
        continue;
      }
      if (t.kind === 'svg' || t.kind === 'html') {
        let s = td.decode(x.bytes);
        const before = s;
        s = s.replace(/<script[\s\S]*?<\/script\s*>/gi, '')
          .replace(/<foreignObject[\s\S]*?<\/foreignObject\s*>/gi, '')
          .replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
          .replace(/(href|xlink:href|src)\s*=\s*(["'])\s*javascript:[^"']*\2/gi, '$1="#"');
        if (s !== before) f('medium', 'active-content-removed', 'Scripts, event handlers or javascript: URLs removed', x.name);
        next.push({ name: x.name, bytes: te.encode(s) });
        continue;
      }
      if (t.textual) {
        let s = td.decode(x.bytes);
        const bidi = s.match(BIDI)?.length ?? 0;
        const zw = s.match(ZW)?.length ?? 0;
        if (bidi) f('medium', 'trojan-source', `Removed ${bidi} bidirectional control character(s) (Trojan Source, CVE-2021-42574)`, x.name);
        if (zw) f('medium', 'zero-width', `Removed ${zw} zero-width character(s) (filter evasion / watermarking)`, x.name);
        if (bidi || zw) s = s.replace(BIDI, '').replace(ZW, '');
        next.push(bidi || zw ? { name: x.name, bytes: te.encode(s) } : x);
        continue;
      }
      next.push(x);
    }
    ctx.files = next;
  },
};

// ---------------------------------------------------------------- markings
interface ParsedMark { level: number; raw: string }

function parseBanner(line: string, levels: string[]): ParsedMark | null {
  const s = line.trim().toUpperCase();
  // Longest level names first so "TOP SECRET" wins over "SECRET".
  const ordered = levels.map((l, i) => ({ l, i })).sort((a, b) => b.l.length - a.l.length);
  for (const { l, i } of ordered) {
    if (s === l || s.startsWith(l + '//')) return { level: i, raw: line.trim() };
  }
  return null;
}

const PORTION: Record<string, string> = { U: 'UNCLASSIFIED', CUI: 'CUI', C: 'CONFIDENTIAL', S: 'SECRET', TS: 'TOP SECRET' };

const markings: StageDef = {
  id: 'markings',
  title: 'Classification markings',
  control: 'AC-16 Security Attributes / 32 CFR 2002 (CUI)',
  async run({ policy, files }, f) {
    const L = policy.markingLevels;
    const srcMax = L.indexOf(policy.sourceNetwork.maxLevel);
    const dstMax = L.indexOf(policy.destination.maxLevel);
    for (const x of files) {
      if (!policy.markingRequiredExtensions.includes(extname(x.name))) continue;
      const lines = textOf(x).split(/\r?\n/).filter((l) => l.trim().length);
      if (!lines.length) continue;
      const top = parseBanner(lines[0], L);
      const bottom = parseBanner(lines[lines.length - 1], L);
      if (!top || !bottom) { f('high', 'unmarked', `Missing ${!top ? 'top' : 'bottom'} banner marking`, x.name); continue; }
      if (top.raw.toUpperCase() !== bottom.raw.toUpperCase()) f('medium', 'banner-mismatch', `Top banner "${top.raw}" differs from bottom "${bottom.raw}"`, x.name);
      const level = Math.max(top.level, bottom.level);
      let maxPortion = -1;
      for (const l of lines) {
        const m = l.trim().match(/^\((U|CUI|C|S|TS)(\/\/[A-Z0-9 ,-]+)?\)/);
        if (m) maxPortion = Math.max(maxPortion, L.indexOf(PORTION[m[1]]));
      }
      if (maxPortion > level) f('high', 'portion-exceeds-banner', `Portion marking (${L[maxPortion]}) exceeds banner (${L[level]})`, x.name);
      const eff = Math.max(level, maxPortion);
      if (eff > srcMax) {
        f('critical', 'spillage', `${L[eff]} content on ${policy.sourceNetwork.name} (accredited to ${policy.sourceNetwork.maxLevel}): probable spillage. Quarantine and notify ISSM`, x.name);
      } else if (eff > dstMax) {
        f('critical', 'exceeds-destination', `${L[eff]} exceeds destination accreditation ${policy.destination.maxLevel}`, x.name);
      } else {
        f('info', 'marking-ok', `Marked ${top.raw}`, x.name);
      }
    }
  },
};

// ---------------------------------------------------------------- dirty words
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const dirtyword: StageDef = {
  id: 'dirtyword',
  title: 'Dirty-word search',
  control: 'AC-4(8) Security & Privacy Policy Filters',
  async run({ policy, files }, f) {
    const words = policy.dirtyWords.map((w) => new RegExp(`\\b${esc(w).replace(/\s+/g, '\\s+')}\\b`, 'gi'));
    const pats = policy.dirtyPatterns.map((p) => new RegExp(p, 'g'));
    for (const x of files) {
      if (!isTextual(x)) continue;
      const s = textOf(x);
      for (const re of [...words, ...pats]) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let n = 0;
        while ((m = re.exec(s)) && n < 5) {
          f('high', 'dirty-word', `Restricted term "${m[0]}" at ${lineCol(s, m.index)}`, x.name, m.index);
          n++;
        }
      }
    }
  },
};

// ---------------------------------------------------------------- secrets
const SECRET_RULES: { rule: string; re: RegExp; label: string }[] = [
  { rule: 'aws-access-key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, label: 'AWS access key ID' },
  { rule: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g, label: 'Private key block' },
  { rule: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g, label: 'GitHub token' },
  { rule: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, label: 'Slack token' },
  { rule: 'vault-token', re: /\bhvs\.[A-Za-z0-9_-]{24,}\b/g, label: 'HashiCorp Vault token' },
  { rule: 'password-assignment', re: /\b(password|passwd|pwd|secret)\s*[:=]\s*["']?[^\s"']{6,}/gi, label: 'Hard-coded password' },
];

const secrets: StageDef = {
  id: 'secrets',
  title: 'Credential leak scan',
  control: 'IA-5(7) No Embedded Unencrypted Static Authenticators',
  async run({ files }, f) {
    for (const x of files) {
      if (!isTextual(x)) continue;
      const s = textOf(x);
      for (const r of SECRET_RULES) {
        r.re.lastIndex = 0;
        const m = r.re.exec(s);
        if (m) {
          const red = m[0].slice(0, 6) + '…' + '*'.repeat(6);
          f('high', r.rule, `${r.label} (${red}) at ${lineCol(s, m.index)}`, x.name, m.index);
        }
      }
    }
  },
};

// ---------------------------------------------------------------- SBOM
interface CdxComponent { name?: string; version?: string; purl?: string; licenses?: { license?: { id?: string } }[] }

const sbom: StageDef = {
  id: 'sbom',
  title: 'SBOM vulnerability gate',
  control: 'RA-5 Vulnerability Monitoring / SR-3 Supply Chain Controls',
  async run({ policy, files }, f) {
    let any = false;
    for (const x of files) {
      if (identify(x.bytes).kind !== 'json') continue;
      let doc: { bomFormat?: string; components?: CdxComponent[] };
      try { doc = JSON.parse(textOf(x)); } catch { continue; }
      if (doc.bomFormat !== 'CycloneDX') continue;
      any = true;
      const comps = doc.components ?? [];
      let hits = 0;
      for (const c of comps) {
        if (!c.name || !c.version) continue;
        for (const v of VULN_SNAPSHOT) {
          if (v.name === c.name && versionMatches(c.version, v.affected)) {
            hits++;
            f(v.kev ? 'critical' : 'high', v.kev ? 'kev' : 'cve', `${c.name}@${c.version}: ${v.cve} ${v.summary}${v.kev ? ' [CISA KEV]' : ''}`, x.name);
          }
        }
        for (const l of c.licenses ?? []) {
          const id = l.license?.id;
          if (id && policy.sbom.deniedLicenses.includes(id)) f('medium', 'license', `${c.name}@${c.version} is ${id} (requires legal review)`, x.name);
        }
      }
      if (!hits) f('info', 'sbom-clean', `${comps.length} components, no matches in offline snapshot`, x.name);
    }
    if (!any) f('info', 'no-sbom', 'No CycloneDX SBOM in package');
  },
};

export const STAGES: StageDef[] = [integrity, signature, filetype, archive, cdr, markings, dirtyword, secrets, sbom];
