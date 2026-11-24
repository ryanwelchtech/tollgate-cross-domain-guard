// Realistic test scenarios, built from bytes at runtime. Used by the test
// suite, the CLI demo, and the browser console. All codewords and operation
// names are fictitious.

import type { Manifest, TransferFile, TransferPackage } from './types.ts';
import { canonical, crc32, sha256, sign, te } from './encoding.ts';
import { deflateRaw, writeZip } from './zip.ts';

export interface Scenario {
  id: string;
  title: string;
  blurb: string;
  expect: 'pass' | 'warn' | 'block';
  build(): Promise<{ files: TransferFile[]; tamper?: 'after-sign' | 'wrong-key' | 'unsigned' }>;
}

const banner = (level: string, body: string) => `${level}\n\n${body.trim()}\n\n${level}\n`;
const txt = (name: string, s: string): TransferFile => ({ name, bytes: te.encode(s) });

function png(extra?: { text?: string; trailing?: Uint8Array }): Uint8Array {
  // 1x1 RGBA PNG, valid IDAT; optional tEXt chunk and trailing payload.
  const chunk = (type: string, data: Uint8Array) => {
    const out = new Uint8Array(12 + data.length);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, data.length);
    const td = te.encode(type);
    out.set(td, 4); out.set(data, 8);
    const crcIn = new Uint8Array(4 + data.length); crcIn.set(td); crcIn.set(data, 4);
    dv.setUint32(8 + data.length, crc32(crcIn));
    return out;
  };
  const ihdr = new Uint8Array([0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
  const idat = new Uint8Array([0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0xa5, 0xf7, 0xab, 0x4a]);
  const parts: Uint8Array[] = [new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr)];
  if (extra?.text) parts.push(chunk('tEXt', te.encode('Comment\0' + extra.text)));
  parts.push(chunk('IDAT', idat), chunk('IEND', new Uint8Array()));
  if (extra?.trailing) parts.push(extra.trailing);
  const out = new Uint8Array(parts.reduce((a, x) => a + x.length, 0));
  let p = 0;
  for (const x of parts) { out.set(x, p); p += x.length; }
  return out;
}

function sbom(components: { name: string; version: string; license?: string }[]): string {
  return JSON.stringify({
    bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: { component: { type: 'container', name: 'registry.lab/ops/telemetry-api', version: '4.2.0' } },
    components: components.map((c) => ({
      type: 'library', name: c.name, version: c.version, purl: `pkg:generic/${c.name}@${c.version}`,
      licenses: c.license ? [{ license: { id: c.license } }] : undefined,
    })),
  }, null, 2);
}

const CLEAN_SBOM = [
  { name: 'log4j-core', version: '2.24.1', license: 'Apache-2.0' },
  { name: 'spring-beans', version: '6.1.14', license: 'Apache-2.0' },
  { name: 'openssl', version: '3.3.2', license: 'Apache-2.0' },
  { name: 'zlib', version: '1.3.1', license: 'Zlib' },
];

export const SCENARIOS: Scenario[] = [
  {
    id: 'clean-update', title: 'Signed STIG & AV signature update', expect: 'pass',
    blurb: 'Routine low-to-high import: marked release notes, AV signature feed, CycloneDX SBOM, and a diagram. Every stage should pass.',
    async build() {
      return { files: [
        txt('RELEASE-NOTES.txt', banner('UNCLASSIFIED', 'Quarterly RHEL 9 STIG content update V2R3.\n(U) Adds 14 rules, retires 3. No action required for enclave operators beyond scheduled rescan.')),
        txt('av-signatures.json', JSON.stringify({ feed: 'clamav-main', version: 27461, generated: '2026-11-20T04:00:00Z', count: 8_734_221 })),
        txt('telemetry-api.cdx.json', sbom(CLEAN_SBOM)),
        { name: 'topology.png', bytes: png() },
      ] };
    },
  },
  {
    id: 'macro-docx', title: 'Macro-enabled Word document', expect: 'block',
    blurb: 'A .docx whose OOXML container carries word/vbaProject.bin. Macros are the #1 initial-access vector into isolated networks.',
    async build() {
      const docx = writeZip([
        { name: '[Content_Types].xml', data: te.encode('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>') },
        { name: 'word/document.xml', data: te.encode('<w:document><w:body><w:p><w:r><w:t>UNCLASSIFIED Quarterly brief</w:t></w:r></w:p></w:body></w:document>') },
        { name: 'word/vbaProject.bin', data: new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...te.encode('AutoOpen Shell powershell -enc ...')]) },
      ]);
      return { files: [{ name: 'quarterly-brief.docx', bytes: docx }, txt('README.txt', banner('UNCLASSIFIED', 'Brief for the enclave staff meeting.'))] };
    },
  },
  {
    id: 'masquerade', title: 'Executable disguised as text', expect: 'block',
    blurb: 'notes.txt is actually an ELF binary. The guard identifies content by magic bytes, never by filename.',
    async build() {
      const elf = new Uint8Array(256);
      elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
      return { files: [{ name: 'notes.txt', bytes: elf }, txt('cover.txt', banner('UNCLASSIFIED', 'Field notes attached.'))] };
    },
  },
  {
    id: 'spillage', title: 'SECRET memo on the low side', expect: 'block',
    blurb: 'A memo marked SECRET//NOFORN is sitting on a network accredited only to CUI. That is a spill: block, quarantine, call the ISSM.',
    async build() {
      return { files: [txt('ops-memo.txt', banner('SECRET//NOFORN', '(S//NF) PROJECT KESTREL phase two moves to OP-2291-KX on the 14th.\n(U) Logistics details to follow.'))] };
    },
  },
  {
    id: 'dws-evasion', title: 'Dirty word hidden with zero-width chars', expect: 'block',
    blurb: 'Someone split a codeword with U+200B so a naive regex misses it. CDR strips the zero-width characters before the dirty-word search runs, so it still hits.',
    async build() {
      return { files: [txt('status.md', banner('UNCLASSIFIED', '(U) Weekly status.\n(U) Coordination with BLUE​ HAR​BOR team continues.'))] };
    },
  },
  {
    id: 'trojan-source', title: 'Trojan Source config file', expect: 'warn',
    blurb: 'A YAML config with Unicode bidi overrides (CVE-2021-42574). CDR removes them and the sanitized file is released with a WARN for the reviewers.',
    async build() {
      return { files: [
        txt('pipeline.yaml', 'stages:\n  - name: verify\n    run: "check --strict ‮⁦ && skip⁩⁦"\n'),
        txt('README.txt', banner('UNCLASSIFIED', 'Updated CI config for the enclave runner.')),
      ] };
    },
  },
  {
    id: 'log4shell-sbom', title: 'Container SBOM with Log4Shell', expect: 'block',
    blurb: 'A container image SBOM lists log4j-core 2.14.1 (CVE-2021-44228, CISA KEV). The offline vulnerability snapshot catches it without internet access.',
    async build() {
      return { files: [txt('telemetry-api.cdx.json', sbom([{ name: 'log4j-core', version: '2.14.1', license: 'Apache-2.0' }, { name: 'xz-utils', version: '5.6.1' }, { name: 'zlib', version: '1.3.1' }]))] };
    },
  },
  {
    id: 'leaked-secret', title: 'Credentials in a deployment file', expect: 'block',
    blurb: 'An env file with an AWS access key and a Vault token. Credential spills across a boundary are reportable incidents.',
    async build() {
      return { files: [txt('deploy.yaml', 'region: us-gov-west-1\naws_access_key_id: AKIAIOSFODNN7EXAMPLE\nvault_token: hvs.CAESIJ7fakefakefakefakefakefake1234\n')] };
    },
  },
  {
    id: 'svg-script', title: 'SVG diagram with embedded script', expect: 'warn',
    blurb: 'An architecture diagram with an onload handler and <script>. CDR rebuilds it without active content.',
    async build() {
      const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40" onload="fetch(\'//x\')"><script>alert(1)</script><a href="javascript:void(0)"><rect width="120" height="40" fill="#234"/></a></svg>';
      return { files: [txt('arch.svg', svg), txt('README.txt', banner('UNCLASSIFIED', 'Updated architecture diagram.'))] };
    },
  },
  {
    id: 'polyglot-png', title: 'PNG with appended ZIP (polyglot)', expect: 'block',
    blurb: 'A valid image with a ZIP payload glued after IEND, a classic way to smuggle data past type checks.',
    async build() {
      const payload = writeZip([{ name: 'payload.ps1', data: te.encode('Invoke-Expression ...') }]);
      return { files: [{ name: 'map.png', bytes: png({ trailing: payload, text: 'exif-gps 38.89,-77.03' }) }] };
    },
  },
  {
    id: 'zip-bomb', title: 'Decompression bomb', expect: 'block',
    blurb: 'A small ZIP that inflates thousands of times over. Caught from the central directory without decompressing anything.',
    async build() {
      const raw = new Uint8Array(8 * 1024 * 1024);
      const d = await deflateRaw(raw);
      const z = writeZip([{ name: 'logs.csv', data: raw, deflated: { data: d, size: raw.length, crc: crc32(raw) } }]);
      return { files: [{ name: 'logs.zip', bytes: z }] };
    },
  },
  {
    id: 'tampered', title: 'Package altered after signing', expect: 'block',
    blurb: 'The publisher signed the manifest, then someone swapped a file in transit. The signature still verifies, but the file no longer matches the signed SHA-256, so integrity blocks it.',
    async build() {
      return { tamper: 'after-sign', files: [txt('firmware-notes.txt', banner('UNCLASSIFIED', 'Radio firmware 7.4.2 release notes.')), txt('checksums.txt', banner('UNCLASSIFIED', 'sha256 9f2c…  radio-7.4.2.bin'))] };
    },
  },
];

let seq = 0;
export async function makeManifest(files: TransferFile[], requester: string, publisher: string | undefined, justification: string): Promise<Manifest> {
  const entries = [];
  for (const f of files) entries.push({ name: f.name, size: f.bytes.length, sha256: await sha256(f.bytes) });
  const stamp = new Date().toISOString();
  return {
    id: `TG-${stamp.slice(0, 10).replace(/-/g, '')}-${String(++seq).padStart(4, '0')}-${Math.random().toString(16).slice(2, 6)}`,
    requester, direction: 'low-to-high', sourceNetwork: 'NIPR-LAB', destination: 'MISSION-ENCLAVE',
    justification, createdAt: stamp, publisher, files: entries,
  };
}

/** Build and sign a scenario package with the given publisher key. */
export async function buildScenario(s: Scenario, publisherId: string, publisherKey: CryptoKey, otherKey?: CryptoKey): Promise<TransferPackage> {
  const { files, tamper } = await s.build();
  const manifest = await makeManifest(files, 'j.ramirez', tamper === 'unsigned' ? undefined : publisherId, s.title);
  let signature: string | undefined;
  if (tamper !== 'unsigned') signature = await sign(tamper === 'wrong-key' && otherKey ? otherKey : publisherKey, canonical(manifest));
  if (tamper === 'after-sign') {
    files[0] = txt(files[0].name, banner('UNCLASSIFIED', 'Radio firmware 7.4.2 release notes.\nAlso install the attached hotfix from the vendor portal.'));
  }
  return { manifest, files, signature };
}
