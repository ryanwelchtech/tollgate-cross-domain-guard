// True file-type identification from content (magic bytes), independent of the
// claimed extension. Guards never trust a filename.

export type Kind =
  | 'pe' | 'elf' | 'macho' | 'script' | 'pdf' | 'zip' | 'ooxml' | 'gzip'
  | 'png' | 'jpeg' | 'gif' | 'svg' | 'html' | 'json' | 'xml' | 'text' | 'binary' | 'empty';

export interface TypeInfo {
  kind: Kind;
  executable: boolean;
  textual: boolean;
  label: string;
}

const LABELS: Record<Kind, string> = {
  pe: 'Windows PE executable', elf: 'ELF executable', macho: 'Mach-O executable',
  script: 'Script with interpreter (#!)', pdf: 'PDF document', zip: 'ZIP archive',
  ooxml: 'Office Open XML document', gzip: 'gzip stream', png: 'PNG image',
  jpeg: 'JPEG image', gif: 'GIF image', svg: 'SVG image', html: 'HTML document',
  json: 'JSON data', xml: 'XML document', text: 'Plain text', binary: 'Unidentified binary', empty: 'Empty file',
};

function startsWith(b: Uint8Array, sig: number[], at = 0): boolean {
  if (b.length < at + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig[i]) return false;
  return true;
}

/** UTF-8 validity + control-character ratio heuristic. */
export function looksTextual(b: Uint8Array): boolean {
  const n = Math.min(b.length, 8192);
  let ctrl = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32)) ctrl++;
  }
  if (ctrl / Math.max(1, n) > 0.02) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, n));
    return true;
  } catch {
    // a multibyte char could have been cut at the sample boundary
    return n < b.length;
  }
}

export function identify(b: Uint8Array, zipNames?: string[]): TypeInfo {
  const k = detect(b, zipNames);
  return {
    kind: k,
    executable: k === 'pe' || k === 'elf' || k === 'macho' || k === 'script',
    textual: ['text', 'json', 'xml', 'svg', 'html', 'script'].includes(k),
    label: LABELS[k],
  };
}

function detect(b: Uint8Array, zipNames?: string[]): Kind {
  if (b.length === 0) return 'empty';
  if (startsWith(b, [0x4d, 0x5a])) return 'pe';
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (startsWith(b, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xce, 0xfa, 0xed, 0xfe]) ||
      startsWith(b, [0xfe, 0xed, 0xfa, 0xcf]) || startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) return 'macho';
  if (startsWith(b, [0x25, 0x50, 0x44, 0x46])) return 'pdf';
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) {
    if (zipNames && zipNames.includes('[Content_Types].xml')) return 'ooxml';
    return 'zip';
  }
  if (startsWith(b, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return 'png';
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (startsWith(b, [0x47, 0x49, 0x46, 0x38])) return 'gif';
  if (startsWith(b, [0x23, 0x21])) return 'script';
  if (!looksTextual(b)) return 'binary';
  const head = new TextDecoder().decode(b.subarray(0, 2048)).replace(/^﻿/, '').trimStart().toLowerCase();
  if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) return 'svg';
  if (head.startsWith('<!doctype html') || head.startsWith('<html')) return 'html';
  if (head.startsWith('<?xml') || head.startsWith('<')) return 'xml';
  if (head.startsWith('{') || head.startsWith('[')) {
    try { JSON.parse(new TextDecoder().decode(b)); return 'json'; } catch { /* fallthrough */ }
  }
  return 'text';
}

/** Which detected kinds are acceptable for a claimed extension. */
export const EXTENSION_KINDS: Record<string, Kind[]> = {
  '.txt': ['text', 'empty'], '.md': ['text', 'empty'], '.csv': ['text', 'empty'], '.log': ['text', 'empty'],
  '.yaml': ['text'], '.yml': ['text'], '.conf': ['text'], '.ini': ['text'],
  '.json': ['json'], '.cdx.json': ['json'], '.xml': ['xml'], '.svg': ['svg'],
  '.pdf': ['pdf'], '.png': ['png'], '.jpg': ['jpeg'], '.jpeg': ['jpeg'], '.gif': ['gif'],
  '.zip': ['zip'], '.docx': ['ooxml'], '.xlsx': ['ooxml'], '.pptx': ['ooxml'],
  '.tar.gz': ['gzip'], '.gz': ['gzip'],
};
