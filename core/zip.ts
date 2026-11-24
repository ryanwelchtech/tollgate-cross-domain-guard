// Minimal ZIP central-directory reader (for inspection) and writer (for test
// fixtures and the console's sample packages). No decompression of untrusted
// data is needed to make guard decisions: declared sizes, flags and entry names
// are enough to catch macros, encryption, nesting and decompression bombs.

import { crc32, te } from './encoding.ts';

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  encrypted: boolean;
}

export function readZipDirectory(b: Uint8Array): ZipEntry[] | null {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  // EOCD is at least 22 bytes; comment up to 65535.
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const count = dv.getUint16(eocd + 10, true);
  let off = dv.getUint32(eocd + 16, true);
  const out: ZipEntry[] = [];
  for (let n = 0; n < count; n++) {
    if (off + 46 > b.length || dv.getUint32(off, true) !== 0x02014b50) return null;
    const flags = dv.getUint16(off + 8, true);
    const method = dv.getUint16(off + 10, true);
    const csize = dv.getUint32(off + 20, true);
    const usize = dv.getUint32(off + 24, true);
    const nlen = dv.getUint16(off + 28, true);
    const xlen = dv.getUint16(off + 30, true);
    const clen = dv.getUint16(off + 32, true);
    const name = new TextDecoder().decode(b.subarray(off + 46, off + 46 + nlen));
    out.push({ name, method, compressedSize: csize, uncompressedSize: usize, encrypted: (flags & 1) === 1 });
    off += 46 + nlen + xlen + clen;
  }
  return out;
}

export interface ZipInput {
  name: string;
  data: Uint8Array;
  /** Pre-deflated payload (raw DEFLATE) and its original size, to build realistic bombs. */
  deflated?: { data: Uint8Array; size: number; crc: number };
  encrypted?: boolean;
}

export function writeZip(entries: ZipInput[]): Uint8Array {
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = te.encode(e.name);
    const method = e.deflated ? 8 : 0;
    const body = e.deflated ? e.deflated.data : e.data;
    const usize = e.deflated ? e.deflated.size : e.data.length;
    const crc = e.deflated ? e.deflated.crc : crc32(e.data);
    const flags = e.encrypted ? 1 : 0;

    const lh = new Uint8Array(30 + name.length);
    const l = new DataView(lh.buffer);
    l.setUint32(0, 0x04034b50, true); l.setUint16(4, 20, true); l.setUint16(6, flags, true);
    l.setUint16(8, method, true); l.setUint32(14, crc, true);
    l.setUint32(18, body.length, true); l.setUint32(22, usize, true); l.setUint16(26, name.length, true);
    lh.set(name, 30);
    locals.push(lh, body);

    const ch = new Uint8Array(46 + name.length);
    const c = new DataView(ch.buffer);
    c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true);
    c.setUint16(8, flags, true); c.setUint16(10, method, true); c.setUint32(16, crc, true);
    c.setUint32(20, body.length, true); c.setUint32(24, usize, true); c.setUint16(28, name.length, true);
    c.setUint32(42, offset, true);
    ch.set(name, 46);
    centrals.push(ch);
    offset += lh.length + body.length;
  }
  const cdSize = centrals.reduce((a, x) => a + x.length, 0);
  const eocd = new Uint8Array(22);
  const d = new DataView(eocd.buffer);
  d.setUint32(0, 0x06054b50, true); d.setUint16(8, entries.length, true); d.setUint16(10, entries.length, true);
  d.setUint32(12, cdSize, true); d.setUint32(16, offset, true);
  const parts = [...locals, ...centrals, eocd];
  const out = new Uint8Array(parts.reduce((a, x) => a + x.length, 0));
  let p = 0;
  for (const x of parts) { out.set(x, p); p += x.length; }
  return out;
}

export async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw');
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
