// One-way transfer protocol for a data diode.
//
// A diode has no return path: no ACKs, no retransmit requests, no TCP. The
// sender must therefore add enough redundancy up front that the receiver can
// rebuild the bundle on its own. TOLLGATE uses:
//   * fixed-size chunks with a 28-byte header,
//   * XOR parity per group of K data chunks (recovers any 1 loss per group),
//   * N-times repetition of every frame (survives bursty loss),
//   * a whole-bundle SHA-256 that the receiver checks before accepting.

import type { SignedRelease, TransferFile } from './types.ts';
import { b64decode, b64encode, sha256, td, te } from './encoding.ts';

export const MAGIC = 0x54474431; // "TGD1"
export const HEADER = 28;
export const CHUNK = 1024;

export interface DiodeConfig {
  group: number; // K data chunks per parity chunk
  repeat: number; // times every frame is transmitted
}

export const DEFAULT_DIODE: DiodeConfig = { group: 8, repeat: 2 };

export interface Bundle {
  release: SignedRelease;
  manifestId: string;
  files: TransferFile[];
}

export function encodeBundle(b: Bundle): Uint8Array {
  return te.encode(JSON.stringify({
    release: b.release, manifestId: b.manifestId,
    files: b.files.map((f) => ({ name: f.name, b64: b64encode(f.bytes) })),
  }));
}

export function decodeBundle(bytes: Uint8Array): Bundle {
  const o = JSON.parse(td.decode(bytes));
  return { release: o.release, manifestId: o.manifestId, files: o.files.map((f: { name: string; b64: string }) => ({ name: f.name, bytes: b64decode(f.b64) })) };
}

// Header layout (big endian):
//  0 u32 magic | 4 u32 session | 8 u32 index | 12 u32 dataChunks | 16 u32 totalBytes
// 20 u16 group | 22 u8 kind (0=data,1=parity) | 23 u8 rsvd | 24 u16 payloadLen | 26 u16 rsvd
export interface Frame {
  session: number;
  index: number; // data: chunk index; parity: group index
  dataChunks: number;
  totalBytes: number;
  group: number;
  kind: 0 | 1;
  payload: Uint8Array;
}

export function packFrame(fr: Frame): Uint8Array {
  const out = new Uint8Array(HEADER + fr.payload.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, MAGIC); dv.setUint32(4, fr.session); dv.setUint32(8, fr.index);
  dv.setUint32(12, fr.dataChunks); dv.setUint32(16, fr.totalBytes); dv.setUint16(20, fr.group);
  dv.setUint8(22, fr.kind); dv.setUint16(24, fr.payload.length);
  out.set(fr.payload, HEADER);
  return out;
}

export function unpackFrame(b: Uint8Array): Frame | null {
  if (b.length < HEADER) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (dv.getUint32(0) !== MAGIC) return null;
  const len = dv.getUint16(24);
  if (HEADER + len !== b.length) return null;
  const kind = dv.getUint8(22);
  if (kind > 1) return null;
  return {
    session: dv.getUint32(4), index: dv.getUint32(8), dataChunks: dv.getUint32(12),
    totalBytes: dv.getUint32(16), group: dv.getUint16(20), kind: kind as 0 | 1,
    payload: b.slice(HEADER),
  };
}

function xorInto(acc: Uint8Array, x: Uint8Array) {
  for (let i = 0; i < x.length; i++) acc[i] ^= x[i];
}

/** Produce the full transmit schedule (already repeated and interleaved). */
export function encodeFrames(data: Uint8Array, session: number, cfg: DiodeConfig = DEFAULT_DIODE): Uint8Array[] {
  const n = Math.max(1, Math.ceil(data.length / CHUNK));
  const frames: Uint8Array[] = [];
  for (let g = 0; g * cfg.group < n; g++) {
    const parity = new Uint8Array(CHUNK);
    for (let i = g * cfg.group; i < Math.min(n, (g + 1) * cfg.group); i++) {
      const payload = data.subarray(i * CHUNK, Math.min(data.length, (i + 1) * CHUNK));
      const padded = new Uint8Array(CHUNK); padded.set(payload);
      xorInto(parity, padded);
      frames.push(packFrame({ session, index: i, dataChunks: n, totalBytes: data.length, group: cfg.group, kind: 0, payload }));
    }
    frames.push(packFrame({ session, index: g, dataChunks: n, totalBytes: data.length, group: cfg.group, kind: 1, payload: parity }));
  }
  // Repeat passes back-to-back rather than adjacent duplicates, so a loss burst
  // doesn't wipe out both copies of the same frame.
  const out: Uint8Array[] = [];
  for (let r = 0; r < cfg.repeat; r++) out.push(...frames);
  return out;
}

export interface ReassemblyStats {
  received: number;
  duplicates: number;
  rejected: number;
  recovered: number;
  missing: number;
}

export class Reassembler {
  private chunks = new Map<number, Uint8Array>();
  private parity = new Map<number, Uint8Array>();
  dataChunks = 0;
  totalBytes = 0;
  group = 0;
  stats: ReassemblyStats = { received: 0, duplicates: 0, rejected: 0, recovered: 0, missing: 0 };

  session: number;
  constructor(session: number) {
    this.session = session;
  }

  push(raw: Uint8Array): void {
    const fr = unpackFrame(raw);
    if (!fr || fr.session !== this.session) { this.stats.rejected++; return; }
    if (this.dataChunks && (fr.dataChunks !== this.dataChunks || fr.totalBytes !== this.totalBytes)) { this.stats.rejected++; return; }
    this.dataChunks = fr.dataChunks; this.totalBytes = fr.totalBytes; this.group = fr.group;
    const map = fr.kind === 0 ? this.chunks : this.parity;
    if (map.has(fr.index)) { this.stats.duplicates++; return; }
    map.set(fr.index, fr.payload);
    this.stats.received++;
  }

  /** Attempt FEC recovery and return the payload, or null if unrecoverable. */
  finish(): Uint8Array | null {
    if (!this.dataChunks) return null;
    const n = this.dataChunks;
    const sizeOf = (i: number) => (i === n - 1 ? this.totalBytes - i * CHUNK : CHUNK);
    for (let g = 0; g * this.group < n; g++) {
      const idx: number[] = [];
      for (let i = g * this.group; i < Math.min(n, (g + 1) * this.group); i++) idx.push(i);
      const miss = idx.filter((i) => !this.chunks.has(i));
      if (miss.length === 1 && this.parity.has(g)) {
        const acc = new Uint8Array(CHUNK); acc.set(this.parity.get(g)!);
        for (const i of idx) if (i !== miss[0]) { const p = new Uint8Array(CHUNK); p.set(this.chunks.get(i)!); xorInto(acc, p); }
        this.chunks.set(miss[0], acc.slice(0, sizeOf(miss[0])));
        this.stats.recovered++;
      }
    }
    let missing = 0;
    for (let i = 0; i < n; i++) if (!this.chunks.has(i)) missing++;
    this.stats.missing = missing;
    if (missing) return null;
    const out = new Uint8Array(this.totalBytes);
    for (let i = 0; i < n; i++) out.set(this.chunks.get(i)!, i * CHUNK);
    return out;
  }
}

export async function bundleChecksum(b: Uint8Array): Promise<string> {
  return sha256(b);
}
