// Append-only, hash-chained chain-of-custody ledger (AU-9, AU-10).
// Each entry commits to the previous entry's hash, so editing, deleting or
// reordering any record breaks every hash after it.

import { canonical, sha256 } from './encoding.ts';

export interface LedgerEntry {
  seq: number;
  at: string;
  side: 'low' | 'high';
  event: string;
  transferId: string;
  data: Record<string, unknown>;
  prev: string;
  hash: string;
}

export const GENESIS = '0'.repeat(64);

export async function entryHash(e: Omit<LedgerEntry, 'hash'>): Promise<string> {
  return sha256(canonical(e));
}

export class Ledger {
  entries: LedgerEntry[];
  side: 'low' | 'high';
  constructor(side: 'low' | 'high', entries: LedgerEntry[] = []) {
    this.side = side;
    this.entries = entries;
  }

  get head(): string {
    return this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS;
  }

  async append(event: string, transferId: string, data: Record<string, unknown> = {}): Promise<LedgerEntry> {
    const base = { seq: this.entries.length, at: new Date().toISOString(), side: this.side, event, transferId, data, prev: this.head };
    const e: LedgerEntry = { ...base, hash: await entryHash(base) };
    this.entries.push(e);
    return e;
  }
}

export interface ChainCheck {
  ok: boolean;
  brokenAt?: number;
  reason?: string;
}

export async function verifyChain(entries: LedgerEntry[]): Promise<ChainCheck> {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const { hash, ...rest } = entries[i];
    if (rest.seq !== i) return { ok: false, brokenAt: i, reason: `sequence gap: expected ${i}, found ${rest.seq}` };
    if (rest.prev !== prev) return { ok: false, brokenAt: i, reason: 'prev-hash does not link to previous entry' };
    const h = await entryHash(rest);
    if (h !== hash) return { ok: false, brokenAt: i, reason: 'entry contents do not match recorded hash' };
    prev = hash;
  }
  return { ok: true };
}
