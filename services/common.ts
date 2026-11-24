import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Policy } from '../core/types.ts';
import type { LedgerEntry } from '../core/ledger.ts';
import { Ledger, verifyChain } from '../core/ledger.ts';

export const ROOT = resolve(import.meta.dirname, '..');
export const KEYS = process.env.TG_KEYS ?? join(ROOT, 'keys');
export const DATA = process.env.TG_DATA ?? join(ROOT, 'data');

export function log(side: string, msg: string, extra: Record<string, unknown> = {}) {
  // Structured JSON logs (AU-3 content of audit records) for SIEM ingestion.
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), side, msg, ...extra }) + '\n');
}

export function loadPolicy(): Policy {
  const p: Policy = JSON.parse(readFileSync(process.env.TG_POLICY ?? join(ROOT, 'policy/policy.json'), 'utf8'));
  const trustDir = join(KEYS, 'trust');
  if (existsSync(trustDir)) {
    for (const f of readdirSync(trustDir)) {
      if (f.endsWith('.pub')) p.trustStore[f.slice(0, -4)] = readFileSync(join(trustDir, f), 'utf8').trim();
    }
  }
  return p;
}

export function readKey(name: string): string {
  const p = join(KEYS, name);
  if (!existsSync(p)) throw new Error(`missing key ${p}; run "npm run tg -- keygen" first`);
  return readFileSync(p, 'utf8').trim();
}

/** Ledger persisted as JSON Lines; verified on every start-up. */
export async function openLedger(side: 'low' | 'high'): Promise<Ledger & { persist(e: LedgerEntry): void }> {
  const dir = join(DATA, side === 'low' ? 'lowside' : 'highside');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'ledger.jsonl');
  const entries: LedgerEntry[] = existsSync(file)
    ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  const check = await verifyChain(entries);
  if (!check.ok) {
    log(side, 'LEDGER INTEGRITY FAILURE: refusing to start', { brokenAt: check.brokenAt, reason: check.reason });
    process.exit(2);
  }
  const l = new Ledger(side, entries) as Ledger & { persist(e: LedgerEntry): void };
  const append = l.append.bind(l);
  l.append = async (event, id, data) => {
    const e = await append(event, id, data);
    appendFileSync(file, JSON.stringify(e) + '\n');
    return e;
  };
  l.persist = () => {};
  return l;
}
