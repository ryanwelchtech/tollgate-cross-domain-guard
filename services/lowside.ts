// LOW SIDE: transfer intake, inspection, two-person review, guard signing and
// one-way transmission into the diode.
//
// In production the X-TG-User identity comes from the mTLS client certificate
// (CAC/PIV) terminated at the ingress; here it is a header so the lab runs
// with no PKI.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createSocket } from 'node:dgram';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Approval, InspectionResult, TransferPackage } from '../core/types.ts';
import { b64decode, importPrivate } from '../core/encoding.ts';
import { inspect } from '../core/pipeline.ts';
import { approvalsSatisfied, canApprove, signRelease } from '../core/release.ts';
import { DEFAULT_DIODE, encodeBundle, encodeFrames } from '../core/diode.ts';
import { DATA, loadPolicy, log, openLedger, readKey } from './common.ts';

const PORT = Number(process.env.TG_PORT ?? 8080);
const DIODE_HOST = process.env.TG_DIODE_HOST ?? '127.0.0.1';
const DIODE_PORT = Number(process.env.TG_DIODE_PORT ?? 9999);
const GUARD_ID = process.env.TG_GUARD_ID ?? 'tollgate-01';
/** Lab-only: drop this fraction of frames on purpose to exercise FEC. */
const SIM_LOSS = Number(process.env.TG_SIM_LOSS ?? 0);
const REPEAT = Number(process.env.TG_REPEAT ?? DEFAULT_DIODE.repeat);

const policy = loadPolicy();
const guardKey = await importPrivate(readKey('guard.key'));
const ledger = await openLedger('low');
const storeDir = join(DATA, 'lowside', 'transfers');
mkdirSync(storeDir, { recursive: true });

interface Record_ {
  pkg: TransferPackage;
  inspection: InspectionResult;
  approvals: Approval[];
  status: 'inspected' | 'blocked' | 'approved' | 'rejected' | 'released';
}
const transfers = new Map<string, Record_>();

function summary(r: Record_) {
  return {
    id: r.pkg.manifest.id, requester: r.pkg.manifest.requester, status: r.status,
    verdict: r.inspection.verdict, files: r.pkg.manifest.files.length,
    approvals: r.approvals, bundleDigest: r.inspection.bundleDigest,
    stages: r.inspection.stages.map((s) => ({ stage: s.stage, verdict: s.verdict, findings: s.findings })),
  };
}

function persist(r: Record_) {
  writeFileSync(join(storeDir, `${r.pkg.manifest.id}.json`), JSON.stringify(summary(r), null, 2));
}

async function body(req: IncomingMessage, limit = policy.maxPackageBytes * 1.4): Promise<unknown> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > limit) throw Object.assign(new Error('payload too large'), { status: 413 });
    chunks.push(c as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function send(res: ServerResponse, status: number, obj: unknown) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(obj));
}

async function transmit(bundle: Uint8Array): Promise<{ session: number; frames: number; dropped: number }> {
  const session = (Math.random() * 0xffffffff) >>> 0;
  const frames = encodeFrames(bundle, session, { ...DEFAULT_DIODE, repeat: REPEAT });
  const sock = createSocket('udp4');
  let dropped = 0;
  for (let i = 0; i < frames.length; i++) {
    if (SIM_LOSS && Math.random() < SIM_LOSS) { dropped++; continue; }
    await new Promise<void>((ok, err) => sock.send(frames[i], DIODE_PORT, DIODE_HOST, (e) => (e ? err(e) : ok())));
    // Pace transmission: a diode link has fixed bandwidth and no flow control.
    if (i % 32 === 31) await new Promise((r) => setTimeout(r, 2));
  }
  sock.close();
  return { session, frames: frames.length, dropped };
}

const routes: [string, RegExp, (req: IncomingMessage, res: ServerResponse, m: RegExpMatchArray, user: string) => Promise<void>][] = [
  ['GET', /^\/healthz$/, async (_q, res) => send(res, 200, { ok: true, side: 'low', ledgerHead: ledger.head, entries: ledger.entries.length })],

  ['POST', /^\/api\/transfers$/, async (req, res, _m, user) => {
    const b = (await body(req)) as { manifest: TransferPackage['manifest']; files: { name: string; b64: string }[]; signature?: string };
    if (!b?.manifest?.id || !Array.isArray(b.files)) return send(res, 400, { error: 'manifest and files required' });
    if (transfers.has(b.manifest.id)) return send(res, 409, { error: 'duplicate transfer id (replay?)' });
    if (b.manifest.requester !== user) return send(res, 403, { error: 'manifest requester must match authenticated user' });
    const pkg: TransferPackage = { manifest: b.manifest, signature: b.signature, files: b.files.map((f) => ({ name: f.name, bytes: b64decode(f.b64) })) };
    await ledger.append('submitted', pkg.manifest.id, { requester: user, files: pkg.files.length });
    const inspection = await inspect(pkg, policy);
    const r: Record_ = { pkg, inspection, approvals: [], status: inspection.verdict === 'block' ? 'blocked' : 'inspected' };
    transfers.set(pkg.manifest.id, r);
    const blocking = inspection.stages.flatMap((s) => s.findings).filter((f) => f.severity === 'critical' || f.severity === 'high');
    await ledger.append('inspected', pkg.manifest.id, { verdict: inspection.verdict, bundleDigest: inspection.bundleDigest, blocking: blocking.map((f) => f.rule) });
    persist(r);
    log('low', 'inspected', { id: pkg.manifest.id, verdict: inspection.verdict, blocking: blocking.map((f) => `${f.stage}/${f.rule}`) });
    send(res, 201, summary(r));
  }],

  ['GET', /^\/api\/transfers$/, async (_q, res) => send(res, 200, [...transfers.values()].map(summary))],

  ['GET', /^\/api\/transfers\/([\w-]+)$/, async (_q, res, m) => {
    const r = transfers.get(m[1]);
    return r ? send(res, 200, summary(r)) : send(res, 404, { error: 'not found' });
  }],

  ['POST', /^\/api\/transfers\/([\w-]+)\/review$/, async (req, res, m, user) => {
    const r = transfers.get(m[1]);
    if (!r) return send(res, 404, { error: 'not found' });
    const b = (await body(req, 8192)) as { decision: 'approve' | 'reject'; note?: string };
    const check = canApprove(policy, r.pkg.manifest, r.inspection, r.approvals, user);
    if (!check.ok) {
      await ledger.append('review-denied', r.pkg.manifest.id, { user, reason: check.reason });
      return send(res, 403, { error: check.reason });
    }
    const a: Approval = { reviewer: user, role: policy.approvals.reviewers[user], decision: b.decision === 'reject' ? 'reject' : 'approve', at: new Date().toISOString(), note: b.note?.slice(0, 500) };
    r.approvals.push(a);
    if (a.decision === 'reject') r.status = 'rejected';
    else if (approvalsSatisfied(policy, r.approvals)) r.status = 'approved';
    await ledger.append('reviewed', r.pkg.manifest.id, { reviewer: user, decision: a.decision });
    persist(r);
    send(res, 200, summary(r));
  }],

  ['POST', /^\/api\/transfers\/([\w-]+)\/release$/, async (_req, res, m, user) => {
    const r = transfers.get(m[1]);
    if (!r) return send(res, 404, { error: 'not found' });
    if (r.status !== 'approved') return send(res, 409, { error: `status is ${r.status}; two-person approval required before release` });
    const rel = await signRelease(GUARD_ID, guardKey, r.inspection, r.approvals);
    const bundle = encodeBundle({ release: rel, manifestId: r.pkg.manifest.id, files: r.inspection.released });
    const tx = await transmit(bundle);
    r.status = 'released';
    await ledger.append('released', r.pkg.manifest.id, { by: user, bytes: bundle.length, ...tx, bundleDigest: r.inspection.bundleDigest });
    persist(r);
    log('low', 'released into diode', { id: r.pkg.manifest.id, bytes: bundle.length, ...tx });
    send(res, 200, { ...summary(r), transmission: tx });
  }],

  ['GET', /^\/api\/ledger$/, async (_q, res) => send(res, 200, ledger.entries)],
];

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');
  const user = String(req.headers['x-tg-user'] ?? '');
  for (const [method, re, fn] of routes) {
    const m = url.pathname.match(re);
    if (m && req.method === method) {
      if (url.pathname !== '/healthz' && !/^[a-z][\w.-]{1,40}$/.test(user)) return send(res, 401, { error: 'X-TG-User identity required' });
      try { await fn(req, res, m, user); } catch (e) {
        const err = e as Error & { status?: number };
        log('low', 'request error', { path: url.pathname, error: err.message });
        send(res, err.status ?? 400, { error: err.message });
      }
      return;
    }
  }
  send(res, 404, { error: 'no route' });
});

server.listen(PORT, () => log('low', 'listening', { port: PORT, diode: `${DIODE_HOST}:${DIODE_PORT}`, simLoss: SIM_LOSS, publishers: Object.keys(policy.trustStore) }));
