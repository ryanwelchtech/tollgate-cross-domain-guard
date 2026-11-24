// HIGH SIDE: receive-only diode endpoint.
//
// This process binds a UDP socket and only ever reads from it. It holds no
// private key (only the guard's public key), opens no outbound connections and
// never calls send(). On Kubernetes, NetworkPolicy denies all egress from this
// pod (deploy/k8s/highside.yaml); in production a hardware diode enforces the
// same thing physically.

import { createSocket } from 'node:dgram';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeBundle, Reassembler } from '../core/diode.ts';
import { bundleDigest } from '../core/pipeline.ts';
import { verifyRelease } from '../core/release.ts';
import { DATA, loadPolicy, log, openLedger, readKey } from './common.ts';

const PORT = Number(process.env.TG_DIODE_PORT ?? 9999);
const IDLE_MS = Number(process.env.TG_IDLE_MS ?? 750);
const MAX_SESSIONS = 32;

const policy = loadPolicy();
const guardPub = readKey('guard.pub');
const ledger = await openLedger('high');
const inbox = join(DATA, 'highside', 'inbox');
const quarantine = join(DATA, 'highside', 'quarantine');
mkdirSync(inbox, { recursive: true });
mkdirSync(quarantine, { recursive: true });

const sessions = new Map<number, { rx: Reassembler; timer: ReturnType<typeof setTimeout> }>();

async function complete(session: number) {
  const s = sessions.get(session);
  sessions.delete(session);
  if (!s) return;
  const payload = s.rx.finish();
  if (!payload) {
    log('high', 'unrecoverable session', { session, ...s.rx.stats });
    await ledger.append('rx-failed', `session-${session}`, { ...s.rx.stats });
    return;
  }
  let id = `session-${session}`;
  try {
    const b = decodeBundle(payload);
    id = b.manifestId;
    const problems: string[] = [];
    const rel = await verifyRelease(b.release, guardPub, policy.approvals.required);
    if (!rel.ok) problems.push(rel.reason);
    if (b.release.token.transferId !== b.manifestId) problems.push('token/manifest id mismatch');
    const digest = await bundleDigest(b.manifestId, b.files);
    if (digest !== b.release.token.bundleDigest) problems.push('bundle digest does not match guard-signed token');
    if (ledger.entries.some((e) => e.event === 'accepted' && e.transferId === b.manifestId)) problems.push('replay: transfer already accepted');

    const dest = join(problems.length ? quarantine : inbox, b.manifestId.replace(/[^\w-]/g, '_'));
    mkdirSync(dest, { recursive: true });
    for (const f of b.files) {
      const safe = f.name.replace(/[^\w.-]/g, '_');
      writeFileSync(join(dest, safe), f.bytes, { mode: 0o440 });
    }
    writeFileSync(join(dest, 'release-token.json'), JSON.stringify(b.release, null, 2));
    if (problems.length) {
      await ledger.append('quarantined', id, { problems, ...s.rx.stats });
      log('high', 'QUARANTINED', { id, problems });
    } else {
      await ledger.append('accepted', id, { files: b.files.length, digest, approvals: b.release.token.approvals.map((a) => a.reviewer), ...s.rx.stats });
      log('high', 'accepted', { id, files: b.files.length, fecRecovered: s.rx.stats.recovered, duplicates: s.rx.stats.duplicates });
    }
  } catch (e) {
    await ledger.append('rx-failed', id, { error: (e as Error).message });
    log('high', 'decode failure', { id, error: (e as Error).message });
  }
}

const sock = createSocket('udp4');
sock.on('message', (msg) => {
  if (msg.length < 28) return;
  const session = msg.readUInt32BE(4);
  let s = sessions.get(session);
  if (!s) {
    if (sessions.size >= MAX_SESSIONS) return; // bounded memory under flood
    s = { rx: new Reassembler(session), timer: setTimeout(() => {}, 0) };
    sessions.set(session, s);
  }
  s.rx.push(new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));
  clearTimeout(s.timer);
  s.timer = setTimeout(() => void complete(session), IDLE_MS);
});
sock.bind(PORT, process.env.TG_BIND ?? '127.0.0.1', () => log('high', 'diode receiver listening (receive-only)', { port: PORT, ledgerHead: ledger.head }));
