// End-to-end demo / integration run with real processes and real UDP:
//   1. start the high-side receiver and the low-side guard as child processes
//   2. submit every scenario through the HTTP API (signed by the lab publisher)
//   3. two reviewers approve whatever is releasable; release into the diode
//      with TG_SIM_LOSS of frames deliberately dropped
//   4. confirm what landed on the high side and verify both ledgers

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { b64encode, importPrivate } from '../core/encoding.ts';
import { SCENARIOS, buildScenario } from '../core/samples.ts';
import { verifyChain } from '../core/ledger.ts';
import { KEYS, ROOT, readKey } from './common.ts';

const data = mkdtempSync(join(tmpdir(), 'tollgate-'));
const loss = process.env.TG_SIM_LOSS ?? '0.10';
const port = 18080 + Math.floor(Math.random() * 1000);
const diodePort = 19999 + Math.floor(Math.random() * 1000);
const env = { ...process.env, TG_DATA: data, TG_PORT: String(port), TG_DIODE_PORT: String(diodePort), TG_SIM_LOSS: loss };

if (!existsSync(join(KEYS, 'guard.key'))) {
  await new Promise((ok) => spawn(process.execPath, [join(ROOT, 'services/tg.ts'), 'keygen'], { stdio: 'inherit' }).on('exit', ok));
}

const procs: ChildProcess[] = [];
function start(script: string) {
  const p = spawn(process.execPath, [join(ROOT, 'services', script)], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  p.stdout!.on('data', (d) => { if (process.env.TG_VERBOSE) process.stdout.write(`  [${script}] ${d}`); });
  procs.push(p);
}
const cleanup = () => procs.forEach((p) => p.kill());
process.on('exit', cleanup);

start('highside.ts');
start('lowside.ts');
const base = `http://127.0.0.1:${port}`;
for (let i = 0; i < 50; i++) {
  try { if ((await fetch(`${base}/healthz`)).ok) break; } catch { /* starting */ }
  await new Promise((r) => setTimeout(r, 100));
}

const api = async (path: string, user: string, body?: unknown) => {
  const r = await fetch(base + path, { method: body ? 'POST' : 'GET', headers: { 'x-tg-user': user, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json() };
};

const pubKey = await importPrivate(readKey('lab-release-eng.key'));
console.log(`\nTOLLGATE end-to-end  (diode loss simulated at ${(Number(loss) * 100).toFixed(0)}%)\n`);
const pad = (s: string, n: number) => s.padEnd(n);
const released: string[] = [];
let failures = 0;
for (const s of SCENARIOS) {
  const pkg = await buildScenario(s, 'lab-release-eng', pubKey);
  const sub = await api('/api/transfers', 'j.ramirez', { manifest: pkg.manifest, signature: pkg.signature, files: pkg.files.map((f) => ({ name: f.name, b64: b64encode(f.bytes) })) });
  const v = sub.json.verdict as string;
  const rules = (sub.json.stages as { findings: { severity: string; rule: string }[] }[]).flatMap((x) => x.findings).filter((f) => ['high', 'critical', 'medium'].includes(f.severity)).map((f) => f.rule);
  let outcome = '';
  if (v !== 'block') {
    const self = await api(`/api/transfers/${pkg.manifest.id}/review`, 'j.ramirez', { decision: 'approve' });
    await api(`/api/transfers/${pkg.manifest.id}/review`, 'rhr.chen', { decision: 'approve' });
    const twice = await api(`/api/transfers/${pkg.manifest.id}/review`, 'rhr.chen', { decision: 'approve' });
    await api(`/api/transfers/${pkg.manifest.id}/review`, 'rhr.alvarez', { decision: 'approve', note: v === 'warn' ? 'CDR changes reviewed' : undefined });
    const rel = await api(`/api/transfers/${pkg.manifest.id}/release`, 'rhr.alvarez', {});
    if (self.status !== 403 || twice.status !== 403) { failures++; outcome = 'TPI NOT ENFORCED'; }
    else if (rel.status === 200) { released.push(pkg.manifest.id); outcome = `released (${rel.json.transmission.frames} frames, ${rel.json.transmission.dropped} dropped)`; }
    else outcome = `release failed: ${rel.json.error}`;
  } else {
    const tryApprove = await api(`/api/transfers/${pkg.manifest.id}/review`, 'rhr.chen', { decision: 'approve' });
    outcome = tryApprove.status === 403 ? 'held; approval refused' : 'APPROVAL WRONGLY ALLOWED';
    if (tryApprove.status !== 403) failures++;
  }
  if (v !== s.expect) failures++;
  console.log(`${v === s.expect ? '✓' : '✗'} ${pad(v.toUpperCase(), 6)} ${pad(s.title, 40)} ${outcome}${rules.length ? `  [${[...new Set(rules)].join(', ')}]` : ''}`);
}

await new Promise((r) => setTimeout(r, 1500));
const inbox = join(data, 'highside', 'inbox');
const landed = existsSync(inbox) ? readdirSync(inbox) : [];
console.log(`\nHigh side inbox: ${landed.length}/${released.length} released transfers accepted`);
for (const id of landed) console.log(`  ${id}/  ${readdirSync(join(inbox, id)).join('  ')}`);
for (const side of ['lowside', 'highside']) {
  const entries = readFileSync(join(data, side, 'ledger.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const r = await verifyChain(entries);
  console.log(`${side} ledger: ${entries.length} entries, chain ${r.ok ? 'VERIFIED' : 'BROKEN'}  head=${entries.at(-1)?.hash.slice(0, 16)}…`);
  if (!r.ok) failures++;
}
const ok = failures === 0 && landed.length === released.length;
console.log(ok ? '\nPASS\n' : `\nFAIL (${failures} failures)\n`);
cleanup();
process.exit(ok ? 0 : 1);
