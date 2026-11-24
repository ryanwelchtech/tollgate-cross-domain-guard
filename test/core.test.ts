import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { Policy } from '../core/types.ts';
import { generateKeyPair } from '../core/encoding.ts';
import { inspect } from '../core/pipeline.ts';
import { SCENARIOS, buildScenario, makeManifest } from '../core/samples.ts';
import { Ledger, verifyChain } from '../core/ledger.ts';
import { encodeFrames, Reassembler } from '../core/diode.ts';
import { canApprove, approvalsSatisfied, signRelease, verifyRelease } from '../core/release.ts';
import { versionMatches } from '../core/vulns.ts';
import { te } from '../core/encoding.ts';

const basePolicy: Policy = JSON.parse(readFileSync(new URL('../policy/policy.json', import.meta.url), 'utf8'));

async function setup() {
  const pub = await generateKeyPair();
  const other = await generateKeyPair();
  const policy: Policy = { ...basePolicy, trustStore: { 'lab-release-eng': pub.publicRaw } };
  return { pub, other, policy };
}

for (const s of SCENARIOS) {
  test(`scenario ${s.id} -> ${s.expect}`, async () => {
    const { pub, other, policy } = await setup();
    const pkg = await buildScenario(s, 'lab-release-eng', pub.privateKey, other.privateKey);
    const r = await inspect(pkg, policy);
    const blocking = r.stages.flatMap((x) => x.findings).filter((f) => f.severity === 'high' || f.severity === 'critical');
    assert.equal(r.verdict, s.expect, `${s.id}: ${JSON.stringify(blocking.map((f) => f.rule))}`);
  });
}

test('specific detections fire with the expected rules', async () => {
  const { pub, policy } = await setup();
  const rules = async (id: string) => {
    const pkg = await buildScenario(SCENARIOS.find((s) => s.id === id)!, 'lab-release-eng', pub.privateKey);
    return (await inspect(pkg, policy)).stages.flatMap((s) => s.findings.map((f) => f.rule));
  };
  assert.ok((await rules('macro-docx')).includes('macro'));
  assert.ok((await rules('masquerade')).includes('executable'));
  assert.ok((await rules('spillage')).includes('spillage'));
  const dws = await rules('dws-evasion');
  assert.ok(dws.includes('zero-width') && dws.includes('dirty-word'), 'CDR must run before DWS');
  assert.ok((await rules('log4shell-sbom')).includes('kev'));
  assert.ok((await rules('leaked-secret')).includes('aws-access-key'));
  assert.ok((await rules('polyglot-png')).includes('polyglot'));
  assert.ok((await rules('zip-bomb')).includes('decompression-bomb'));
  assert.ok((await rules('tampered')).includes('hash-mismatch'));
});

test('signature: wrong key and untrusted publisher are blocked', async () => {
  const { pub, other, policy } = await setup();
  const clean = SCENARIOS.find((s) => s.id === 'clean-update')!;
  const wrong = await buildScenario({ ...clean, build: async () => ({ ...(await clean.build()), tamper: 'wrong-key' }) }, 'lab-release-eng', pub.privateKey, other.privateKey);
  const r1 = await inspect(wrong, policy);
  assert.equal(r1.verdict, 'block');
  assert.ok(r1.stages.find((s) => s.stage === 'signature')!.findings.some((f) => f.rule === 'bad-signature'));
  const pkg = await buildScenario(clean, 'unknown-vendor', pub.privateKey);
  const r2 = await inspect(pkg, policy);
  assert.ok(r2.stages.find((s) => s.stage === 'signature')!.findings.some((f) => f.rule === 'untrusted-publisher'));
});

test('integrity: smuggled unlisted file and path traversal', async () => {
  const { policy } = await setup();
  const files = [{ name: 'ok.json', bytes: te.encode('{}') }];
  const manifest = await makeManifest(files, 'j.ramirez', undefined, 't');
  const r = await inspect({ manifest, files: [...files, { name: '../../etc/cron.d/x', bytes: te.encode('x') }] }, { ...policy, requireSignature: false });
  const rules = r.stages.flatMap((s) => s.findings.map((f) => f.rule));
  assert.ok(rules.includes('unlisted-file'));
  assert.ok(rules.includes('path-traversal'));
});

test('two-person integrity rules', async () => {
  const { pub, policy } = await setup();
  const pkg = await buildScenario(SCENARIOS[0], 'lab-release-eng', pub.privateKey);
  const r = await inspect(pkg, policy);
  assert.equal(r.verdict, 'pass');
  const appr: import("../core/types.ts").Approval[] = [];
  assert.equal(canApprove(policy, pkg.manifest, r, appr, 'j.ramirez').ok, false, 'not a reviewer');
  assert.equal(canApprove({ ...policy, approvals: { ...policy.approvals, reviewers: { ...policy.approvals.reviewers, 'j.ramirez': 'RHR' } } }, pkg.manifest, r, appr, 'j.ramirez').ok, false, 'requester');
  assert.equal(canApprove(policy, pkg.manifest, r, appr, 'rhr.chen').ok, true);
  appr.push({ reviewer: 'rhr.chen', role: 'RHR', decision: 'approve' as const, at: '' });
  assert.equal(canApprove(policy, pkg.manifest, r, appr, 'rhr.chen').ok, false, 'same reviewer twice');
  assert.equal(approvalsSatisfied(policy, appr), false);
  appr.push({ reviewer: 'rhr.alvarez', role: 'RHR', decision: 'approve' as const, at: '' });
  assert.equal(approvalsSatisfied(policy, appr), true);

  const guard = await generateKeyPair();
  const rel = await signRelease('tollgate-01', guard.privateKey, r, appr);
  assert.equal((await verifyRelease(rel, guard.publicRaw, 2)).ok, true);
  rel.token.approvals.pop();
  assert.equal((await verifyRelease(rel, guard.publicRaw, 2)).ok, false, 'token edited after signing');
});

test('blocked transfers can never be approved', async () => {
  const { pub, policy } = await setup();
  const pkg = await buildScenario(SCENARIOS.find((s) => s.id === 'spillage')!, 'lab-release-eng', pub.privateKey);
  const r = await inspect(pkg, policy);
  assert.equal(canApprove(policy, pkg.manifest, r, [], 'rhr.chen').ok, false);
});

test('ledger detects edits, deletions and reordering', async () => {
  const l = new Ledger('low');
  for (let i = 0; i < 6; i++) await l.append('event', `TG-${i}`, { i });
  assert.equal((await verifyChain(l.entries)).ok, true);
  const edited = structuredClone(l.entries); edited[2].data = { i: 99 };
  assert.equal((await verifyChain(edited)).brokenAt, 2);
  const deleted = structuredClone(l.entries); deleted.splice(3, 1);
  assert.equal((await verifyChain(deleted)).ok, false);
  const swapped = structuredClone(l.entries); [swapped[1], swapped[4]] = [swapped[4], swapped[1]];
  assert.equal((await verifyChain(swapped)).ok, false);
});

test('diode FEC: survives loss with no return channel', async () => {
  const data = new Uint8Array(50_000).map((_, i) => (i * 31) & 0xff);
  const frames = encodeFrames(data, 7, { group: 8, repeat: 2 });
  // deterministic PRNG so the test is stable
  let seed = 1234567;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const rx = new Reassembler(7);
  for (const f of frames) if (rnd() > 0.2) rx.push(f); // 20% loss
  const out = rx.finish();
  assert.ok(out, `unrecoverable: ${JSON.stringify(rx.stats)}`);
  assert.deepEqual(out, data);

  // single pass + parity recovers exactly one loss per group
  const one = encodeFrames(data, 9, { group: 8, repeat: 1 });
  const rx2 = new Reassembler(9);
  one.forEach((f, i) => { if (i !== 3) rx2.push(f); });
  assert.deepEqual(rx2.finish(), data);
  assert.equal(rx2.stats.recovered, 1);

  // frames from another session and garbage are rejected
  const rx3 = new Reassembler(1);
  rx3.push(one[0]); rx3.push(new Uint8Array(40));
  assert.equal(rx3.stats.rejected, 2);
});

test('version range matching', () => {
  assert.ok(versionMatches('2.14.1', '>=2.0.0,<2.15.0'));
  assert.ok(!versionMatches('2.17.1', '>=2.0.0,<2.15.0'));
  assert.ok(versionMatches('5.6.1', '5.6.0|5.6.1'));
  assert.ok(versionMatches('2.5.10', '>=2.3.5,<2.3.32|>=2.5.0,<2.5.10.1'));
});
