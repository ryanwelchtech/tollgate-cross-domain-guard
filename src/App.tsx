import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Approval, InspectionResult, Policy, SignedRelease, StageResult, TransferPackage } from '../core/types.ts';
import { generateKeyPair, sha256, type KeyPair } from '../core/encoding.ts';
import { identify } from '../core/magic.ts';
import { readZipDirectory } from '../core/zip.ts';
import { inspect, STAGES } from '../core/pipeline.ts';
import { SCENARIOS, buildScenario, makeManifest, type Scenario } from '../core/samples.ts';
import { approvalsSatisfied, canApprove, signRelease, verifyRelease } from '../core/release.ts';
import { decodeBundle, encodeBundle, encodeFrames, Reassembler } from '../core/diode.ts';
import { bundleDigest } from '../core/pipeline.ts';
import { Ledger, verifyChain, type LedgerEntry, type ChainCheck } from '../core/ledger.ts';
import { VULN_SNAPSHOT_DATE } from '../core/vulns.ts';
import basePolicy from '../policy/policy.json';
import { DiodeView, type DiodeRun } from './Diode.tsx';

const PUBLISHER = 'lab-release-eng';
const REQUESTER = 'j.ramirez';
const REVIEWERS = ['rhr.chen', 'rhr.alvarez', 'issm.okafor', REQUESTER];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const auto = new URLSearchParams(location.search).has('auto');

interface Keys { pub: KeyPair; guard: KeyPair }
type StageState = { status: 'idle' | 'running' | 'done'; result?: StageResult };

const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`);

export function App() {
  const [keys, setKeys] = useState<Keys | null>(null);
  const policy = useMemo<Policy | null>(() => (keys ? { ...(basePolicy as Policy), trustStore: { [PUBLISHER]: keys.pub.publicRaw } } : null), [keys]);
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [pkg, setPkg] = useState<TransferPackage | null>(null);
  const [fileInfo, setFileInfo] = useState<{ name: string; size: number; type: string; sha: string }[]>([]);
  const [stages, setStages] = useState<StageState[]>(STAGES.map(() => ({ status: 'idle' })));
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [denial, setDenial] = useState<string | null>(null);
  const [released, setReleased] = useState<SignedRelease | null>(null);
  const [diode, setDiode] = useState<DiodeRun | null>(null);
  const [loss, setLoss] = useState(0.15);
  const [repeat, setRepeat] = useState(2);
  const [signUploads, setSignUploads] = useState(true);
  const low = useRef(new Ledger('low'));
  const high = useRef(new Ledger('high'));
  const [ledgerView, setLedgerView] = useState<LedgerEntry[]>([]);
  const [chain, setChain] = useState<{ low: ChainCheck; high: ChainCheck } | null>(null);
  const [busy, setBusy] = useState(false);
  const [openStage, setOpenStage] = useState<string | null>(null);

  useEffect(() => { Promise.all([generateKeyPair(), generateKeyPair()]).then(([pub, guard]) => setKeys({ pub, guard })); }, []);

  const refreshLedger = useCallback(() => {
    setLedgerView([...low.current.entries, ...high.current.entries].sort((a, b) => a.at.localeCompare(b.at)));
    setChain(null);
  }, []);

  const run = useCallback(async (p: TransferPackage, s: Scenario | null) => {
    if (!policy) return;
    setBusy(true);
    setScenario(s); setPkg(p); setResult(null); setApprovals([]); setDenial(null); setReleased(null); setDiode(null); setOpenStage(null);
    setStages(STAGES.map(() => ({ status: 'idle' })));
    const info = [];
    for (const f of p.files) info.push({ name: f.name, size: f.bytes.length, type: identify(f.bytes, readZipDirectory(f.bytes)?.map((e) => e.name)).label, sha: (await sha256(f.bytes)).slice(0, 12) });
    setFileInfo(info);
    await low.current.append('submitted', p.manifest.id, { requester: p.manifest.requester, files: p.files.length });
    let i = 0;
    setStages((st) => st.map((x, j) => (j === 0 ? { status: 'running' } : x)));
    const r = await inspect(p, policy, {
      onStage: async (res) => {
        await sleep(auto ? 140 : 220);
        const k = i++;
        setStages((st) => st.map((x, j) => (j === k ? { status: 'done', result: res } : j === k + 1 ? { status: 'running' } : x)));
      },
    });
    await low.current.append('inspected', p.manifest.id, { verdict: r.verdict, bundleDigest: r.bundleDigest });
    setResult(r);
    const firstBad = r.stages.find((x) => x.verdict !== 'pass');
    setOpenStage(firstBad?.stage ?? null);
    refreshLedger();
    setBusy(false);
    return r;
  }, [policy, refreshLedger]);

  const runScenario = useCallback(async (s: Scenario) => {
    if (!keys) return;
    const other = await generateKeyPair();
    const p = await buildScenario(s, PUBLISHER, keys.pub.privateKey, other.privateKey);
    return run(p, s);
  }, [keys, run]);

  const onFiles = useCallback(async (list: FileList | null) => {
    if (!list || !keys) return;
    const files = await Promise.all([...list].slice(0, 16).map(async (f) => ({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) })));
    const manifest = await makeManifest(files, REQUESTER, signUploads ? PUBLISHER : undefined, 'operator upload');
    const { canonical, sign } = await import('../core/encoding.ts');
    const signature = signUploads ? await sign(keys.pub.privateKey, canonical(manifest)) : undefined;
    run({ manifest, files, signature }, null);
  }, [keys, run, signUploads]);

  const review = useCallback(async (reviewer: string) => {
    if (!policy || !pkg || !result) return;
    const c = canApprove(policy, pkg.manifest, result, approvals, reviewer);
    if (!c.ok) {
      setDenial(`${reviewer}: ${c.reason}`);
      await low.current.append('review-denied', pkg.manifest.id, { user: reviewer, reason: c.reason });
      refreshLedger();
      return;
    }
    setDenial(null);
    const a: Approval = { reviewer, role: policy.approvals.reviewers[reviewer], decision: 'approve', at: new Date().toISOString() };
    setApprovals((x) => [...x, a]);
    await low.current.append('reviewed', pkg.manifest.id, { reviewer, decision: 'approve' });
    refreshLedger();
  }, [policy, pkg, result, approvals, refreshLedger]);

  const release = useCallback(async () => {
    if (!keys || !policy || !pkg || !result) return;
    setBusy(true);
    const rel = await signRelease('tollgate-01', keys.guard.privateKey, result, approvals);
    setReleased(rel);
    const bytes = encodeBundle({ release: rel, manifestId: pkg.manifest.id, files: result.released });
    const session = (Math.random() * 0xffffffff) >>> 0;
    const frames = encodeFrames(bytes, session, { group: 8, repeat });
    const fates = frames.map(() => Math.random() >= loss);
    await low.current.append('released', pkg.manifest.id, { bytes: bytes.length, frames: frames.length, bundleDigest: result.bundleDigest });
    refreshLedger();
    const rx = new Reassembler(session);
    const runState: DiodeRun = { frames: frames.length, fates, delivered: 0, phase: 'sending', stats: rx.stats, bytes: bytes.length };
    setDiode({ ...runState });
    const stepMs = Math.max(8, Math.min(60, 2200 / frames.length));
    for (let i = 0; i < frames.length; i++) {
      if (fates[i]) rx.push(frames[i]);
      if (i % Math.max(1, Math.floor(frames.length / 60)) === 0 || i === frames.length - 1) {
        setDiode({ ...runState, delivered: i + 1, stats: { ...rx.stats } });
        await sleep(stepMs * Math.max(1, Math.floor(frames.length / 60)));
      }
    }
    const out = rx.finish();
    let verdict: DiodeRun['verdict'] = 'unrecoverable';
    const problems: string[] = [];
    if (out) {
      const b = decodeBundle(out);
      const v = await verifyRelease(b.release, keys.guard.publicRaw, policy.approvals.required);
      if (!v.ok) problems.push(v.reason);
      if ((await bundleDigest(b.manifestId, b.files)) !== b.release.token.bundleDigest) problems.push('bundle digest mismatch');
      verdict = problems.length ? 'quarantined' : 'accepted';
      await high.current.append(verdict, b.manifestId, { files: b.files.length, fecRecovered: rx.stats.recovered, duplicates: rx.stats.duplicates, problems });
    } else {
      await high.current.append('rx-failed', `session-${session}`, { ...rx.stats });
    }
    setDiode({ ...runState, delivered: frames.length, phase: 'done', stats: { ...rx.stats }, verdict, problems });
    refreshLedger();
    setBusy(false);
  }, [keys, policy, pkg, result, approvals, loss, repeat, refreshLedger]);

  const tamper = useCallback(() => {
    const e = low.current.entries;
    if (e.length < 2) return;
    const i = Math.floor(e.length / 2);
    e[i] = { ...e[i], data: { ...e[i].data, verdict: 'pass', tampered: 'insider edit' } };
    refreshLedger();
  }, [refreshLedger]);

  const verifyLedgers = useCallback(async () => {
    setChain({ low: await verifyChain(low.current.entries), high: await verifyChain(high.current.entries) });
  }, []);

  // Scripted walkthrough for the README GIF (?auto)
  useEffect(() => {
    if (!auto || !keys || !policy) return;
    (async () => {
      await sleep(400);
      for (const id of ['macro-docx', 'spillage', 'log4shell-sbom']) { await runScenario(SCENARIOS.find((s) => s.id === id)!); await sleep(1100); }
      await runScenario(SCENARIOS[0]);
      await sleep(500);
      document.getElementById('btn-rhr.chen')?.click(); await sleep(450);
      document.getElementById('btn-rhr.chen')?.click(); await sleep(700);
      document.getElementById('btn-rhr.alvarez')?.click(); await sleep(500);
      document.getElementById('btn-release')?.click(); await sleep(3800);
      document.getElementById('btn-tamper')?.click(); await sleep(400);
      document.getElementById('btn-verify')?.click();
      (window as unknown as { __done: boolean }).__done = true;
    })();
  }, [keys, policy]); // eslint-disable-line react-hooks/exhaustive-deps

  const satisfied = policy ? approvalsSatisfied(policy, approvals) : false;
  const verdict = result?.verdict;

  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="logo">⛩</span>
          <div>
            <h1>TOLLGATE</h1>
            <p>Cross-domain transfer guard · low → high · air-gapped enclave</p>
          </div>
        </div>
        <div className="chips">
          <span className="chip">SRC <b>{basePolicy.sourceNetwork.name}</b> ≤ {basePolicy.sourceNetwork.maxLevel}</span>
          <span className="chip">DST <b>{basePolicy.destination.name}</b> ≤ {basePolicy.destination.maxLevel}</span>
          <span className="chip">TPI <b>{basePolicy.approvals.required}-person</b></span>
          <span className="chip">Vuln snapshot <b>{VULN_SNAPSHOT_DATE}</b></span>
        </div>
      </header>

      <main>
        <aside className="panel scenarios">
          <h2>Transfer requests</h2>
          {SCENARIOS.map((s) => (
            <button key={s.id} className={`scn ${scenario?.id === s.id ? 'active' : ''}`} disabled={!keys || busy} onClick={() => runScenario(s)}>
              <span className={`dot ${s.expect}`} />
              <span>{s.title}</span>
            </button>
          ))}
          <label className="drop">
            <input type="file" multiple onChange={(e) => onFiles(e.target.files)} disabled={!keys || busy} />
            <b>Inspect your own files</b>
            <span>Files stay in your browser. Nothing is uploaded.</span>
          </label>
          <label className="check"><input type="checkbox" checked={signUploads} onChange={(e) => setSignUploads(e.target.checked)} /> sign with lab publisher key</label>
        </aside>

        <section className="panel center">
          {!pkg && (
            <div className="empty">
              <h2>Select a transfer request</h2>
              <p>Each request runs through nine inspection stages, two-person review, guard signing, and a one-way diode with forward error correction. Every action lands in a hash-chained custody ledger.</p>
            </div>
          )}
          {pkg && (
            <>
              <div className="manifest">
                <div>
                  <div className="mid">{pkg.manifest.id}</div>
                  <div className="muted">requester <b>{pkg.manifest.requester}</b> · publisher <b>{pkg.manifest.publisher ?? 'unsigned'}</b> · {pkg.manifest.files.length} file(s)</div>
                  {scenario && <p className="blurb">{scenario.blurb}</p>}
                </div>
                {verdict && <div className={`verdict ${verdict}`}>{verdict.toUpperCase()}</div>}
              </div>
              <table className="files">
                <thead><tr><th>file</th><th>size</th><th>true type</th><th>sha-256</th></tr></thead>
                <tbody>{fileInfo.map((f) => <tr key={f.name}><td>{f.name}</td><td>{fmtBytes(f.size)}</td><td>{f.type}</td><td className="mono">{f.sha}…</td></tr>)}</tbody>
              </table>
              <div className="stages">
                {STAGES.map((def, i) => {
                  const st = stages[i];
                  const v = st.result?.verdict;
                  const shown = st.result?.findings.filter((f) => f.severity !== 'info') ?? [];
                  const open = openStage === def.id;
                  return (
                    <div key={def.id} className={`stage ${st.status} ${v ?? ''}`} onClick={() => setOpenStage(open ? null : def.id)}>
                      <div className="srow">
                        <span className="idx">{String(i + 1).padStart(2, '0')}</span>
                        <span className="sname">{def.title}</span>
                        <span className="ctl">{def.control}</span>
                        <span className={`badge ${v ?? st.status}`}>{st.status === 'running' ? '…' : v ? v.toUpperCase() : ''}</span>
                      </div>
                      {open && st.result && (
                        <ul className="findings">
                          {(shown.length ? shown : st.result.findings).map((f, k) => (
                            <li key={k} className={f.severity}><span className="sev">{f.severity}</span>{f.file && <span className="ff">{f.file}</span>}{f.message}</li>
                          ))}
                          {!st.result.findings.length && <li className="info"><span className="sev">info</span>No findings</li>}
                        </ul>
                      )}
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </section>

        <section className="panel right">
          <h2>Two-person review</h2>
          <div className="reviewers">
            {REVIEWERS.map((r) => {
              const done = approvals.some((a) => a.reviewer === r);
              return (
                <button key={r} id={`btn-${r}`} className={`rv ${done ? 'ok' : ''}`} disabled={!result || busy || !!released} onClick={() => review(r)}>
                  <b>{r}</b><span>{r === REQUESTER ? 'requester' : basePolicy.approvals.reviewers[r as keyof typeof basePolicy.approvals.reviewers]}</span>
                  {done && <i>✓ approved</i>}
                </button>
              );
            })}
          </div>
          {denial && <div className="denial">⛔ {denial}</div>}
          <button id="btn-release" className="release" disabled={!satisfied || !!released || busy} onClick={release}>
            Sign & release into diode →
          </button>
          <div className="knobs">
            <label>link loss <b>{Math.round(loss * 100)}%</b><input type="range" min={0} max={0.45} step={0.01} value={loss} onChange={(e) => setLoss(+e.target.value)} disabled={busy} /></label>
            <label>repetition <b>×{repeat}</b><input type="range" min={1} max={3} step={1} value={repeat} onChange={(e) => setRepeat(+e.target.value)} disabled={busy} /></label>
          </div>
          <DiodeView run={diode} />
          {released && diode?.phase === 'done' && (
            <div className={`receipt ${diode.verdict}`}>
              <b>HIGH SIDE: {diode.verdict?.toUpperCase()}</b>
              <span>{diode.verdict === 'accepted' ? 'Guard signature, 2 distinct approvals and bundle digest verified. Files written read-only to the enclave inbox.' : diode.verdict === 'unrecoverable' ? 'Too many frames lost for FEC to rebuild. With no return path the sender must re-send; raise repetition.' : diode.problems?.join('; ')}</span>
            </div>
          )}
        </section>
      </main>

      <section className="panel ledger">
        <div className="lhead">
          <h2>Chain-of-custody ledger</h2>
          <div className="lbtns">
            <button id="btn-tamper" onClick={tamper} disabled={ledgerView.length < 2}>Simulate insider edit</button>
            <button id="btn-verify" onClick={verifyLedgers} disabled={!ledgerView.length}>Verify hash chains</button>
            {chain && <span className={`cv ${chain.low.ok && chain.high.ok ? 'ok' : 'bad'}`}>
              low: {chain.low.ok ? 'VERIFIED' : `BROKEN @ #${chain.low.brokenAt} (${chain.low.reason})`} · high: {chain.high.ok ? 'VERIFIED' : `BROKEN @ #${chain.high.brokenAt}`}
            </span>}
          </div>
        </div>
        <div className="ltable">
          <table>
            <thead><tr><th>side</th><th>#</th><th>event</th><th>transfer</th><th>data</th><th>prev</th><th>hash</th></tr></thead>
            <tbody>
              {ledgerView.slice(-14).reverse().map((e) => (
                <tr key={e.side + e.seq} className={chain && ((e.side === 'low' && chain.low.brokenAt === e.seq) || (e.side === 'high' && chain.high.brokenAt === e.seq)) ? 'broken' : ''}>
                  <td><span className={`side ${e.side}`}>{e.side}</span></td><td>{e.seq}</td><td>{e.event}</td><td className="mono">{e.transferId}</td>
                  <td className="mono dim">{JSON.stringify(e.data).slice(0, 70)}</td><td className="mono dim">{e.prev.slice(0, 10)}</td><td className="mono">{e.hash.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <footer>
        Same TypeScript engine as the Node services in <code>services/</code>; runs entirely in your browser with WebCrypto Ed25519 / SHA-256. Fictitious markings & codewords. Lab demo, not an accredited CDS.
      </footer>
    </div>
  );
}
