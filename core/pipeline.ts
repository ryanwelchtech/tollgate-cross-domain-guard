import type { Finding, InspectionResult, Policy, StageResult, TransferPackage, Verdict } from './types.ts';
import { STAGES, verdictOf, type StageContext } from './stages.ts';
import { canonical, sha256 } from './encoding.ts';

export async function bundleDigest(transferId: string, files: { name: string; bytes: Uint8Array }[]): Promise<string> {
  const entries = [];
  for (const f of files) entries.push({ name: f.name, sha256: await sha256(f.bytes), size: f.bytes.length });
  return sha256(canonical({ transferId, files: entries }));
}

export interface InspectOptions {
  onStage?: (r: StageResult) => void | Promise<void>;
}

/**
 * Run every stage (never short-circuit: reviewers and the ISSM need the full
 * picture), then compute the release digest over the post-CDR file set.
 */
export async function inspect(pkg: TransferPackage, policy: Policy, opts: InspectOptions = {}): Promise<InspectionResult> {
  const ctx: StageContext = { pkg, policy, files: pkg.files.map((f) => ({ name: f.name, bytes: f.bytes })) };
  const stages: StageResult[] = [];
  for (const s of STAGES) {
    const findings: Finding[] = [];
    const t0 = performance.now();
    await s.run(ctx, (severity, rule, message, file, offset) => findings.push({ stage: s.id, rule, severity, message, file, offset }));
    const r: StageResult = { stage: s.id, title: s.title, verdict: verdictOf(findings), findings, durationMs: performance.now() - t0 };
    stages.push(r);
    await opts.onStage?.(r);
  }
  const verdict: Verdict = stages.some((s) => s.verdict === 'block') ? 'block' : stages.some((s) => s.verdict === 'warn') ? 'warn' : 'pass';
  return {
    transferId: pkg.manifest.id,
    verdict,
    stages,
    released: ctx.files,
    bundleDigest: await bundleDigest(pkg.manifest.id, ctx.files),
    inspectedAt: new Date().toISOString(),
  };
}

export { STAGES };
