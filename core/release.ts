// Two-person integrity (TPI) review and guard-signed release tokens.

import type { Approval, InspectionResult, Manifest, Policy, ReleaseToken, SignedRelease } from './types.ts';
import { canonical, sign, verify } from './encoding.ts';

export type ApprovalCheck = { ok: true } | { ok: false; reason: string };

export function canApprove(policy: Policy, manifest: Manifest, inspection: InspectionResult, approvals: Approval[], reviewer: string): ApprovalCheck {
  if (inspection.verdict === 'block') return { ok: false, reason: 'Inspection verdict is BLOCK; blocked transfers cannot be approved' };
  if (!policy.approvals.reviewers[reviewer]) return { ok: false, reason: `"${reviewer}" is not an authorized reliable human reviewer (RHR)` };
  if (reviewer === manifest.requester) return { ok: false, reason: 'Separation of duties: the requester cannot review their own transfer' };
  if (approvals.some((a) => a.reviewer === reviewer)) return { ok: false, reason: 'Two-person integrity: the same reviewer cannot approve twice' };
  if (approvals.some((a) => a.decision === 'reject')) return { ok: false, reason: 'Transfer was already rejected' };
  return { ok: true };
}

export function approvalsSatisfied(policy: Policy, approvals: Approval[]): boolean {
  const ok = approvals.filter((a) => a.decision === 'approve');
  return new Set(ok.map((a) => a.reviewer)).size >= policy.approvals.required && !approvals.some((a) => a.decision === 'reject');
}

export async function signRelease(
  guardId: string, guardKey: CryptoKey, inspection: InspectionResult, approvals: Approval[],
): Promise<SignedRelease> {
  const token: ReleaseToken = {
    transferId: inspection.transferId,
    bundleDigest: inspection.bundleDigest,
    verdict: inspection.verdict,
    approvals,
    releasedAt: new Date().toISOString(),
    guard: guardId,
  };
  return { token, signature: await sign(guardKey, canonical(token)) };
}

export async function verifyRelease(rel: SignedRelease, guardPublicRaw: string, requiredApprovals: number): Promise<ApprovalCheck> {
  if (!(await verify(guardPublicRaw, canonical(rel.token), rel.signature))) return { ok: false, reason: 'Guard signature invalid' };
  if (rel.token.verdict === 'block') return { ok: false, reason: 'Token carries BLOCK verdict' };
  const n = new Set(rel.token.approvals.filter((a) => a.decision === 'approve').map((a) => a.reviewer)).size;
  if (n < requiredApprovals) return { ok: false, reason: `Only ${n}/${requiredApprovals} distinct approvals` };
  return { ok: true };
}
