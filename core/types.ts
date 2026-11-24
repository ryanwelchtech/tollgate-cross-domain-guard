// Shared types for the TOLLGATE cross-domain transfer guard.
// This module is environment-agnostic: it runs unchanged in Node (services)
// and in the browser (console demo).

export type Verdict = 'pass' | 'warn' | 'block';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  stage: string;
  rule: string;
  severity: Severity;
  message: string;
  file?: string;
  offset?: number;
}

export interface TransferFile {
  name: string;
  bytes: Uint8Array;
}

export interface ManifestEntry {
  name: string;
  size: number;
  sha256: string;
}

export interface Manifest {
  id: string;
  requester: string;
  direction: 'low-to-high';
  sourceNetwork: string;
  destination: string;
  justification: string;
  createdAt: string;
  publisher?: string;
  files: ManifestEntry[];
}

export interface TransferPackage {
  manifest: Manifest;
  files: TransferFile[];
  /** base64 Ed25519 signature over canonical(manifest) by the publisher. */
  signature?: string;
}

export interface StageResult {
  stage: string;
  title: string;
  verdict: Verdict;
  findings: Finding[];
  durationMs: number;
}

export interface InspectionResult {
  transferId: string;
  verdict: Verdict;
  stages: StageResult[];
  /** Files after content disarm & reconstruction (CDR). */
  released: TransferFile[];
  /** sha256 over the canonical released bundle. */
  bundleDigest: string;
  inspectedAt: string;
}

export interface Approval {
  reviewer: string;
  role: string;
  decision: 'approve' | 'reject';
  at: string;
  note?: string;
}

export interface ReleaseToken {
  transferId: string;
  bundleDigest: string;
  verdict: Verdict;
  approvals: Approval[];
  releasedAt: string;
  guard: string;
}

export interface SignedRelease {
  token: ReleaseToken;
  /** base64 Ed25519 signature over canonical(token) by the guard key. */
  signature: string;
}

export interface Policy {
  name: string;
  sourceNetwork: { name: string; maxLevel: string };
  destination: { name: string; maxLevel: string };
  maxFileBytes: number;
  maxPackageBytes: number;
  maxFiles: number;
  requireSignature: boolean;
  /** publisher id -> base64 raw Ed25519 public key */
  trustStore: Record<string, string>;
  allowedExtensions: string[];
  markingRequiredExtensions: string[];
  markingLevels: string[];
  dirtyWords: string[];
  dirtyPatterns: string[];
  archive: { maxRatio: number; maxEntries: number; allowNested: boolean };
  sbom: { deniedLicenses: string[] };
  approvals: { required: number; reviewers: Record<string, string> };
}

export interface VulnRecord {
  name: string;
  /** versions affected, exact match or "<x.y.z" / ">=a,<b" range syntax */
  affected: string;
  cve: string;
  kev: boolean;
  summary: string;
}
