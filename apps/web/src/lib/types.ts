/** Response shapes of /api/v1, as the API routes return them (apps/api/src/routes). */
import type { FindingState, ScanState, Severity } from "@garnetops/core";

export type { FindingState, ScanState, Severity };
export type SeverityCounts = Partial<Record<Severity, number>>;

export interface Page<T> {
  items: T[];
  total: number;
  pageSize: number;
  next: string | null;
  prev: string | null;
}

export interface Overview {
  open: SeverityCounts;
  states: Partial<Record<FindingState, number>>;
  knownExploitedOpen: number;
  fixableOpen: number;
  /** Open findings with a fixed version, per severity. */
  fixableBySeverity: SeverityCounts;
  repositories: { total: number; blocked: number; attention: number; never_scanned: number };
  fixFirst: {
    id: string;
    severity: Severity;
    packageName: string;
    packageVersion: string;
    packageType: string;
    vulnerabilityId: string;
    repositoryId: string;
    repositoryName: string;
    fixedIn: string[] | null;
    knownExploited: boolean;
  }[];
  recentScans: {
    id: string;
    state: ScanState;
    repositoryId: string;
    repositoryName: string;
    newFindings: number | null;
    resolvedFindings: number | null;
    finishedAt: string | null;
    createdAt: string;
    error: string | null;
  }[];
  /** Open findings per calendar day in `timeZone`. */
  trend: { timeZone: string; days: { day: string; severity: Severity; n: number }[] };
  /** The vulnerability database and scanners of the latest successful scan; null before the first one. */
  vulnerabilityData: {
    builtAt: string | null;
    scannerVersions: Record<string, string> | null;
    scannedAt: string | null;
  } | null;
  /** Advisory sources behind the findings so far, e.g. ["debian", "github", "nvd"]. */
  vulnerabilitySources: string[];
  /** Recent organisation events every member may see, newest first. */
  activity: ActivityItem[];
  generatedAt: string;
}

export interface ActivityItem {
  /** An audit action such as "repository.created", or "schedule.run" for a nightly scan. */
  kind: string;
  at: string;
  actorName: string | null;
  subject: string | null;
  count: number | null;
}

export interface RepositoryRow {
  id: string;
  name: string;
  url: string;
  branch: string | null;
  authKind: "none" | "https-token" | "ssh-deploy-key";
  /** OpenSSH public key of the generated deploy key, for SSH repositories. */
  deployPublicKey: string | null;
  /** Host keys pinned on the first SSH contact, with the fingerprints ssh shows. */
  sshHostKeys: { pinnedAt: string; keys: { host: string; type: string; fingerprint: string }[] } | null;
  lastScanAt: string | null;
  lastScan: { id: string; state: ScanState; finishedAt: string | null; error: string | null } | null;
  open: SeverityCounts;
  /** Scanners of the last successful scan, e.g. ["grype", "syft"]. */
  scanners: string[];
  /** Open findings at the end of each of the last 14 days in the viewer's zone, oldest first. */
  trend: number[];
}

export interface FindingRow {
  id: string;
  severity: Severity;
  state: FindingState;
  packageName: string;
  packageVersion: string;
  packageType: string;
  fixedIn: string[] | null;
  vulnerabilityId: string;
  knownExploited: boolean;
  cvssScore: number | null;
  /** Probability of exploitation in the next 30 days (FIRST EPSS), 0 to 1. */
  epss: number | null;
  /** When the advisory was published. */
  publishedAt: string | null;
  repositoryId: string;
  repositoryName: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface FindingDetail {
  id: string;
  severity: Severity;
  state: FindingState;
  packageName: string;
  packageVersion: string;
  packageType: string;
  packagePurl: string | null;
  fixedIn: string[] | null;
  fixState: string | null;
  locations: string[] | null;
  acceptedReason: string | null;
  acceptedUntil: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  vulnerability: {
    id: string;
    description: string | null;
    cvssScore: number | null;
    cvssVector: string | null;
    urls: string[] | null;
    aliases: string[] | null;
    knownExploited: boolean;
    epss: number | null;
    publishedAt: string | null;
    modifiedAt: string | null;
  };
  repository: { id: string; name: string; url: string };
}

/** `GET /repositories/:id`: one repository with its latest scan and finding counts. */
export interface RepositoryDetail extends Omit<RepositoryRow, "lastScan" | "scanners" | "trend"> {
  createdAt: string;
  lastScan: { id: string; state: ScanState; finishedAt: string | null; error: string | null } | null;
  states: Partial<Record<FindingState, number>>;
}

export interface ScanRow {
  id: string;
  state: ScanState;
  trigger: "manual" | "schedule" | "webhook";
  branch: string | null;
  commitSha: string | null;
  packageCount: number | null;
  newFindings: number | null;
  resolvedFindings: number | null;
  scannerVersions: Record<string, string> | null;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

/** A resolved finding and the package version the repository has now (empty: removed). */
export interface PatchRow {
  id: string;
  resolvedAt: string;
  severity: Severity;
  vulnerabilityId: string;
  packageName: string;
  packageType: string;
  version: string;
  fixedIn: string[] | null;
  firstSeenAt: string;
  currentVersions: string[];
}

export type GateMode = "off" | "report" | "block";
export type GateResult = "passed" | "notes" | "blocked";
export type GateMatches = Record<string, { count: number; mode: GateMode }>;

export interface GateRuleState {
  rule: "critical-fixable" | "known-exploited" | "high-fixable" | "license-denied";
  mode: GateMode;
  defaultMode: GateMode;
  deniedLicenses?: string[];
  updatedAt: string | null;
}

export interface GateRunRow {
  id: string;
  createdAt: string;
  result: GateResult;
  matches: GateMatches;
  repositoryId: string;
  repositoryName: string;
  scanId: string;
  trigger: "manual" | "schedule" | "webhook" | "ci";
  ref: string | null;
  branch: string | null;
  commitSha: string | null;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface GateTokenRow {
  id: string;
  label: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  createdBy: string | null;
}
