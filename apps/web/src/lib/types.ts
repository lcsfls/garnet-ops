/** Response shapes of /api/v1, as the API routes return them (apps/api/src/routes). */
import type { FindingState, ScanState, Severity } from "@garnetops/core";
import type { AiError, TriageResult } from "@garnetops/core/ai";
import type { Grade, GradeRule } from "@garnetops/core/grades";

export type { FindingState, Grade, GradeRule, ScanState, Severity };
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

/**
 * The grade of a repository or server (ADR 0018), display only. `grade` is null before the
 * first successful scan or inventory. `gradeStale`: the latest scan failed, the grade is that
 * of the last successful one.
 */
export interface GradeFields {
  grade: Grade | null;
  gradeReason: { rule: GradeRule; count: number; example: string | null } | null;
  gradeStale: boolean;
}

export interface RepositoryRow extends GradeFields {
  id: string;
  name: string;
  url: string;
  branch: string | null;
  authKind: "none" | "https-token" | "ssh-deploy-key" | "connection";
  /** Who sees it (ADR 0030): the organisation, or only the person who added it from their connected account. */
  visibility: "organization" | "private";
  /** The caller added it (and owns its credential). */
  mine: boolean;
  /** Private, and its owner asked owners and admins to share it. */
  shareRequested: boolean;
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
  writeAccess: WriteAccess;
}

/* Fix proposals and fix pull requests (ADR 0014) */

export type ForgeKind = "github" | "gitea" | "forgejo";
export type FixPrState = "queued" | "running" | "open" | "merged" | "closed" | "failed";

export interface WriteAccess {
  /** The repository address names an owner and a repository on a host. */
  supported: boolean;
  suggested: { forgeKind: ForgeKind | null; apiBaseUrl: string | null } | null;
  enabled: boolean;
  access: {
    forgeKind: ForgeKind;
    apiBaseUrl: string;
    enabledAt: string;
    enabledBy: string | null;
    status: "unchecked" | "ok" | "failed";
    statusReason: string | null;
    /** "broad-token": the forge says the token reaches more than this repository. */
    warning: string | null;
    checkedAt: string | null;
  } | null;
}

export interface FixPrSummary {
  id: string;
  state: FixPrState;
  reason: string | null;
  number: number | null;
  url: string | null;
  from: string;
  to: string;
  branch: string | null;
  requestedBy: string | null;
  createdAt: string;
  openedAt: string | null;
  closedAt: string | null;
  lastCheckedAt: string | null;
}

export interface FixProposalRow {
  key: string;
  repositoryId: string;
  repositoryName: string;
  ecosystem: "npm" | "pypi" | "go" | "cargo" | "composer" | null;
  packageType: string;
  packageName: string;
  installedVersion: string;
  targetVersion: string | null;
  majorUpgrade: boolean;
  severity: Severity;
  vulnerabilityIds: string[];
  unresolvedIds: string[];
  findingIds: string[];
  manifestPath: string | null;
  dependency: "direct" | "transitive" | "unknown";
  section: string | null;
  dev: boolean;
  currentSpec: string | null;
  newSpec: string | null;
  action: "edit" | "manual";
  reason: string | null;
  writeAccess: "off" | "on" | "failed";
  /** The branch a pull request would use. */
  branch: string | null;
  creatable: boolean;
  pr: FixPrSummary | null;
  aiSuggestion: {
    findingId: string;
    summary: string;
    recommendation: string;
    confidence: "low" | "medium" | "high";
    upgradeTo: string | null;
  } | null;
}

export interface FixProposalPage extends Page<FixProposalRow> {
  counts: { all: number; edit: number; manual: number };
}

export interface FixPrRow extends FixPrSummary {
  repositoryId: string;
  repositoryName: string;
  ecosystem: string;
  packageName: string;
  manifestPath: string;
  majorUpgrade: boolean;
  severity: Severity;
  vulnerabilityIds: string[];
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

/* AI triage (ADR 0013) */

export type { AiError, TriageResult };
export type AiScope = "private" | "external" | "unknown";

export type AiSettings =
  | { configured: false }
  | {
      configured: true;
      enabled: boolean;
      baseUrl: string;
      model: string;
      hasApiKey: boolean;
      maxTokens: number;
      temperature: number;
      timeoutSeconds: number;
      maxConcurrent: number;
      scope: AiScope;
      insecureTransport: boolean;
      externalAcknowledged: boolean;
      externalAckAt: string | null;
      updatedAt: string;
    };

export interface AiProbe {
  status: "pending" | "done";
  kind: "models" | "test";
  result: {
    ok: boolean;
    error?: AiError;
    models?: string[];
    latencyMs?: number;
    replyChars?: number;
    scope?: AiScope;
  } | null;
}

export type AiMessageStatus = "pending" | "streaming" | "complete" | "stopped" | "failed";

export interface AiMessage {
  id: string;
  role: "user" | "assistant";
  kind: "triage" | "chat";
  status: AiMessageStatus;
  content: string;
  structured: TriageResult | null;
  error: AiError | null;
  model: string | null;
  promptTokens: number | null;
  completionTokens: number | null;
  latencyMs: number | null;
  createdAt: string;
  /** The name of the person who asked (user messages only). */
  author: string | null;
  /** The answer was taken over as a note on the finding. */
  noted: boolean;
}

export interface AiThread {
  state: "not-configured" | "disabled" | "ready";
  model?: string;
  scope?: AiScope;
  insecureTransport?: boolean;
  canAsk: boolean;
  threadId: string | null;
  messages: AiMessage[];
}

export interface FindingNote {
  id: string;
  body: string;
  source: "manual" | "ai";
  meta: { exploitability?: string; reachable?: string; confidence?: string; upgradeTo?: string } | null;
  createdAt: string;
  author: string | null;
}

/** GET /statistics (apps/api/src/routes/statistics.ts, packages/db/src/statistics.ts). */
export interface StatisticsBucket {
  start: string;
  end: string;
  open: SeverityCounts;
  opened: SeverityCounts;
  resolved: SeverityCounts;
  gates: { passed: number; notes: number; blocked: number };
}

export interface StatisticsRanking {
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Statistics {
  range: { days: number; from: string; to: string; timeZone: string; granularity: "day" | "week" };
  buckets: StatisticsBucket[];
  totals: {
    opened: number;
    resolved: number;
    previous: { opened: number; resolved: number };
    gates: { passed: number; notes: number; blocked: number };
    scans: { succeeded: number; failed: number };
    fixPrs: { opened: number; merged: number };
  };
  timeToFix: { severity: Severity; resolved: number; medianDays: number | null }[];
  repositories: ({ id: string; name: string } & StatisticsRanking)[];
  packages: ({ name: string; type: string; repositories: number } & StatisticsRanking)[];
  oldest: {
    id: string;
    severity: Severity;
    vulnerabilityId: string;
    packageName: string;
    packageVersion: string;
    repositoryId: string;
    repositoryName: string;
    firstSeenAt: string;
  }[];
  generatedAt: string;
}

/* Personal forge connections (ADR 0030) */

export interface ForgeConnection {
  id: string;
  forgeKind: ForgeKind;
  webBaseUrl: string;
  /** A pasted token, or signed in with the forge's own login (ADR 0031). */
  authMethod: "token" | "sign-in";
  apiBaseUrl: string;
  accountLogin: string | null;
  state: "unchecked" | "ok" | "failed";
  /** A short code such as "token-rejected" when the last check failed. */
  problem: string | null;
  broadToken: boolean;
  truncated: boolean;
  lastCheckedAt: string | null;
  createdAt: string;
  repositories: number;
}

export interface ConnectionRepository {
  forgeId: string;
  fullName: string;
  description: string | null;
  private: boolean;
  archived: boolean;
  defaultBranch: string | null;
  /** Already monitored: visible to the caller (with its id), or privately by someone else. */
  added: { repositoryId: string } | { elsewhere: true } | null;
}

export interface ShareRequest {
  id: string;
  name: string;
  requestedAt: string;
  requestedBy: string | null;
}

/* Signing in to forges (ADR 0031) */

export interface ForgeApp {
  id: string;
  forgeKind: ForgeKind;
  webBaseUrl: string;
  apiBaseUrl: string;
  clientId: string;
  hasSecret: boolean;
  flow: "device" | "code";
  createdAt: string;
}

export interface AvailableForgeApp {
  id: string;
  forgeKind: ForgeKind;
  webBaseUrl: string;
  flow: "device" | "code";
}

export interface ForgeSignIn {
  id: string;
  flow: "device" | "code";
  state: "starting" | "waiting" | "exchanging" | "done" | "failed";
  userCode: string | null;
  verificationUri: string | null;
  expiresAt: string;
  problem: string | null;
  connectionId: string | null;
}
