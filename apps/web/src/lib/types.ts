/** Response shapes of /api/v1, as the API routes return them (apps/api/src/routes). */
import type { FindingState, ScanState, Severity } from "@garnetops/core";
import type { AiError, TriageResult } from "@garnetops/core/ai";
import type { AttackEventView, LiveState, PausedReason } from "@garnetops/core/attack-live";
import type { Grade, GradeRule } from "@garnetops/core/grades";
import type { HomeLocation } from "@garnetops/core/home-location";

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

/* Servers (ADR 0011) */

export type HostKeyStatus = "pending" | "confirmed" | "changed";
export type RunState = "queued" | "running" | "succeeded" | "failed";

export interface HostRow extends GradeFields {
  id: string;
  name: string;
  address: string;
  port: number;
  sshUser: string;
  /** "manual", "csv", "proxmox" or "wazuh". */
  source: string;
  /** The Wazuh agent this server is linked to (ADR 0015), if any. */
  wazuh: { agentId: string; agentName: string; status: string; connectionName: string } | null;
  /** The Proxmox guest this server was created from (ADR 0012), if it is still known. */
  proxmox: {
    guestId: string;
    clusterId: string;
    clusterName: string;
    vmid: number;
    type: "qemu" | "lxc";
    name: string;
    status: string;
  } | null;
  hostKey: {
    status: HostKeyStatus;
    type: string | null;
    fingerprint: string | null;
    confirmedAt: string | null;
    /** The key waiting for an admin's confirmation (first contact, or after a change). */
    candidate: { type: string | null; fingerprint: string; seenAt: string | null } | null;
  };
  os: { id: string | null; versionId: string | null; name: string | null };
  kernel: string | null;
  arch: string | null;
  packageCount: number | null;
  pendingUpdates: number | null;
  securityUpdates: number | null;
  lastInventoryAt: string | null;
  /** Short, safe text of the last failure (packages/core host-errors.ts). */
  lastError: string | null;
  open: SeverityCounts;
  run: {
    id: string;
    state: RunState;
    trigger: "manual" | "schedule" | "setup";
    error: string | null;
    createdAt: string;
    finishedAt: string | null;
  } | null;
  createdAt: string;
}

export interface HostDetail extends HostRow {
  states: Partial<Record<"open" | "resolved", number>>;
}

export interface HostPackageRow {
  id: string;
  name: string;
  version: string;
  arch: string | null;
  type: "deb" | "rpm" | "apk";
  origin: string | null;
  upgradableTo: string | null;
  securityUpdate: boolean;
}

export interface HostFindingRow {
  id: string;
  severity: Severity;
  state: "open" | "resolved";
  packageName: string;
  packageVersion: string;
  packageType: string;
  fixedIn: string[] | null;
  vulnerabilityId: string;
  knownExploited: boolean;
  cvssScore: number | null;
  epss: number | null;
  publishedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface HostRunRow {
  id: string;
  state: RunState;
  trigger: "manual" | "schedule" | "setup";
  packageCount: number | null;
  pendingUpdates: number | null;
  newFindings: number | null;
  resolvedFindings: number | null;
  severityCounts: Record<string, number> | null;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

export interface HostAccess {
  ready: boolean;
  publicKey?: string;
  fingerprint?: string;
  /** The source addresses last used for a setup script. */
  allowedSource?: string | null;
}

export interface HostImportResult {
  created: { id: string; line: number; address: string; name: string }[];
  skipped: { line: number; address: string; reason: "duplicate" | "limit" }[];
  invalid: { line: number; address: string; errors: { field: string; code: string }[] }[];
}

/* Proxmox VE (ADR 0012) */

export type ProxmoxFlag = "stoppedLong" | "noRecentBackup" | "oldSnapshot" | "untracked";
export type GuestStatus = "running" | "stopped" | "paused" | "other";

export interface ProxmoxCluster {
  id: string;
  name: string;
  apiUrl: string;
  host: string;
  port: number;
  /** Owners and admins only. */
  tokenId: string | null;
  enabled: boolean;
  certificate: {
    status: "pending" | "confirmed" | "changed";
    fingerprint: string | null;
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    confirmedAt: string | null;
    candidate: {
      fingerprint: string;
      subject: string | null;
      issuer: string | null;
      validFrom: string | null;
      validTo: string | null;
      caTrusted: boolean | null;
      seenAt: string | null;
    } | null;
  };
  privileges: {
    extra: string[];
    acknowledged: boolean;
    acknowledgedAt: string | null;
    checkedAt: string | null;
  };
  version: string | null;
  clusterName: string | null;
  quorate: boolean | null;
  backupsReadable: boolean;
  lastSyncAt: string | null;
  lastError: string | null;
  counts: {
    guests: number;
    running: number;
    templates: number;
    stale: number;
    untracked: number;
    nodes: number;
    online: number;
    withUpdates: number;
    updates: number;
  };
  run: {
    id: string;
    state: RunState;
    trigger: "manual" | "schedule" | "setup";
    error: string | null;
    warnings: string[];
    createdAt: string;
    finishedAt: string | null;
  } | null;
  createdAt: string;
}

export interface ProxmoxClusters {
  syncIntervalMinutes: number;
  thresholds: { stoppedDays: number; backupDays: number; snapshotDays: number };
  items: ProxmoxCluster[];
}

export interface ProxmoxNode {
  id: string;
  clusterId: string;
  clusterName: string;
  name: string;
  online: boolean;
  cpu: number | null;
  cpus: number | null;
  mem: number | null;
  maxMem: number | null;
  disk: number | null;
  maxDisk: number | null;
  uptime: number | null;
  pveVersion: string | null;
  kernel: string | null;
  pendingUpdates: number | null;
  guests: number;
  lastSeenAt: string | null;
}

export interface ProxmoxStorage {
  id: string;
  clusterId: string;
  clusterName: string;
  node: string;
  name: string;
  type: string | null;
  content: string[];
  shared: boolean;
  status: string | null;
  used: number | null;
  total: number | null;
}

export interface ProxmoxGuest {
  id: string;
  clusterId: string;
  clusterName: string;
  vmid: number;
  type: "qemu" | "lxc";
  name: string;
  node: string;
  status: GuestStatus;
  statusSince: string | null;
  cpu: number | null;
  cpus: number | null;
  mem: number | null;
  maxMem: number | null;
  disk: number | null;
  maxDisk: number | null;
  uptime: number | null;
  ostype: string | null;
  tags: string[];
  template: boolean;
  haState: string | null;
  backup: { inJob: boolean | null; lastAt: string | null; readable: boolean };
  snapshots: { count: number | null; newestAt: string | null; oldestAt: string | null };
  ips: string[];
  flags: ProxmoxFlag[];
  server: { id: string; name: string } | null;
  lastSeenAt: string | null;
}

export interface ProxmoxRun {
  id: string;
  state: RunState;
  trigger: "manual" | "schedule" | "setup";
  nodeCount: number | null;
  guestCount: number | null;
  requestCount: number | null;
  warnings: string[];
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

/* UniFi (ADR 0022) */

export type UnifiDeviceFlag = "offline" | "updateAvailable";
export type UnifiFirmware = "updateAvailable" | "current" | "unknown";
export type IpsState = "live" | "waiting" | "paused" | "off";
export type IpsPausedReason = "disabled" | "certificate" | "credentials" | "no-sync" | "rights";

export interface UnifiIps {
  enabled: boolean;
  /** Owners and admins only. */
  username: string | null;
  hasPassword: boolean;
  intervalSeconds: number;
  /** Rights beyond viewing that the last login reported; the preview does not poll until they are acknowledged. */
  rights: { reported: string[]; acknowledged: boolean; acknowledgedAt: string | null };
  state: IpsState;
  reason: IpsPausedReason | null;
  error: string | null;
  lastPollAt: string | null;
  lastEventAt: string | null;
  enabledAt: string | null;
}

/** The state of the IPS preview over all consoles, as the Attacks page and the stream give it. */
export interface UnifiLiveInfo {
  enabled: boolean;
  state: IpsState;
  reason: IpsPausedReason | null;
  error: string | null;
  lastEventAt: string | null;
  lastPollAt: string | null;
  connections: number;
}

export interface UnifiConnection {
  id: string;
  name: string;
  apiUrl: string;
  host: string;
  port: number;
  apiBase: "auto" | "unifi-os" | "network-app";
  enabled: boolean;
  hasKey: boolean;
  certificate: {
    status: "pending" | "confirmed" | "changed";
    fingerprint: string | null;
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    confirmedAt: string | null;
    candidate: {
      fingerprint: string;
      subject: string | null;
      issuer: string | null;
      validFrom: string | null;
      validTo: string | null;
      caTrusted: boolean | null;
      seenAt: string | null;
    } | null;
  };
  version: string | null;
  lastSyncAt: string | null;
  lastError: string | null;
  counts: {
    sites: number;
    clients: number | null;
    devices: number;
    online: number;
    offline: number;
    updatable: number;
  };
  ips: UnifiIps;
  run: {
    id: string;
    state: RunState;
    trigger: "manual" | "schedule" | "setup";
    error: string | null;
    warnings: string[];
    createdAt: string;
    finishedAt: string | null;
  } | null;
  createdAt: string;
}

export interface UnifiConnections {
  syncIntervalMinutes: number;
  ips: { intervalSeconds: { min: number; max: number; default: number } };
  items: UnifiConnection[];
}

export interface UnifiDevice {
  id: string;
  connectionId: string;
  connectionName: string;
  siteId: string;
  siteName: string;
  name: string;
  model: string | null;
  mac: string | null;
  ip: string | null;
  state: "online" | "offline" | "other";
  rawState: string;
  stateSince: string | null;
  firmwareVersion: string | null;
  firmwareUpdatable: boolean | null;
  latestFirmware: string | null;
  firmware: UnifiFirmware;
  uptimeSec: number | null;
  flags: UnifiDeviceFlag[];
  firstSeenAt: string | null;
  lastSeenAt: string | null;
}

export interface UnifiSite {
  id: string;
  connectionId: string;
  connectionName: string;
  name: string;
  clients: number | null;
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

/* XDR / Wazuh (ADR 0015) */

export type XdrSeverity = "critical" | "high" | "medium" | "low";
export type XdrCounts = Record<XdrSeverity, number>;
export type XdrWindow = "24h" | "7d" | "30d";
export type XdrAgentStatus = "active" | "disconnected" | "never_connected" | "pending" | "unknown";
export type XdrTrust = "pin" | "ca";
export type XdrCertificateStatus = "pending" | "confirmed" | "changed";

export interface XdrCertificate {
  status: XdrCertificateStatus;
  /** The following are only sent to owners and admins. */
  fingerprint?: string | null;
  subject?: string | null;
  issuer?: string | null;
  validFrom?: string | null;
  validTo?: string | null;
  confirmedAt?: string | null;
  candidate?: {
    fingerprint: string;
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    caTrusted: boolean | null;
    seenAt: string | null;
  } | null;
}

export interface XdrEndpoint {
  kind: "manager" | "indexer";
  trust: XdrTrust;
  certificate: XdrCertificate;
  lastError: string | null;
  /** Owners and admins only. */
  apiUrl?: string;
  host?: string;
  port?: number;
  username?: string;
  ca?: { count: number; subjects: string[]; validTo: string | null } | null;
}

export interface XdrRun {
  id: string;
  state: RunState;
  trigger: "manual" | "schedule" | "setup";
  error: string | null;
  warnings: string[];
  agentCount: number | null;
  requestCount: number | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface XdrConnection {
  id: string;
  name: string;
  enabled: boolean;
  dashboardUrl: string | null;
  /** Owners and admins only. */
  enrollmentHost?: string | null;
  adapter: { id: "wazuh4" | "wazuh5"; preview: boolean } | null;
  managerVersion: string | null;
  indexerVersion: string | null;
  endpoints: XdrEndpoint[];
  privileges: {
    extra: string[];
    acknowledged: boolean;
    acknowledgedAt: string | null;
    checkedAt: string | null;
  };
  lastSyncAt: string | null;
  lastError: string | null;
  run: XdrRun | null;
  createdAt: string;
}

export interface XdrConnectionResponse {
  syncIntervalMinutes: number;
  connection: XdrConnection | null;
}

export interface XdrWindowData {
  readAt: string;
  total: number;
  bySeverity: XdrCounts;
  previous: { total: number; bySeverity: XdrCounts } | null;
  tactics: { name: string; count: number }[];
  agents: { agentId: string; name: string; count: number }[];
  fim: number;
}

export interface XdrFimEvent {
  id: string;
  at: string;
  agentId: string;
  agentName: string;
  path: string;
  event: "added" | "modified" | "deleted" | "other";
  level: number | null;
}

export interface XdrOverview {
  connection: XdrConnection | null;
  syncIntervalMinutes?: number;
  syncedAt?: string | null;
  windows?: Partial<Record<XdrWindow, XdrWindowData>>;
  vulnerabilities?: (XdrCounts & { agentsAffected: number; readAt: string }) | null;
  agents?: {
    total: number;
    active: number;
    disconnected: number;
    neverConnected: number;
    pending: number;
    linked: number;
    suggested: number;
  };
  fim?: XdrFimEvent[];
  ai?: { state: "not-configured" | "disabled" } | { state: "ready"; model: string };
}

export interface XdrAgent {
  id: string;
  connectionId: string;
  agentId: string;
  name: string;
  ip: string | null;
  os: { name: string | null; version: string | null; platform: string | null };
  arch: string | null;
  version: string | null;
  status: XdrAgentStatus;
  lastKeepAliveAt: string | null;
  groups: string[];
  registeredAt: string | null;
  isManager: boolean;
  vulnerabilities: XdrCounts | null;
  server: { id: string; name: string } | null;
  suggestion: { hostId: string; hostName: string; reason: "address" | "name" | "hostname" | null } | null;
}

export interface XdrSummary {
  id: string;
  status: "pending" | "running" | "complete" | "failed";
  content: string;
  error: AiError | null;
  model: string | null;
  language: "en" | "de";
  author: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface XdrEnrollment {
  ok: true;
  templatesVersion: number;
  os: string;
  arch: string;
  packageVersion: string | null;
  series: string;
  preview: boolean;
  passwordPlaceholder: boolean;
  steps: { id: "trust" | "repository" | "install" | "start"; shell: "bash" | "powershell"; text: string }[];
  manager: string;
  addressFromApi: boolean;
  managerVersion: string;
}

/* Attack overview (ADR 0016) */

export type AttackWindow = XdrWindow;
export type GeoipKind = "country" | "asn";

export interface GeoipDatasetView {
  kind: GeoipKind;
  active: {
    source: "import" | "download";
    month: string | null;
    rows: number;
    loadedAt: string;
    sha256: string | null;
    stale: boolean;
  } | null;
  lastFailure: { source: "import" | "download"; error: string; at: string } | null;
}

export interface AttackAgent {
  agentId: string;
  name: string;
  count: number;
  hostId: string | null;
}

/** The status of the live attack feed (ADR 0021), as `/attacks/events`, the stream and the overview give it. */
export interface AttackLiveInfo {
  enabled: boolean;
  intervalSeconds: number;
  minLevel: number;
  state: LiveState;
  reason: PausedReason | null;
  error: string | null;
  lastEventAt: string | null;
  lastPollAt: string | null;
}

export type AttackEvent = AttackEventView;
export type { HomeLocation };

export interface AttackEventsAnswer {
  items: AttackEvent[];
  latestSeq: number;
  live: AttackLiveInfo | null;
  /** The IPS preview of UniFi (ADR 0022); null while no console has it switched on. */
  unifi?: UnifiLiveInfo | null;
}

export interface AttackOverview {
  connected: boolean;
  /** Where the globe ends its arcs; null if an admin has not set it. */
  home: HomeLocation | null;
  live: AttackLiveInfo | null;
  unifi?: UnifiLiveInfo | null;
  period: AttackWindow;
  syncedAt: string | null;
  attribution: { text: string; url: string; licenseUrl: string };
  geoip: { datasets: GeoipDatasetView[]; missing: boolean; asnMissing: boolean };
  osint: { enabled: false } | { enabled: true; provider: string; providerName: string };
  retentionDays: number;
  ai: { state: "not-configured" | "disabled" } | { state: "ready"; model: string };
  window: {
    readAt: string;
    attackAlerts: number;
    previousAttackAlerts: number | null;
    distinctSources: number;
    previousDistinctSources: number | null;
    countryCount: number;
    previousCountryCount: number | null;
    /** The addresses listed are the busiest ones; these say how much of the whole they cover. */
    listedAlerts: number;
    listedSources: number;
    countries: { country: string; alerts: number; sources: number; topScore?: number; blocked?: number }[];
    unlocated: { alerts: number; sources: number };
    internal: { alerts: number; sources: number };
    asns: { asn: number | null; org: string | null; alerts: number; sources: number }[];
    agents: AttackAgent[];
    /** Of the listed alerts, the ones a UniFi console blocked (ADR 0022). */
    blockedAlerts?: number;
  } | null;
}

export interface AttackSourceRow {
  ip: string;
  scope: "public" | "internal";
  country: string | null;
  asn: number | null;
  org: string | null;
  count: number;
  /** Of `count`, the events a UniFi console blocked. */
  blocked?: number;
  groups: string[];
  agents: AttackAgent[];
  firstSeen: string | null;
  lastSeen: string | null;
  osint: {
    score: number;
    reports: number;
    lastReportedAt: string | null;
    checkedAt: string;
    pageUrl: string | null;
  } | null;
}

export interface AttackSettings {
  wazuhConnected: boolean;
  home: HomeLocation | null;
  liveFeed:
    | (AttackLiveInfo & {
        limits: {
          intervalSeconds: { min: number; max: number; default: number };
          minLevel: { min: number; max: number; default: number };
        };
      })
    | null;
  retentionDays: number;
  retention: { default: number; min: number; max: number };
  geoip: {
    datasets: GeoipDatasetView[];
    attribution: { text: string; url: string; licenseUrl: string };
    host: string;
    urls: { country: string; asn: string };
    limits: { maxCompressedBytes: number; maxDecompressedBytes: number };
    errors: Record<string, string>;
    download: {
      enabled: boolean;
      enabledAt: string | null;
      lastAttemptAt: string | null;
      lastError: string | null;
    };
  };
  osint: {
    enabled: boolean;
    provider: string | null;
    providers: {
      id: string;
      name: string;
      host: string;
      termsUrl: string;
      termsConfirmed: boolean;
      freeDailyLimit: number;
    }[];
    keySet: boolean;
    topN: number;
    dailyBudget: number;
    limits: {
      topN: { default: number; min: number; max: number };
      dailyBudget: { default: number; min: number; max: number };
      cacheHours: number;
    };
    acknowledgedAt: string | null;
    usageToday: number;
    lastRunAt: string | null;
    lastError: string | null;
  };
}

export interface AttackSummary {
  id: string;
  status: "pending" | "running" | "complete" | "failed";
  content: string;
  error: AiError | null;
  model: string | null;
  language: "en" | "de";
  author: string | null;
  createdAt: string;
  finishedAt: string | null;
}
