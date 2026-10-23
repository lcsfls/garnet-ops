/**
 * The answer of `GET /api/v1/system/status` (ADR 0024). Times are ISO strings. Only numbers, states
 * and short codes: no secret, no output of a tool, no address of an integration. Fields are added,
 * never changed in meaning (AGENTS.md rule 2).
 */
import type {
  BlockReason,
  Freshness,
  IntegrationState,
  ScannerMatch,
  ScannerName,
  StatusLevel,
  VulnDbSource,
  WorkerLiveness,
} from "./system-status.ts";

/**
 * Why something failed or is odd. The page turns `value` into a sentence in the user's language;
 * `family` says which list of sentences it belongs to. A value this version does not know is shown as is.
 */
export interface Reason {
  family:
    | "proxmox"
    | "wazuh"
    | "wazuh-code"
    | "unifi"
    | "exposure"
    | "geoip"
    | "ai"
    | "vulndb-update"
    /** A reason of the status page itself, such as "the directory could not be asked". */
    | "status"
    | "raw";
  value: string;
}

export interface ScannerStatus {
  name: ScannerName;
  level: StatusLevel;
  version: string | null;
  pinned: string;
  match: ScannerMatch;
  problem: "missing" | "unreadable" | "not_configured" | null;
  reportedAt: string | null;
}

export interface ProviderStatus {
  name: string;
  version: string | null;
  capturedAt: string | null;
  records: number | null;
}

export interface BuildProviderStatus {
  name: string;
  level: StatusLevel;
  lastRunAt: string | null;
  result: "ok" | "failed" | "skipped" | null;
  records: number | null;
  durationMs: number | null;
  reason: string | null;
}

export interface GeoipDatasetStatus {
  kind: "country" | "asn";
  level: StatusLevel;
  /** `none`: nothing loaded. */
  state: "loaded" | "none";
  /** `YYYY-MM` of the DB-IP release. */
  month: string | null;
  ageDays: number | null;
  freshness: Freshness;
  loadedAt: string | null;
  rows: number | null;
  source: "import" | "download" | null;
  /** The last refused load, if it is newer than the loaded dataset. */
  failure: { source: "import" | "download"; error: string; at: string } | null;
}

/** One connection (a cluster, a console, a channel) that needs a look. */
export interface InstanceStatus {
  name: string;
  state: IntegrationState;
  lastSuccessAt: string | null;
  reason: Reason | null;
  blocked: BlockReason | null;
}

export interface IntegrationPartStatus {
  /** `sync`, `live`, `ips`, `reconcile`, `stage1`, `stage2`, `verification`, `probe`, `delivery`. */
  key: string;
  state: IntegrationState;
  level: StatusLevel;
  lastSuccessAt: string | null;
  lastAttemptAt: string | null;
  /** `true` if the last attempt worked, `false` if it failed, `null` if none was made. */
  lastAttemptOk: boolean | null;
  blocked: BlockReason | null;
  reason: Reason | null;
  /** Counts that explain the state: assets lost, channels failed, the endpoint scope. */
  detail: Record<string, number | string | boolean | null>;
  /** The connections behind the part, worst first, at most five. */
  instances: InstanceStatus[];
}

export type IntegrationKey =
  | "wazuh"
  | "proxmox"
  | "unifi"
  | "directory"
  | "exposure"
  | "ai"
  | "notifications";

export interface IntegrationStatus {
  key: IntegrationKey;
  state: IntegrationState;
  level: StatusLevel;
  configured: boolean;
  /** Connections, channels or assets behind it. */
  count: number;
  parts: IntegrationPartStatus[];
}

export interface QueueStatus {
  name: string;
  level: StatusLevel;
  queued: number;
  active: number;
  failed24h: number;
  oldestQueuedSeconds: number | null;
}

export interface SystemStatus {
  generatedAt: string;
  refreshSeconds: number;
  overall: { level: Exclude<StatusLevel, "inactive">; attention: number; failed: number };
  app: {
    version: string;
    updater: {
      configured: boolean;
      reachable: boolean;
      level: StatusLevel;
      phase: "idle" | "scheduled" | "running" | "succeeded" | "failed" | null;
      latestAvailable: string | null;
    };
  };
  scanners: { level: StatusLevel; items: ScannerStatus[] };
  vulnDb: {
    level: StatusLevel;
    /** False until the worker has reported; the dates then come from the latest scan. */
    reported: boolean;
    freshness: Freshness;
    valid: boolean | null;
    problem: "missing" | "invalid" | "unreadable" | null;
    builtAt: string | null;
    ageDays: number | null;
    schemaVersion: string | null;
    source: VulnDbSource | null;
    checkedAt: string | null;
    thresholds: { staleAfterDays: number; outdatedAfterDays: number };
    update: {
      mode: "auto" | "off" | null;
      lastAttemptAt: string | null;
      lastSuccessAt: string | null;
      lastResult: "ok" | "failed" | null;
      reason: Reason | null;
      nextAt: string | null;
    };
    providers: { available: boolean; items: ProviderStatus[] };
  };
  localBuild: {
    level: StatusLevel;
    state: "not_set_up" | "set_up";
    lastBuildAt: string | null;
    providers: BuildProviderStatus[];
  };
  geoip: {
    level: StatusLevel;
    datasets: GeoipDatasetStatus[];
    download: { enabled: boolean; lastAttemptAt: string | null; reason: Reason | null };
  };
  integrations: IntegrationStatus[];
  worker: {
    level: StatusLevel;
    liveness: WorkerLiveness;
    heartbeat: { version: string; startedAt: string; beatAt: string; instances: number } | null;
    queues: { available: boolean; level: StatusLevel; items: QueueStatus[] };
    nightly: {
      enabled: boolean;
      localTime: string;
      timeZone: string;
      lastRun: {
        at: string;
        localDate: string;
        queued: number;
        succeeded: number;
        failed: number;
        pending: number;
      } | null;
      nextAt: string | null;
    };
    database: {
      level: StatusLevel;
      sizeBytes: number | null;
      migrations: { applied: number; expected: number; latest: string | null };
    };
  };
}
