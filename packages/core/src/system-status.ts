/**
 * The System status page (ADR 0024): thresholds, state mapping and the shapes of what the worker
 * reports into the database. Pure functions and constants, no Node-only imports: the API computes
 * with them, the worker writes the shapes and the web app shows the result.
 *
 * Nothing here is proof of anything. "Current" is a neutral state (AGENTS.md rule 6); green is
 * reserved for results that prove something, such as a passed gate.
 */
import { z } from "zod";

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The scanner versions this release ships and checks (`scripts/fetch-scanners.mjs` pins them with
 * SHA-256 checksums; a test keeps both in step). A different version is shown, not refused.
 */
export const PINNED_SCANNERS = { grype: "0.120.1", syft: "1.55.0" } as const;
export type ScannerName = keyof typeof PINNED_SCANNERS;
export const SCANNER_NAMES = Object.keys(PINNED_SCANNERS) as ScannerName[];

/**
 * Staleness of the vulnerability database. Anchore publishes a new one every day, so a database
 * that is more than 3 days old has missed updates (amber) and one that is more than 7 days old
 * is outdated (vermilion). Scanning with it stays allowed; the page says so.
 */
export const VULNDB_STALE_AFTER_DAYS = 3;
export const VULNDB_OUTDATED_AFTER_DAYS = 7;

/**
 * Staleness of the GeoIP datasets. DB-IP publishes one release per month; the dataset's date is the
 * first day of its month, so a normal one is up to about a month old. Amber after 45 days (a
 * month was skipped), vermilion after 90.
 */
export const GEOIP_STALE_AFTER_DAYS = 45;
export const GEOIP_OUTDATED_AFTER_DAYS = 90;

/** The worker writes its heartbeat this often and is "late" after three missed beats. */
export const HEARTBEAT_INTERVAL_SECONDS = 30;
export const HEARTBEAT_LATE_AFTER_SECONDS = 3 * HEARTBEAT_INTERVAL_SECONDS;
/** Heartbeats of workers that stopped long ago are removed. */
export const HEARTBEAT_KEEP_DAYS = 7;

/** The worker updates the vulnerability database this often when automatic updates are on. */
export const VULNDB_UPDATE_INTERVAL_HOURS = 24;
/** The worker reads the database's own metadata this often, so a manual import shows up. */
export const VULNDB_PROBE_INTERVAL_MINUTES = 15;

/** A sync that has not worked for this many of its own intervals is stale. */
export const SYNC_STALE_AFTER_INTERVALS = 3;

/** The page asks again this often while it is visible. */
export const STATUS_REFRESH_SECONDS = 60;

/** A queued job that has waited this long (seconds) is worth a look. */
export const QUEUE_WAIT_ATTENTION_SECONDS = 15 * 60;

const DAY_MS = 86_400_000;

/* -------------------------------------------------------------------------- */
/* Levels and states                                                           */
/* -------------------------------------------------------------------------- */

/**
 * How much a row needs the reader:
 * - `ok`: as expected (neutral, never green);
 * - `attention`: stale, blocked or waiting for an admin (amber);
 * - `failed`: broken (vermilion, with an icon and a word);
 * - `inactive`: not configured, paused or planned (neutral).
 */
export const STATUS_LEVELS = ["ok", "attention", "failed", "inactive"] as const;
export type StatusLevel = (typeof STATUS_LEVELS)[number];

const LEVEL_RANK: Record<StatusLevel, number> = { inactive: 0, ok: 1, attention: 2, failed: 3 };

/** The worst of several levels; `inactive` when there are none. */
export function worstLevel(levels: readonly StatusLevel[]): StatusLevel {
  return levels.reduce<StatusLevel>(
    (worst, l) => (LEVEL_RANK[l] > LEVEL_RANK[worst] ? l : worst),
    "inactive",
  );
}

/** Overall verdict of the page: inactive rows do not count, and nothing to report is `ok`. */
export function overallLevel(levels: readonly StatusLevel[]): Exclude<StatusLevel, "inactive"> {
  const worst = worstLevel(levels);
  return worst === "inactive" ? "ok" : worst;
}

/* -------------------------------------------------------------------------- */
/* Age and freshness                                                           */
/* -------------------------------------------------------------------------- */

const toDate = (value: Date | string | null | undefined): Date | null => {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

/** Whole days from `from` to `now`; 0 for a moment in the future; null if `from` is unknown. */
export function ageDays(from: Date | string | null | undefined, now: Date): number | null {
  const date = toDate(from);
  if (!date) return null;
  return Math.max(0, Math.floor((now.getTime() - date.getTime()) / DAY_MS));
}

export const FRESHNESS = ["current", "stale", "outdated", "unknown"] as const;
export type Freshness = (typeof FRESHNESS)[number];

/**
 * Compares the age of a dataset with two limits in days. Exactly at a limit still counts as
 * the better state: "older than 3 days" is stale.
 */
export function freshnessOf(
  date: Date | string | null | undefined,
  now: Date,
  staleAfterDays: number,
  outdatedAfterDays: number,
): Freshness {
  const at = toDate(date);
  if (!at) return "unknown";
  const age = now.getTime() - at.getTime();
  if (age > outdatedAfterDays * DAY_MS) return "outdated";
  if (age > staleAfterDays * DAY_MS) return "stale";
  return "current";
}

export const vulnDbFreshness = (builtAt: Date | string | null | undefined, now: Date): Freshness =>
  freshnessOf(builtAt, now, VULNDB_STALE_AFTER_DAYS, VULNDB_OUTDATED_AFTER_DAYS);

export const geoipFreshness = (date: Date | string | null | undefined, now: Date): Freshness =>
  freshnessOf(date, now, GEOIP_STALE_AFTER_DAYS, GEOIP_OUTDATED_AFTER_DAYS);

export function levelOfFreshness(freshness: Freshness): StatusLevel {
  if (freshness === "current") return "ok";
  if (freshness === "outdated") return "failed";
  return "attention";
}

/** The first day (UTC) of a `YYYY-MM` dataset month, or null for anything else. */
export function monthStart(month: string | null | undefined): Date | null {
  const match = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(month ?? "");
  return match ? new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, 1)) : null;
}

/* -------------------------------------------------------------------------- */
/* Scanners                                                                    */
/* -------------------------------------------------------------------------- */

export const SCANNER_MATCHES = ["match", "differs", "unknown"] as const;
export type ScannerMatch = (typeof SCANNER_MATCHES)[number];

/** A version as the tools print it: without a leading "v". */
export const cleanVersion = (value: string | null | undefined): string | null => {
  const v = (value ?? "").trim().replace(/^v(?=\d)/i, "");
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/.test(v) ? v : null;
};

export function scannerMatch(name: ScannerName, version: string | null | undefined): ScannerMatch {
  const v = cleanVersion(version);
  if (!v) return "unknown";
  return v === PINNED_SCANNERS[name] ? "match" : "differs";
}

/** Level of one scanner row: a missing or unreadable binary fails, a different version needs a look. */
export function scannerLevel(match: ScannerMatch, problem: string | null): StatusLevel {
  if (problem === "not_configured") return "inactive";
  if (problem) return "failed";
  if (match === "match") return "ok";
  return "attention";
}

/** `Version: 1.2.3` out of the text `grype version` and `syft version` print. */
export function parseVersionOutput(output: string): string | null {
  const match = /^Version:\s+(\S+)\s*$/m.exec(output);
  return cleanVersion(match?.[1]);
}

/**
 * The running build's version. Release images bake it in at build time, so it always names the
 * code that runs; builds without a version (development, tests) report the current 0.0.1 alpha.
 */
export function appVersionOf(value: string | undefined): string {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value ?? "") ? (value as string) : "0.0.1";
}

/* -------------------------------------------------------------------------- */
/* Worker                                                                      */
/* -------------------------------------------------------------------------- */

export const WORKER_LIVENESS = ["running", "late", "missing"] as const;
export type WorkerLiveness = (typeof WORKER_LIVENESS)[number];

export function workerLiveness(beatAt: Date | string | null | undefined, now: Date): WorkerLiveness {
  const at = toDate(beatAt);
  if (!at) return "missing";
  const seconds = (now.getTime() - at.getTime()) / 1000;
  return seconds > HEARTBEAT_LATE_AFTER_SECONDS ? "late" : "running";
}

export const levelOfWorker = (liveness: WorkerLiveness): StatusLevel =>
  liveness === "running" ? "ok" : "failed";

/** Level of one queue: failed jobs in the last 24 hours or a long wait need a look. */
export function queueLevel(q: { failed24h: number; oldestQueuedSeconds: number | null }): StatusLevel {
  if (q.failed24h > 0) return "attention";
  if ((q.oldestQueuedSeconds ?? 0) > QUEUE_WAIT_ATTENTION_SECONDS) return "attention";
  return "ok";
}

/* -------------------------------------------------------------------------- */
/* Integrations                                                                */
/* -------------------------------------------------------------------------- */

/** What stops an integration until an admin acts. */
export const BLOCK_REASONS = [
  "certificate",
  "privileges",
  "credentials",
  "verification",
  "acknowledgement",
] as const;
export type BlockReason = (typeof BLOCK_REASONS)[number];

export const INTEGRATION_STATES = [
  "not_configured",
  "paused",
  "blocked",
  "failed",
  "stale",
  "waiting",
  "current",
] as const;
export type IntegrationState = (typeof INTEGRATION_STATES)[number];

/** Worst first. */
const STATE_RANK: Record<IntegrationState, number> = {
  not_configured: 0,
  paused: 1,
  current: 2,
  waiting: 3,
  stale: 4,
  blocked: 5,
  failed: 6,
};

export interface IntegrationFacts {
  configured: boolean;
  /** False when an admin switched it off or paused it. */
  enabled: boolean;
  blocked: BlockReason | null;
  lastSuccessAt: Date | string | null;
  /** `true` if the last attempt worked, `false` if it failed, `null` if there was none. */
  lastAttemptOk: boolean | null;
  /** How often it should work; null if it runs only on request. */
  expectedEveryMs: number | null;
}

/**
 * The state of one connection. A failure outranks "stale" because it says why; being blocked
 * outranks both because nothing happens until an admin acts.
 */
export function integrationState(facts: IntegrationFacts, now: Date): IntegrationState {
  if (!facts.configured) return "not_configured";
  if (!facts.enabled) return "paused";
  if (facts.blocked) return "blocked";
  if (facts.lastAttemptOk === false) return "failed";
  const success = toDate(facts.lastSuccessAt);
  if (!success) return "waiting";
  if (
    facts.expectedEveryMs !== null &&
    now.getTime() - success.getTime() > SYNC_STALE_AFTER_INTERVALS * facts.expectedEveryMs
  ) {
    return "stale";
  }
  return "current";
}

export function levelOfIntegration(state: IntegrationState): StatusLevel {
  switch (state) {
    case "current":
      return "ok";
    case "failed":
      return "failed";
    case "blocked":
    case "stale":
    case "waiting":
      return "attention";
    default:
      return "inactive";
  }
}

/** The state that stands for several connections: the one that needs the reader most. */
export function worstState(states: readonly IntegrationState[]): IntegrationState {
  return states.reduce<IntegrationState>(
    (worst, s) => (STATE_RANK[s] > STATE_RANK[worst] ? s : worst),
    "not_configured",
  );
}

/* -------------------------------------------------------------------------- */
/* What the worker reports (table `system_report`, ADR 0024)                    */
/* -------------------------------------------------------------------------- */

export const REPORT_KEYS = ["scanners", "vulndb", "vulndb_update", "vulndb_build"] as const;
export type ReportKey = (typeof REPORT_KEYS)[number];

const isoTime = z.string().datetime({ offset: true });
const shortText = (max: number) => z.string().min(1).max(max);

/**
 * `scanners`: the version of each scanner binary, read when the worker starts (`grype version`,
 * `syft version`) and refreshed from the report of every scan. `problem` is a code, never output.
 */
export const scannersReportSchema = z.object({
  grype: z
    .object({
      version: z.string().max(40).nullable(),
      reportedAt: isoTime,
      problem: z.enum(["missing", "unreadable", "not_configured"]).nullable(),
    })
    .optional(),
  syft: z
    .object({
      version: z.string().max(40).nullable(),
      reportedAt: isoTime,
      problem: z.enum(["missing", "unreadable", "not_configured"]).nullable(),
    })
    .optional(),
});
export type ScannersReport = z.infer<typeof scannersReportSchema>;

export const VULNDB_SOURCES = ["anchore", "manual", "local-build"] as const;
export type VulnDbSource = (typeof VULNDB_SOURCES)[number];

/** `vulndb`: what the database file says about itself (`grype db status`, `grype db providers`). */
export const vulnDbReportSchema = z.object({
  checkedAt: isoTime,
  /** False when there is no usable database; then no scan can run. */
  valid: z.boolean(),
  problem: z.enum(["missing", "invalid", "unreadable"]).nullable(),
  schemaVersion: z.string().max(40).nullable(),
  builtAt: isoTime.nullable(),
  source: z.enum(VULNDB_SOURCES),
  providers: z.object({
    /** False when the providers could not be listed (grype failed, or an older database layout). */
    available: z.boolean(),
    items: z
      .array(
        z.object({
          name: shortText(100),
          version: z.string().max(40).nullable(),
          capturedAt: isoTime.nullable(),
          /** Advisories of this provider; null if the database could not be counted cheaply. */
          records: z.number().int().nonnegative().nullable(),
        }),
      )
      .max(200),
  }),
});
export type VulnDbReport = z.infer<typeof vulnDbReportSchema>;

export const VULNDB_UPDATE_REASONS = [
  "network",
  "timeout",
  "checksum",
  "storage",
  "not_started",
  "failed",
] as const;
export type VulnDbUpdateReason = (typeof VULNDB_UPDATE_REASONS)[number];

/** `vulndb_update`: the worker's automatic update (Anchore's published database). */
export const vulnDbUpdateReportSchema = z.object({
  /** `auto`: the worker updates daily. `off`: the operator imports the database. */
  mode: z.enum(["auto", "off"]),
  lastAttemptAt: isoTime.nullable(),
  lastSuccessAt: isoTime.nullable(),
  lastResult: z.enum(["ok", "failed"]).nullable(),
  reason: z.enum(VULNDB_UPDATE_REASONS).nullable(),
  nextAt: isoTime.nullable(),
});
export type VulnDbUpdateReport = z.infer<typeof vulnDbUpdateReportSchema>;

/** A short, safe code for a failed `grype db update`; never the tool's output. */
export function vulnDbUpdateReason(error: { message?: string; stderr?: string } | null): VulnDbUpdateReason {
  const text = `${error?.message ?? ""} ${error?.stderr ?? ""}`.toLowerCase();
  if (text.includes("timed out")) return "timeout";
  if (text.includes("could not start")) return "not_started";
  if (/checksum|digest|signature|hash mismatch/.test(text)) return "checksum";
  if (/no space left|permission denied|read-only file system|disk quota/.test(text)) return "storage";
  if (
    /dial tcp|no such host|connection refused|connection reset|i\/o timeout|tls|eof|network is unreachable|proxy|status code|unexpected status|failed to (?:get|download|fetch)/.test(
      text,
    )
  )
    return "network";
  return "failed";
}

/**
 * `vulndb_build`: the future local build (vunnel and grype-db, ROADMAP). Until a builder writes
 * this report the page says "not set up". The builder reports per provider (the feeds vunnel
 * pulls) and may add fields later: readers ignore what they do not know, and `v` is the version
 * of this shape. Nothing is stored that the page does not show: no feed URLs, no tokens, no output.
 */
export const vulnDbBuildReportSchema = z.object({
  v: z.number().int().min(1),
  /** The builder is installed and switched on. */
  enabled: z.boolean(),
  lastBuildAt: isoTime.nullable().optional(),
  providers: z
    .array(
      z.object({
        name: shortText(100),
        lastRunAt: isoTime.nullable(),
        result: z.enum(["ok", "failed", "skipped"]).nullable(),
        records: z.number().int().nonnegative().nullable(),
        durationMs: z.number().int().nonnegative().nullable(),
        /** A short code such as "network" or "timeout"; never output of a feed. */
        reason: z.string().max(60).nullable(),
      }),
    )
    .max(200),
});
export type VulnDbBuildReport = z.infer<typeof vulnDbBuildReportSchema>;

/** Level of one provider row of the local build. */
export function buildProviderLevel(result: "ok" | "failed" | "skipped" | null): StatusLevel {
  if (result === "failed") return "failed";
  if (result === "ok") return "ok";
  return "attention";
}
