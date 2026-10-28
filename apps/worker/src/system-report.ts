/**
 * What the worker tells the System status page about itself and its tools (ADR 0024).
 *
 * The API never runs a binary and never talks to the worker. This module runs the scanner
 * binaries (`grype version`, `syft version`, `grype db status`, `grype db providers`), reads the
 * vulnerability database's own metadata and counts, and writes numbers, versions and short codes
 * into `system_report` and `worker_heartbeat`. Nothing a tool prints is stored; a failure becomes
 * a code. Nothing here may stop a scan, an update or the worker: every entry point catches its
 * errors and logs the kind of error only.
 */
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { newId } from "@garnetops/core";
import {
  appVersionOf,
  cleanVersion,
  HEARTBEAT_INTERVAL_SECONDS,
  HEARTBEAT_LATE_AFTER_SECONDS,
  parseVersionOutput,
  type ReportKey,
  VULNDB_PROBE_INTERVAL_MINUTES,
  type VulnDbReport,
  type VulnDbUpdateReport,
  vulnDbReportSchema,
  vulnDbUpdateReportSchema,
} from "@garnetops/core/system-status";
import { schema } from "@garnetops/db";
import { eq, sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { CommandError, run } from "./run.ts";
import { scannerHealth } from "./scanner-client.ts";

const VERSION_TIMEOUT_MS = 15_000;
const DB_TOOL_TIMEOUT_MS = 60_000;

/** This process, for the heartbeat. */
const instanceId = newId("wrk");
const startedAt = new Date();
export const workerVersion = appVersionOf(process.env.APP_VERSION);

/* -------------------------------------------------------------------------- */
/* Writing                                                                     */
/* -------------------------------------------------------------------------- */

async function readReport(key: ReportKey): Promise<unknown> {
  const [row] = await db.select().from(schema.systemReport).where(eq(schema.systemReport.key, key)).limit(1);
  return row?.data ?? null;
}

/** Replaces the report under `key`. */
async function writeReport(key: ReportKey, data: unknown): Promise<void> {
  await db
    .insert(schema.systemReport)
    .values({ key, data, reportedAt: new Date() })
    .onConflictDoUpdate({ target: schema.systemReport.key, set: { data, reportedAt: new Date() } });
}

/** Adds entries to the report under `key` without touching the others (two scans may report at once). */
async function mergeReport(key: ReportKey, entries: Record<string, unknown>): Promise<void> {
  await db
    .insert(schema.systemReport)
    .values({ key, data: entries, reportedAt: new Date() })
    .onConflictDoUpdate({
      target: schema.systemReport.key,
      set: {
        data: sql`coalesce(${schema.systemReport.data}, '{}'::jsonb) || ${JSON.stringify(entries)}::jsonb`,
        reportedAt: new Date(),
      },
    });
}

/** Runs a report step so that no error escapes: the worker's real work never depends on it. */
async function quietly(what: string, step: () => Promise<void>): Promise<void> {
  try {
    await step();
  } catch (error) {
    console.error(`system report (${what}): ${(error as Error)?.name ?? "error"}`);
  }
}

/* -------------------------------------------------------------------------- */
/* Scanner versions                                                            */
/* -------------------------------------------------------------------------- */

/** The environment of a scanner call that only reads local metadata: no network, no update checks. */
function toolEnv(home: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: home,
    USERPROFILE: home,
    TMP: home,
    TEMP: home,
    GRYPE_DB_CACHE_DIR: env.GARNETOPS_GRYPE_DB_DIR,
    GRYPE_DB_AUTO_UPDATE: "false",
    GRYPE_CHECK_FOR_APP_UPDATE: "false",
    SYFT_CHECK_FOR_APP_UPDATE: "false",
    // The page applies its own limits to the age (3 and 7 days), and grype would otherwise call a database
    // older than 5 days invalid, and hash the whole file on every call.
    GRYPE_DB_VALIDATE_AGE: "false",
    GRYPE_DB_VALIDATE_BY_HASH_ON_START: "false",
  };
}

type ScannerEntry = {
  version: string | null;
  reportedAt: string;
  problem: "missing" | "unreadable" | "not_configured" | null;
};

async function versionOf(bin: string | undefined): Promise<ScannerEntry> {
  const reportedAt = new Date().toISOString();
  if (!bin) return { version: null, reportedAt, problem: "not_configured" };
  try {
    const { stdout } = await run(bin, ["version"], {
      env: toolEnv(env.GARNETOPS_WORK_DIR),
      timeoutMs: VERSION_TIMEOUT_MS,
    });
    const version = parseVersionOutput(stdout);
    return { version, reportedAt, problem: version ? null : "unreadable" };
  } catch (error) {
    const missing = error instanceof CommandError && error.exitCode === null && /ENOENT/.test(error.message);
    return { version: null, reportedAt, problem: missing ? "missing" : "unreadable" };
  }
}

/** Runs `grype version` and `syft version` and reports what the binaries say. Called when the worker starts. */
export async function reportScannerVersions(): Promise<void> {
  await quietly("scanners", async () => {
    const [grype, syft] = await Promise.all([
      versionOf(env.GARNETOPS_GRYPE_BIN),
      versionOf(env.GARNETOPS_SYFT_BIN),
    ]);
    await mergeReport("scanners", { grype, syft });
  });
}

/** How long the worker waits at its start for the scanner service, which starts next to it. */
const SCANNER_START_WAIT_MS = 60_000;

/**
 * Reports where syft and grype run (ADR 0028) and, with the scanner service, whether it answers its
 * health check and which release it runs. Called when the worker starts (then it waits a while for
 * the service to come up), with every database probe, and when a scan could not reach the service.
 */
export async function reportScannerIsolation(options: { waitForStart?: boolean } = {}): Promise<void> {
  await quietly("isolation", async () => {
    const socket = env.GARNETOPS_SCANNER_SOCKET;
    let health = socket ? await scannerHealth(socket) : null;
    const deadline = Date.now() + SCANNER_START_WAIT_MS;
    while (socket && !health && options.waitForStart && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      health = await scannerHealth(socket);
    }
    const isolation = {
      mode: socket ? "service" : "worker",
      reachable: socket ? health !== null : null,
      version: health?.version ?? null,
      reportedAt: new Date().toISOString(),
    };
    await mergeReport("scanners", { isolation });
  });
}

/**
 * Reports the versions a scan's own output named (grype's report and syft's SBOM carry the version
 * of the binary that made them). Called after every successful scan.
 */
export async function reportScanFacts(facts: {
  grypeVersion?: string | null;
  syftVersion?: string | null;
}): Promise<void> {
  await quietly("scan", async () => {
    const reportedAt = new Date().toISOString();
    const entries: Record<string, ScannerEntry> = {};
    const grype = cleanVersion(facts.grypeVersion);
    const syft = cleanVersion(facts.syftVersion);
    if (grype) entries.grype = { version: grype, reportedAt, problem: null };
    if (syft) entries.syft = { version: syft, reportedAt, problem: null };
    if (Object.keys(entries).length > 0) await mergeReport("scanners", entries);
  });
}

/* -------------------------------------------------------------------------- */
/* The vulnerability database                                                  */
/* -------------------------------------------------------------------------- */

const statusOutput = z.object({
  schemaVersion: z.string().optional(),
  built: z.string().optional(),
  path: z.string().optional(),
  valid: z.boolean().optional(),
});
const providersOutput = z.array(
  z.object({
    name: z.string().min(1).max(100),
    version: z.string().max(40).optional(),
    dateCaptured: z.string().optional(),
  }),
);

const toIso = (value: string | undefined): string | null => {
  if (!value) return null;
  const date = new Date(value);
  // grype prints the zero time for "never built".
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000 ? null : date.toISOString();
};

/** Advisories per provider, from the database file opened read-only. Null when it cannot be counted. */
function countByProvider(file: string): Map<string, number> | null {
  let sqlite: DatabaseSync | null = null;
  try {
    sqlite = new DatabaseSync(file, { readOnly: true });
    const counts = new Map<string, number>();
    for (const row of sqlite
      .prepare("select provider_id as name, count(*) as n from vulnerability_handles group by provider_id")
      .all()) {
      counts.set(String(row.name), Number(row.n));
    }
    return counts;
  } catch {
    return null;
  } finally {
    sqlite?.close();
  }
}

/** Counting walks an index over every advisory; once per database is enough. */
let countCache: { key: string; counts: Map<string, number> | null } | null = null;

/**
 * Reads what the database file says about itself: `grype db status -o json` (schema, build time,
 * validity), `grype db providers -o json` (the feeds in it) and, read-only, the number of
 * advisories per provider. All of it is local; none of it touches the network. grype exposes no
 * count itself, so the count is a `select count(*)` over the provider column grype indexes.
 */
export async function probeVulnDb(): Promise<void> {
  await quietly("vulndb", async () => {
    const checkedAt = new Date().toISOString();
    const source = env.GARNETOPS_GRYPE_DB_UPDATE === "auto" ? "anchore" : "manual";
    const base = { checkedAt, source } as const;
    const options = { env: toolEnv(env.GARNETOPS_WORK_DIR), timeoutMs: DB_TOOL_TIMEOUT_MS };

    let report: VulnDbReport;
    let status: z.infer<typeof statusOutput>;
    try {
      const { stdout } = await run(env.GARNETOPS_GRYPE_BIN, ["db", "status", "-o", "json"], options);
      status = statusOutput.parse(JSON.parse(stdout));
    } catch (error) {
      // grype exits with 1 when there is no usable database; its words are not kept.
      const problem =
        error instanceof CommandError && /does not exist/.test(error.stderr)
          ? "missing"
          : error instanceof CommandError && error.exitCode === 1
            ? "invalid"
            : "unreadable";
      report = {
        ...base,
        valid: false,
        problem,
        schemaVersion: null,
        builtAt: null,
        providers: { available: false, items: [] },
      };
      await writeReport("vulndb", vulnDbReportSchema.parse(report));
      return;
    }

    const builtAt = toIso(status.built);
    let providers: VulnDbReport["providers"] = { available: false, items: [] };
    try {
      const { stdout } = await run(env.GARNETOPS_GRYPE_BIN, ["db", "providers", "-o", "json"], options);
      const listed = providersOutput.parse(JSON.parse(stdout));
      const key = `${builtAt ?? ""}|${status.path ?? ""}`;
      if (countCache?.key !== key) {
        const file = status.path || join(env.GARNETOPS_GRYPE_DB_DIR, "6", "vulnerability.db");
        countCache = { key, counts: countByProvider(file) };
      }
      const counts = countCache.counts;
      providers = {
        available: true,
        items: listed.slice(0, 200).map((p) => ({
          name: p.name,
          version: p.version?.slice(0, 40) || null,
          capturedAt: toIso(p.dateCaptured),
          records: counts?.get(p.name) ?? null,
        })),
      };
    } catch {
      // The providers are a detail; the database itself is fine.
    }

    report = {
      ...base,
      valid: status.valid !== false,
      problem: status.valid === false ? "invalid" : null,
      schemaVersion: status.schemaVersion?.slice(0, 40) || null,
      builtAt,
      providers,
    };
    await writeReport("vulndb", vulnDbReportSchema.parse(report));
  });
}

/**
 * Merges a change into the report of the automatic update. The update loop is the only writer, so
 * reading, merging and writing needs no lock.
 */
export async function reportVulnDbUpdate(
  patch: Partial<VulnDbUpdateReport> & { mode: "auto" | "off" },
): Promise<void> {
  await quietly("vulndb update", async () => {
    const previous = vulnDbUpdateReportSchema.safeParse(await readReport("vulndb_update"));
    const empty: VulnDbUpdateReport = {
      mode: patch.mode,
      lastAttemptAt: null,
      lastSuccessAt: null,
      lastResult: null,
      reason: null,
      nextAt: null,
    };
    await writeReport("vulndb_update", { ...(previous.success ? previous.data : empty), ...patch });
  });
}

/* -------------------------------------------------------------------------- */
/* Heartbeat                                                                   */
/* -------------------------------------------------------------------------- */

async function beat(): Promise<void> {
  await db
    .insert(schema.workerHeartbeat)
    .values({ instanceId, version: workerVersion, startedAt, beatAt: new Date() })
    .onConflictDoUpdate({
      target: schema.workerHeartbeat.instanceId,
      set: { version: workerVersion, beatAt: new Date() },
    });
}

/**
 * Writes the worker's heartbeat now and every 30 seconds, and removes the rows of workers that
 * stopped. Returns a function that stops the beat and removes this worker's row, so a clean stop
 * shows at once instead of after three missed beats.
 */
export function startHeartbeat(): () => Promise<void> {
  void quietly("heartbeat cleanup", async () => {
    await db
      .delete(schema.workerHeartbeat)
      .where(
        sql`${schema.workerHeartbeat.beatAt} < now() - ${`${HEARTBEAT_LATE_AFTER_SECONDS} seconds`}::interval`,
      );
  }).then(() => quietly("heartbeat", beat));
  const timer = setInterval(() => void quietly("heartbeat", beat), HEARTBEAT_INTERVAL_SECONDS * 1000);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await quietly("heartbeat stop", async () => {
      await db.delete(schema.workerHeartbeat).where(eq(schema.workerHeartbeat.instanceId, instanceId));
    });
  };
}

/**
 * Everything the worker reports on its own: the heartbeat, the scanner versions and the database
 * metadata, the last two read again every 15 minutes so an import by hand shows up without a restart.
 */
export function startSystemReports(): () => Promise<void> {
  const stopHeartbeat = startHeartbeat();
  void reportScannerVersions();
  void reportScannerIsolation({ waitForStart: true });
  void probeVulnDb();
  const timer = setInterval(() => {
    void probeVulnDb();
    void reportScannerIsolation();
  }, VULNDB_PROBE_INTERVAL_MINUTES * 60_000);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await stopHeartbeat();
  };
}
