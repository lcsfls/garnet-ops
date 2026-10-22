/**
 * The attack overview in the worker (ADR 0016): the opt-in monthly GeoIP download, the optional
 * OSINT lookups, and the retention sweep. The worker is the only process that talks to the
 * outside for this feature and the only one that opens the OSINT API key.
 *
 * - Nothing leaves the network unless an admin switched it on: with the download off no request is
 *   made at all, and with OSINT off no address is sent anywhere.
 * - Only public addresses are looked up; internal ones are skipped, and no more than the top N
 *   addresses per sync, within a daily budget below the provider's free tier, with results reused
 *   for 24 hours.
 * - Errors are short codes. Nothing the provider or DB-IP sent, and never the key, goes into a log
 *   line, an error or the audit log.
 */
import { newId } from "@garnetops/core";
import {
  canonicalIp,
  DBIP_HOST,
  dbipUrl,
  GEOIP_LIMITS,
  GeoipError,
  type GeoipKind,
  ipScope,
  monthOf,
  monthsSince,
  newParseStats,
  previousMonth,
  readDataset,
} from "@garnetops/core/geoip";
import { OSINT_LIMITS, type OsintErrorCode, type OsintProvider, osintProvider } from "@garnetops/core/osint";
import { open } from "@garnetops/core/vault";
import { GeoipBusyError, importDataset, recordFailure, schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import { httpsGet, type Lookup, OutboundError, type OutboundOptions, readCapped } from "./outbound.ts";

export const ATTACKS_MAINTENANCE_QUEUE = "attacks.maintenance";

/** What a test can replace: the lookup, the certificate and the port of a local HTTPS server, limits and clocks. */
export interface OutboundDeps {
  test?: { lookup?: Lookup; ca?: string; port?: number };
  now?: Date;
  gapMs?: number;
  timeoutMs?: number;
  maxCompressedBytes?: number;
  maxDecompressedBytes?: number;
}

/* -------------------------------------------------------------------------- */
/* GeoIP download (opt-in)                                                     */
/* -------------------------------------------------------------------------- */

/** The earliest the next automatic attempt may follow the last one. */
const DOWNLOAD_RETRY_HOURS = 12;
const DOWNLOAD_TIMEOUT_MS = 5 * 60_000;

type Settings = typeof schema.attackSettings.$inferSelect;

const writeAudit = (
  organizationId: string,
  action: string,
  targetId: string,
  data: Record<string, unknown>,
) =>
  db.insert(schema.auditLog).values({
    organizationId,
    action,
    targetType: "attack_settings",
    targetId,
    data,
  });

/**
 * Downloads one file from DB-IP and loads it. Returns the number of ranges, or null if DB-IP does
 * not have the file (404). Any other problem throws a `GeoipError` or an `OutboundError`.
 */
export async function downloadDataset(
  kind: GeoipKind,
  month: string,
  importedBy: string | null,
  deps: OutboundDeps = {},
): Promise<number | null> {
  const url = new URL(dbipUrl(kind, month));
  const options: OutboundOptions = {
    host: DBIP_HOST,
    path: url.pathname,
    timeoutMs: deps.timeoutMs ?? DOWNLOAD_TIMEOUT_MS,
    ...(deps.test ? { test: deps.test } : {}),
  };
  let response: Awaited<ReturnType<typeof httpsGet>>;
  try {
    response = await httpsGet(options);
  } catch (error) {
    if (error instanceof OutboundError && error.code === "httpStatus" && error.status === 404) return null;
    throw error;
  }
  const declared = Number(response.headers["content-length"] ?? 0);
  const maxCompressed = deps.maxCompressedBytes ?? GEOIP_LIMITS.maxCompressedBytes;
  if (declared > maxCompressed) {
    response.close();
    // Refused before the loader saw it: remember why, the active dataset stays.
    await recordFailure(
      db,
      { kind, source: "download", month, importedBy, stats: newParseStats() },
      "tooLarge",
    ).catch(() => {});
    throw new GeoipError("tooLarge");
  }
  const stats = newParseStats();
  const limits = {
    maxCompressedBytes: maxCompressed,
    ...(deps.maxDecompressedBytes !== undefined ? { maxDecompressedBytes: deps.maxDecompressedBytes } : {}),
  };
  const rows = readDataset(kind, response.body, stats, limits);
  try {
    const result = await importDataset(db, {
      kind,
      source: "download",
      month,
      importedBy,
      rows,
      stats,
      classify: (error) => (error instanceof OutboundError ? downloadErrorCode(error) : null),
    });
    return result.rows;
  } finally {
    response.close();
  }
}

/** The text stored as the reason of a failed attempt: a code, never a message from the outside. */
function downloadErrorCode(error: unknown): string {
  if (error instanceof GeoipError) return error.code;
  if (error instanceof OutboundError) return error.code === "httpStatus" ? "unreachable" : error.code;
  if (error instanceof GeoipBusyError) return "busy";
  return "unexpected";
}

/**
 * One pass of the monthly download for one organisation's settings: for each kind whose active
 * dataset is older than the current month, fetch this month's file (or last month's if DB-IP has
 * not published this month's yet). Does nothing, and sends nothing, unless the download is on.
 */
export async function runGeoipDownload(settings: Settings, deps: OutboundDeps = {}): Promise<void> {
  if (!settings.geoipDownloadEnabled) return;
  const now = deps.now ?? new Date();
  const current = monthOf(now);
  const d = schema.geoipDataset;
  const active = await db.select().from(d).where(eq(d.state, "active"));
  let lastError: string | null = null;
  for (const kind of ["country", "asn"] as const) {
    const have = active.find((x) => x.kind === kind)?.datasetMonth ?? null;
    if (have !== null && have >= current) continue;
    let loaded: { month: string; rows: number } | null = null;
    try {
      for (const month of [current, previousMonth(current)]) {
        if (have !== null && have >= month) break;
        const rows = await downloadDataset(kind, month, settings.geoipDownloadEnabledBy, deps);
        if (rows !== null) {
          loaded = { month, rows };
          break;
        }
      }
      if (loaded) {
        await writeAudit(settings.organizationId, "attacks.geoip_downloaded", settings.organizationId, {
          kind,
          month: loaded.month,
          rows: loaded.rows,
          source: "download",
        });
      } else {
        lastError ??= "notFound";
      }
    } catch (error) {
      const code = downloadErrorCode(error);
      lastError = code;
      if (error instanceof OutboundError) {
        // The connection failed before the loader had anything to store: remember why, the active dataset stays.
        await recordFailure(
          db,
          { kind, source: "download", month: null, importedBy: null, stats: newParseStats() },
          code,
        ).catch(() => {});
      }
      await writeAudit(settings.organizationId, "attacks.geoip_download_failed", settings.organizationId, {
        kind,
        error: code,
        source: "download",
      });
      console.error(`geoip download (${kind}): ${code}`);
    }
  }
  await db
    .update(schema.attackSettings)
    .set({ geoipDownloadLastAttemptAt: now, geoipDownloadLastError: lastError, updatedAt: now })
    .where(eq(schema.attackSettings.organizationId, settings.organizationId));
}

/** Goes through the organisations that switched the download on and are due for an attempt. */
export async function geoipDownloadTick(deps: OutboundDeps = {}): Promise<void> {
  const now = deps.now ?? new Date();
  const a = schema.attackSettings;
  const due = await db
    .select()
    .from(a)
    .where(
      and(
        eq(a.geoipDownloadEnabled, true),
        sql`(${a.geoipDownloadLastAttemptAt} is null or ${a.geoipDownloadLastAttemptAt} < ${new Date(
          now.getTime() - DOWNLOAD_RETRY_HOURS * 3_600_000,
        )})`,
      ),
    );
  for (const settings of due) {
    // One installation-wide dataset: after the first organisation has loaded it, the others find it current.
    await runGeoipDownload(settings, deps).catch((error: Error) =>
      console.error(`geoip download: ${(error as Error)?.name ?? "error"}`),
    );
  }
}

/* -------------------------------------------------------------------------- */
/* OSINT (opt-in)                                                              */
/* -------------------------------------------------------------------------- */

async function openApiKey(settings: Settings): Promise<string | null> {
  if (!settings.osintSecretId) return null;
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, settings.osintSecretId),
        eq(schema.secret.organizationId, settings.organizationId),
        eq(schema.secret.purpose, "osint-api-key"),
      ),
    )
    .limit(1);
  if (!secret) return null;
  const plain = open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose: "osint-api-key" },
    vaultPrivateKey,
  );
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** One request to the provider for one address. Throws an `OutboundError`; returns null if the answer does not fit. */
async function checkOne(provider: OsintProvider, ip: string, key: string, deps: OutboundDeps) {
  const request = provider.request(ip, key);
  const response = await httpsGet({
    host: provider.host,
    path: request.path,
    headers: request.headers,
    timeoutMs: deps.timeoutMs ?? OSINT_LIMITS.timeoutMs,
    connectTimeoutMs: deps.timeoutMs ?? OSINT_LIMITS.timeoutMs,
    ...(deps.test ? { test: deps.test } : {}),
  });
  const bytes = await readCapped(response, OSINT_LIMITS.maxResponseBytes);
  let body: unknown;
  try {
    body = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  return provider.parse(body, ip);
}

export interface OsintRun {
  checked: number;
  cached: number;
  error: OsintErrorCode | null;
}

/**
 * Looks up the busiest public source addresses of an organisation with the provider it chose, if
 * (and only if) OSINT is switched on and acknowledged. Called after every successful Wazuh sync;
 * never throws, never delays a sync's result.
 */
export async function enrichOsint(organizationId: string, deps: OutboundDeps = {}): Promise<OsintRun> {
  const result: OsintRun = { checked: 0, cached: 0, error: null };
  const a = schema.attackSettings;
  const [settings] = await db.select().from(a).where(eq(a.organizationId, organizationId)).limit(1);
  if (!settings?.osintEnabled || !settings.osintAcknowledgedAt) return result;
  const provider = settings.osintProvider ? osintProvider(settings.osintProvider) : null;
  if (!provider) return result;
  const now = deps.now ?? new Date();
  const finish = async (code: OsintErrorCode | null, used: number) => {
    result.error = code;
    await db
      .update(a)
      .set({
        osintLastRunAt: now,
        osintLastError: code,
        osintUsageDay: now.toISOString().slice(0, 10),
        osintUsageCount: used,
        updatedAt: now,
      })
      .where(eq(a.organizationId, organizationId));
  };

  const today = now.toISOString().slice(0, 10);
  let used = settings.osintUsageDay === today ? settings.osintUsageCount : 0;
  const budget = Math.min(settings.osintDailyBudget, provider.freeDailyLimit - 1);

  const key = await openApiKey(settings).catch(() => null);
  if (!key) {
    await finish("credentialsMissing", used);
    return result;
  }

  // The busiest public addresses over all windows, at most N.
  const s = schema.wazuhSourceIp;
  const rows = await db
    .select({ ip: s.ip, count: sql<number>`max(${s.count})::int` })
    .from(s)
    .where(eq(s.organizationId, organizationId))
    .groupBy(s.ip)
    .orderBy(sql`max(${s.count}) desc`, s.ip)
    .limit(500);
  const wanted: string[] = [];
  for (const row of rows) {
    if (wanted.length >= settings.osintTopN) break;
    const ip = canonicalIp(row.ip);
    if (ip && ipScope(ip) === "public" && !wanted.includes(ip)) wanted.push(ip);
  }
  const o = schema.attackOsintResult;
  const fresh = new Date(now.getTime() - OSINT_LIMITS.cacheHours * 3_600_000);
  const cachedRows = wanted.length
    ? await db
        .select({ ip: o.ip, checkedAt: o.checkedAt })
        .from(o)
        .where(and(eq(o.organizationId, organizationId), eq(o.provider, provider.id)))
    : [];
  const cached = new Set(cachedRows.filter((c) => c.checkedAt > fresh).map((c) => c.ip));
  result.cached = wanted.filter((ip) => cached.has(ip)).length;
  const todo = wanted.filter((ip) => !cached.has(ip));

  let failures = 0;
  let fatal: OsintErrorCode | null = null;
  let soft: OsintErrorCode | null = null;
  for (const ip of todo) {
    if (used >= budget) {
      fatal = "budgetReached";
      break;
    }
    try {
      used += 1;
      const answer = await checkOne(provider, ip, key, deps);
      if (!answer) {
        failures += 1;
        soft = "unexpectedAnswer";
      } else {
        failures = 0;
        result.checked += 1;
        await db
          .insert(o)
          .values({
            id: newId("osr"),
            organizationId,
            provider: provider.id,
            ip,
            score: answer.score,
            reports: answer.reports,
            lastReportedAt: answer.lastReportedAt,
            checkedAt: now,
          })
          .onConflictDoUpdate({
            target: [o.organizationId, o.provider, o.ip],
            set: {
              score: answer.score,
              reports: answer.reports,
              lastReportedAt: answer.lastReportedAt,
              checkedAt: now,
            },
          });
      }
    } catch (error) {
      if (error instanceof OutboundError && error.code === "httpStatus") {
        if (error.status === 401 || error.status === 403) {
          fatal = "keyRejected";
          break;
        }
        if (error.status === 429) {
          fatal = "rateLimited";
          break;
        }
      }
      if (error instanceof OutboundError && error.code === "redirected") {
        fatal = "redirected";
        break;
      }
      failures += 1;
      soft = "unreachable";
    }
    if (failures >= 3) break;
    await sleep(deps.gapMs ?? OSINT_LIMITS.gapMs);
  }
  // A few failed addresses among good answers are not a failed run.
  const code: OsintErrorCode | null = fatal ?? (result.checked === 0 && todo.length > 0 ? soft : null);
  await finish(code, used);
  if (code && code !== "budgetReached") console.error(`osint lookup: ${code}`);
  return result;
}

/* -------------------------------------------------------------------------- */
/* Retention                                                                   */
/* -------------------------------------------------------------------------- */

export interface SweepResult {
  sourceAddresses: number;
  attackWindows: number;
  osintResults: number;
  /** Alerts of the live attack feed (ADR 0021), including the threat events of UniFi (ADR 0022). */
  attackEvents: number;
}

/**
 * Deletes what is older than each organisation's retention period (default 90 days): source
 * addresses with their counts, the attack numbers that carry the previous period's addresses,
 * OSINT results and the alerts of the live feed (ADR 0021). The sync replaces these continuously, so in normal operation nothing gets old;
 * this is the backstop for a stopped sync, a removed connection's leftovers and a shortened period.
 */
export async function retentionSweep(now: Date = new Date()): Promise<SweepResult> {
  const days = (organizationColumn: unknown) =>
    sql`coalesce((select ${schema.attackSettings.retentionDays} from ${schema.attackSettings} where ${schema.attackSettings.organizationId} = ${organizationColumn}), 90)`;
  const cutoff = (organizationColumn: unknown) =>
    sql`${now.toISOString()}::timestamptz - make_interval(days => ${days(organizationColumn)})`;
  const s = schema.wazuhSourceIp;
  const w = schema.wazuhAttackWindow;
  const o = schema.attackOsintResult;
  const ev = schema.wazuhAttackEvent;
  const a = await db
    .delete(s)
    .where(sql`${s.seenAt} < ${cutoff(s.organizationId)}`)
    .returning({ id: s.id });
  const b = await db
    .delete(w)
    .where(sql`${w.readAt} < ${cutoff(w.organizationId)}`)
    .returning({ id: w.connectionId });
  const c = await db
    .delete(o)
    .where(sql`${o.checkedAt} < ${cutoff(o.organizationId)}`)
    .returning({ id: o.id });
  const d = await db
    .delete(ev)
    .where(sql`${ev.at} < ${cutoff(ev.organizationId)}`)
    .returning({ id: ev.seq });
  const ufe = schema.unifiThreatEvent;
  const u = await db
    .delete(ufe)
    .where(sql`${ufe.at} < ${cutoff(ufe.organizationId)}`)
    .returning({ id: ufe.seq });
  return {
    sourceAddresses: a.length,
    attackWindows: b.length,
    osintResults: c.length,
    attackEvents: d.length + u.length,
  };
}

/** Whether the installed datasets are older than the stale limit; shown in the UI, computed there too. */
export const datasetIsStale = (month: string | null, now: Date, limit = 3) =>
  month !== null && monthsSince(month, now) > limit;

/* -------------------------------------------------------------------------- */
/* Schedule                                                                    */
/* -------------------------------------------------------------------------- */

/** Hourly: the retention sweep, then the opt-in download if one is due. Errors never stop the other. */
export async function attacksMaintenance(): Promise<void> {
  await retentionSweep().catch((error: Error) => console.error(`retention sweep: ${error?.name ?? "error"}`));
  await geoipDownloadTick().catch((error: Error) => console.error(`geoip tick: ${error?.name ?? "error"}`));
}

export async function startAttacksScheduler(boss: PgBoss): Promise<void> {
  await boss.createQueue(ATTACKS_MAINTENANCE_QUEUE);
  await boss.schedule(ATTACKS_MAINTENANCE_QUEUE, "17 * * * *", null, { tz: "UTC" });
  await boss.work(ATTACKS_MAINTENANCE_QUEUE, { batchSize: 1 }, async () => {
    await attacksMaintenance();
  });
}
