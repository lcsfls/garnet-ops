/**
 * Builds the answer of `GET /api/v1/system/status` (ADR 0024): one read-only view of whether
 * everything is current and running.
 *
 * Everything is read from the database. The API never runs a binary and never talks to the
 * worker or to an integration: the worker writes what the page shows (`worker_heartbeat`,
 * `system_report`, the sync columns of each integration). Only numbers, states and short codes
 * leave this file: no secret, no address of an integration, no output of a tool. The names of
 * connections are the labels an admin gave them, which the settings pages show to admins as well.
 */
import { endpointHost } from "@garnetops/core/ai-endpoint";
import { isExposureError } from "@garnetops/core/exposure";
import { privilegesAcknowledged as proxmoxPrivilegesAcknowledged } from "@garnetops/core/proxmox";
import { PROXMOX_SYNC_INTERVAL_MINUTES } from "@garnetops/core/proxmox-flags";
import {
  ageDays,
  type BlockReason,
  buildProviderLevel,
  geoipFreshness,
  type IntegrationState,
  integrationState,
  levelOfFreshness,
  levelOfIntegration,
  levelOfWorker,
  monthStart,
  overallLevel,
  PINNED_SCANNERS,
  queueLevel,
  SCANNER_NAMES,
  type ScannerName,
  STATUS_REFRESH_SECONDS,
  type StatusLevel,
  scannerLevel,
  scannerMatch,
  scannersReportSchema,
  VULNDB_OUTDATED_AFTER_DAYS,
  VULNDB_STALE_AFTER_DAYS,
  vulnDbBuildReportSchema,
  vulnDbFreshness,
  vulnDbReportSchema,
  vulnDbUpdateReportSchema,
  workerLiveness,
  worstLevel,
  worstState,
} from "@garnetops/core/system-status";
import type {
  InstanceStatus,
  IntegrationPartStatus,
  IntegrationStatus,
  QueueStatus,
  Reason,
  SystemStatus,
} from "@garnetops/core/system-status-view";
import { UNIFI_SYNC_INTERVAL_MINUTES } from "@garnetops/core/unifi";
import {
  WAZUH_SYNC_INTERVAL_MINUTES,
  privilegesAcknowledged as wazuhPrivilegesAcknowledged,
} from "@garnetops/core/wazuh";
import { databaseState, datasetStatus, nextNightlyRun, schema } from "@garnetops/db";
import { and, desc, eq, sql } from "drizzle-orm";
import { db } from "../db.ts";
import { APP_VERSION } from "../version.ts";

const MINUTE = 60_000;
const DAY = 86_400_000;
/** Connections named for the reader per part. */
const MAX_INSTANCES = 5;
/** The directory check runs every 15 minutes (apps/worker/src/directory.ts). */
const DIRECTORY_CHECK_MINUTES = 15;

const iso = (date: Date | null | undefined): string | null => (date ? date.toISOString() : null);
const newest = (dates: (Date | null)[]): Date | null =>
  dates.filter((d): d is Date => d !== null).sort((a, b) => b.getTime() - a.getTime())[0] ?? null;

/* -------------------------------------------------------------------------- */
/* Parts                                                                       */
/* -------------------------------------------------------------------------- */

interface InstanceFacts {
  name: string;
  configured?: boolean;
  enabled: boolean;
  blocked: BlockReason | null;
  lastSuccessAt: Date | null;
  lastAttemptAt: Date | null;
  lastAttemptOk: boolean | null;
  expectedEveryMs: number | null;
  reason: Reason | null;
}

/** One part (a sync, a live feed) over all its connections: the worst state stands for the part. */
function part(
  key: string,
  instances: InstanceFacts[],
  now: Date,
  detail: IntegrationPartStatus["detail"] = {},
): IntegrationPartStatus {
  const rated = instances.map((i) => ({
    i,
    state: integrationState(
      {
        configured: i.configured ?? true,
        enabled: i.enabled,
        blocked: i.blocked,
        lastSuccessAt: i.lastSuccessAt,
        lastAttemptOk: i.lastAttemptOk,
        expectedEveryMs: i.expectedEveryMs,
      },
      now,
    ),
  }));
  const state = worstState(rated.map((r) => r.state));
  const worst = rated.filter((r) => r.state === state);
  const problems = rated
    .filter((r) => r.state !== "current" && r.state !== "paused" && r.state !== "not_configured")
    .sort((a, b) => stateOrder(b.state) - stateOrder(a.state));
  const instancesShown: InstanceStatus[] = problems.slice(0, MAX_INSTANCES).map(({ i, state: s }) => ({
    name: i.name,
    state: s,
    lastSuccessAt: iso(i.lastSuccessAt),
    reason: i.reason,
    blocked: i.blocked,
  }));
  const lead = worst[0]?.i;
  return {
    key,
    state,
    level: levelOfIntegration(state),
    lastSuccessAt: iso(newest(instances.map((i) => i.lastSuccessAt))),
    lastAttemptAt: iso(newest(instances.map((i) => i.lastAttemptAt))),
    lastAttemptOk: lead?.lastAttemptOk ?? null,
    blocked: worst.map((r) => r.i.blocked).find((b) => b !== null) ?? null,
    reason: worst.map((r) => r.i.reason).find((r) => r !== null) ?? null,
    detail: { connections: instances.length, ...detail },
    instances: instancesShown,
  };
}

const STATE_ORDER: IntegrationState[] = [
  "not_configured",
  "paused",
  "current",
  "waiting",
  "stale",
  "blocked",
  "failed",
];
const stateOrder = (state: IntegrationState) => STATE_ORDER.indexOf(state);

/** A part for something that is not set up or switched off as a whole. */
function idlePart(
  key: string,
  state: "not_configured" | "paused",
  detail: IntegrationPartStatus["detail"] = {},
): IntegrationPartStatus {
  return {
    key,
    state,
    level: "inactive",
    lastSuccessAt: null,
    lastAttemptAt: null,
    lastAttemptOk: null,
    blocked: null,
    reason: null,
    detail,
    instances: [],
  };
}

function integration(
  key: IntegrationStatus["key"],
  configured: boolean,
  count: number,
  parts: IntegrationPartStatus[],
): IntegrationStatus {
  if (!configured) {
    return { key, state: "not_configured", level: "inactive", configured: false, count: 0, parts: [] };
  }
  const state = worstState(parts.map((p) => p.state));
  return { key, state, level: levelOfIntegration(state), configured: true, count, parts };
}

/** The last finished sync run of every connection of a run table. */
async function latestRuns(
  table: "proxmox_sync_run" | "unifi_sync_run" | "wazuh_sync_run",
  idColumn: "cluster_id" | "connection_id",
  organizationId: string,
): Promise<Map<string, { ok: boolean; at: Date | null; error: string | null }>> {
  const result = await db.execute<{ id: string; state: string; at: Date | null; error: string | null }>(sql`
    select distinct on (${sql.raw(idColumn)}) ${sql.raw(idColumn)} as id, state, finished_at as at, error
    from ${sql.raw(table)}
    where organization_id = ${organizationId} and state in ('succeeded', 'failed')
    order by ${sql.raw(idColumn)}, finished_at desc nulls last, created_at desc`);
  return new Map(
    result.rows.map((r) => [
      r.id,
      { ok: r.state === "succeeded", at: r.at ? new Date(r.at) : null, error: r.error },
    ]),
  );
}

type RunFact = { ok: boolean; at: Date | null; error: string | null } | undefined;

/** Whether the last attempt worked, from the run table and the connection's own columns. */
function attemptOk(run: RunFact, lastError: string | null, lastSyncAt: Date | null): boolean | null {
  if (run) return run.ok;
  if (lastError) return false;
  return lastSyncAt ? true : null;
}

/* -------------------------------------------------------------------------- */
/* Integrations                                                                */
/* -------------------------------------------------------------------------- */

async function wazuh(organizationId: string, now: Date): Promise<IntegrationStatus> {
  const [connections, endpoints, live, runs] = await Promise.all([
    db.select().from(schema.wazuhConnection).where(eq(schema.wazuhConnection.organizationId, organizationId)),
    db.select().from(schema.wazuhEndpoint).where(eq(schema.wazuhEndpoint.organizationId, organizationId)),
    db.select().from(schema.wazuhLiveState).where(eq(schema.wazuhLiveState.organizationId, organizationId)),
    latestRuns("wazuh_sync_run", "connection_id", organizationId),
  ]);
  const blockedOf = (c: (typeof connections)[number]): BlockReason | null => {
    if (endpoints.some((e) => e.connectionId === c.id && e.certStatus !== "confirmed")) return "certificate";
    if (!wazuhPrivilegesAcknowledged(c.extraPrivileges, c.acknowledgedPrivileges)) return "privileges";
    return null;
  };
  const sync = connections.map((c): InstanceFacts => {
    const run = runs.get(c.id);
    const error = run && !run.ok ? (run.error ?? c.lastError) : c.lastError;
    return {
      name: c.name,
      enabled: c.enabled,
      blocked: blockedOf(c),
      lastSuccessAt: c.lastSyncAt,
      lastAttemptAt: run?.at ?? c.lastSyncAt,
      lastAttemptOk: attemptOk(run, c.lastError, c.lastSyncAt),
      expectedEveryMs: WAZUH_SYNC_INTERVAL_MINUTES * MINUTE,
      reason: error ? { family: "wazuh", value: error } : null,
    };
  });
  const liveFacts = connections.flatMap((c): InstanceFacts[] => {
    const state = live.find((l) => l.connectionId === c.id);
    if (!state) return [];
    const ok = state.lastPollAt ? state.lastError === null : null;
    return [
      {
        name: c.name,
        enabled: c.enabled && state.enabled,
        blocked: blockedOf(c),
        lastSuccessAt: ok ? state.lastPollAt : null,
        lastAttemptAt: state.lastPollAt,
        lastAttemptOk: ok,
        expectedEveryMs: state.intervalSeconds * 1000,
        reason: state.lastError ? { family: "wazuh-code", value: state.lastError } : null,
      },
    ];
  });
  return integration("wazuh", connections.length > 0, connections.length, [
    part("sync", sync, now),
    liveFacts.length > 0 ? part("live", liveFacts, now) : idlePart("live", "not_configured"),
  ]);
}

async function proxmox(organizationId: string, now: Date): Promise<IntegrationStatus> {
  const [clusters, runs] = await Promise.all([
    db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.organizationId, organizationId)),
    latestRuns("proxmox_sync_run", "cluster_id", organizationId),
  ]);
  const sync = clusters.map((c): InstanceFacts => {
    const run = runs.get(c.id);
    const error = run && !run.ok ? (run.error ?? c.lastError) : c.lastError;
    return {
      name: c.name,
      enabled: c.enabled,
      blocked:
        c.certStatus !== "confirmed"
          ? "certificate"
          : !proxmoxPrivilegesAcknowledged(c.extraPrivileges, c.acknowledgedPrivileges)
            ? "privileges"
            : null,
      lastSuccessAt: c.lastSyncAt,
      lastAttemptAt: run?.at ?? c.lastSyncAt,
      lastAttemptOk: attemptOk(run, c.lastError, c.lastSyncAt),
      expectedEveryMs: PROXMOX_SYNC_INTERVAL_MINUTES * MINUTE,
      reason: error ? { family: "proxmox", value: error } : null,
    };
  });
  return integration("proxmox", clusters.length > 0, clusters.length, [part("sync", sync, now)]);
}

async function unifi(organizationId: string, now: Date): Promise<IntegrationStatus> {
  const [connections, runs] = await Promise.all([
    db.select().from(schema.unifiConnection).where(eq(schema.unifiConnection.organizationId, organizationId)),
    latestRuns("unifi_sync_run", "connection_id", organizationId),
  ]);
  const sync = connections.map((c): InstanceFacts => {
    const run = runs.get(c.id);
    const error = run && !run.ok ? (run.error ?? c.lastError) : c.lastError;
    return {
      name: c.name,
      enabled: c.enabled,
      blocked: c.certStatus !== "confirmed" ? "certificate" : null,
      lastSuccessAt: c.lastSyncAt,
      lastAttemptAt: run?.at ?? c.lastSyncAt,
      lastAttemptOk: attemptOk(run, c.lastError, c.lastSyncAt),
      expectedEveryMs: UNIFI_SYNC_INTERVAL_MINUTES * MINUTE,
      reason: error ? { family: "unifi", value: error } : null,
    };
  });
  // The IPS preview is off unless an admin switched it on for a console.
  const ips = connections
    .filter((c) => c.ipsEnabled)
    .map((c): InstanceFacts => {
      const reported = c.ipsRights;
      const acknowledged = new Set(c.ipsRightsAcknowledged);
      const rightsOpen =
        reported.length > 0 &&
        !(reported.length === acknowledged.size && reported.every((r) => acknowledged.has(r)));
      const ok = c.ipsLastPollAt ? c.ipsLastError === null : null;
      return {
        name: c.name,
        enabled: c.enabled,
        blocked: c.certStatus !== "confirmed" ? "certificate" : rightsOpen ? "privileges" : null,
        lastSuccessAt: ok ? c.ipsLastPollAt : null,
        lastAttemptAt: c.ipsLastPollAt,
        lastAttemptOk: ok,
        expectedEveryMs: c.ipsIntervalSeconds * 1000,
        reason: c.ipsLastError ? { family: "unifi", value: c.ipsLastError } : null,
      };
    });
  return integration("unifi", connections.length > 0, connections.length, [
    part("sync", sync, now),
    ips.length > 0 ? part("ips", ips, now) : idlePart("ips", "not_configured"),
  ]);
}

async function directory(organizationId: string, now: Date): Promise<IntegrationStatus> {
  const [config] = await db
    .select()
    .from(schema.ldapConfig)
    .where(eq(schema.ldapConfig.organizationId, organizationId))
    .limit(1);
  if (!config) return integration("directory", false, 0, []);
  const blocked: BlockReason | null =
    config.bindBlockedUntil && config.bindBlockedUntil.getTime() > now.getTime()
      ? "credentials"
      : config.servers.some(
            (s) => s.certStatus === "changed" || (config.tlsTrust === "pin" && s.certStatus !== "confirmed"),
          )
        ? "certificate"
        : null;
  const ran = config.lastReconcileAt !== null;
  const ok = ran ? config.lastReconcileResult === "ok" : null;
  const facts: InstanceFacts = {
    name: "directory",
    enabled: config.enabled,
    blocked,
    lastSuccessAt: ok ? config.lastReconcileAt : null,
    lastAttemptAt: config.lastReconcileAt,
    lastAttemptOk: ok,
    expectedEveryMs: DIRECTORY_CHECK_MINUTES * MINUTE,
    reason: ok === false ? { family: "status", value: "directoryUnreachable" } : null,
  };
  return integration("directory", true, config.servers.length, [
    part("reconcile", [facts], now, { accountsChecked: config.lastReconcileChecked }),
  ]);
}

async function exposure(organizationId: string, now: Date): Promise<IntegrationStatus> {
  const assets = await db
    .select()
    .from(schema.exposureAsset)
    .where(eq(schema.exposureAsset.organizationId, organizationId));
  const code = (value: string | null): Reason | null =>
    value ? { family: "exposure", value: isExposureError(value) ? value : "unexpected" } : null;
  const stage1 = assets.map(
    (a): InstanceFacts => ({
      name: a.value,
      enabled: a.passiveEnabled,
      blocked: null,
      lastSuccessAt: a.lastPassiveAt && !a.passiveError ? a.lastPassiveAt : null,
      lastAttemptAt: a.lastPassiveAt,
      lastAttemptOk: a.lastPassiveAt ? a.passiveError === null : null,
      expectedEveryMs: DAY,
      reason: code(a.passiveError),
    }),
  );
  const stage2 = assets
    .filter((a) => a.stage2Enabled)
    .map(
      (a): InstanceFacts => ({
        name: a.value,
        enabled: a.verifyState === "verified",
        blocked: null,
        lastSuccessAt: a.lastActiveAt && !a.activeError ? a.lastActiveAt : null,
        lastAttemptAt: a.lastActiveAt,
        lastAttemptOk: a.lastActiveAt ? a.activeError === null : null,
        expectedEveryMs: (a.stage2Schedule === "weekly" ? 7 : 1) * DAY,
        reason: code(a.activeError),
      }),
    );
  const lost = assets.filter((a) => a.verifyState === "lost");
  const verified = assets.filter((a) => a.verifyState === "verified").length;
  const verification: IntegrationPartStatus = lost.length
    ? {
        key: "verification",
        state: "blocked",
        level: "attention",
        lastSuccessAt: iso(newest(assets.map((a) => a.verifiedAt))),
        lastAttemptAt: iso(newest(assets.map((a) => a.verifyCheckedAt))),
        lastAttemptOk: false,
        blocked: "verification",
        reason: null,
        detail: { lost: lost.length, verified, unverified: assets.length - verified - lost.length },
        instances: lost.slice(0, MAX_INSTANCES).map((a) => ({
          name: a.value,
          state: "blocked",
          lastSuccessAt: iso(a.verifiedAt),
          reason: code(a.verifyError),
          blocked: "verification",
        })),
      }
    : {
        key: "verification",
        state: assets.length ? "current" : "not_configured",
        level: assets.length ? "ok" : "inactive",
        lastSuccessAt: iso(newest(assets.map((a) => a.verifiedAt))),
        lastAttemptAt: iso(newest(assets.map((a) => a.verifyCheckedAt))),
        lastAttemptOk: assets.some((a) => a.verifyCheckedAt) ? true : null,
        blocked: null,
        reason: null,
        detail: { lost: 0, verified, unverified: assets.length - verified },
        instances: [],
      };
  return integration("exposure", assets.length > 0, assets.length, [
    part("stage1", stage1, now),
    stage2.length > 0 ? part("stage2", stage2, now) : idlePart("stage2", "not_configured"),
    verification,
  ]);
}

async function ai(organizationId: string, now: Date): Promise<IntegrationStatus> {
  const [settings] = await db
    .select()
    .from(schema.aiSettings)
    .where(eq(schema.aiSettings.organizationId, organizationId))
    .limit(1);
  if (!settings) return integration("ai", false, 0, []);
  // A result for an address that has since been replaced says nothing about the current one.
  const tested = settings.lastProbeAt !== null && settings.lastProbeUrl === settings.baseUrl;
  const external = settings.endpointScope === "external";
  const acknowledged =
    settings.externalAckHost !== null && settings.externalAckHost === endpointHost(settings.baseUrl);
  const facts: InstanceFacts = {
    name: "endpoint",
    enabled: settings.enabled,
    blocked: external && !acknowledged ? "acknowledgement" : null,
    lastSuccessAt: tested && settings.lastProbeOk ? settings.lastProbeAt : null,
    lastAttemptAt: tested ? settings.lastProbeAt : null,
    lastAttemptOk: tested ? settings.lastProbeOk : null,
    expectedEveryMs: null,
    reason:
      tested && settings.lastProbeOk === false
        ? { family: "ai", value: settings.lastProbeError ?? "internal" }
        : null,
  };
  return integration("ai", true, 1, [part("probe", [facts], now, { scope: settings.endpointScope })]);
}

async function notifications(organizationId: string): Promise<IntegrationStatus> {
  const channels = await db
    .select()
    .from(schema.notificationChannel)
    .where(eq(schema.notificationChannel.organizationId, organizationId));
  if (channels.length === 0) return integration("notifications", false, 0, []);
  const last = await db.execute<{
    channel_id: string;
    status: "sent" | "failed";
    error: string | null;
    at: Date;
  }>(sql`
    select distinct on (channel_id) channel_id, status, error, created_at as at
    from notification_delivery
    where organization_id = ${organizationId}
    order by channel_id, created_at desc, id desc`);
  const lastSent = await db.execute<{ channel_id: string; at: Date }>(sql`
    select channel_id, max(created_at) as at
    from notification_delivery
    where organization_id = ${organizationId} and status = 'sent'
    group by channel_id`);
  const latest = new Map(last.rows.map((r) => [r.channel_id, r]));
  const sent = new Map(lastSent.rows.map((r) => [r.channel_id, new Date(r.at)]));
  const rated = channels.map((c) => {
    const delivery = latest.get(c.id);
    const state: IntegrationState = !c.enabled
      ? "paused"
      : delivery?.status === "failed"
        ? "failed"
        : "current";
    return { c, delivery, state, success: sent.get(c.id) ?? null };
  });
  const state = worstState(rated.map((r) => r.state));
  const failedChannels = rated.filter((r) => r.state === "failed");
  const lead = failedChannels[0];
  const attempts = rated.flatMap((r) => (r.delivery ? [new Date(r.delivery.at)] : []));
  const partStatus: IntegrationPartStatus = {
    key: "delivery",
    state,
    level: levelOfIntegration(state),
    lastSuccessAt: iso(newest(rated.map((r) => r.success))),
    lastAttemptAt: iso(newest(attempts)),
    lastAttemptOk: attempts.length ? failedChannels.length === 0 : null,
    blocked: null,
    reason: lead?.delivery?.error ? { family: "raw", value: lead.delivery.error } : null,
    detail: {
      connections: channels.length,
      enabled: channels.filter((c) => c.enabled).length,
      failed: failedChannels.length,
    },
    instances: failedChannels.slice(0, MAX_INSTANCES).map(({ c, delivery, success }) => ({
      name: c.name,
      state: "failed",
      lastSuccessAt: iso(success),
      reason: delivery?.error ? { family: "raw", value: delivery.error } : null,
      blocked: null,
    })),
  };
  return integration("notifications", true, channels.length, [partStatus]);
}

/* -------------------------------------------------------------------------- */
/* Queues                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Per queue: waiting, running, failed in the last 24 hours and how long the oldest waiting job has
 * waited. Read with SQL from pg-boss's own tables, using only the columns every pg-boss release
 * since 10 has (`queue.name`, `job.name`, `job.state`, `job.start_after`, `job.completed_on`). If a
 * future pg-boss changes them the query fails and the page says "not available" instead of
 * guessing; a test runs it against a real pg-boss schema.
 */
export async function readQueues(): Promise<{ available: boolean; items: QueueStatus[] }> {
  try {
    const result = await db.execute<{
      name: string;
      queued: number;
      active: number;
      failed24h: number;
      oldest: number | null;
    }>(sql`
      select q.name,
             coalesce(j.queued, 0)::int as queued,
             coalesce(j.active, 0)::int as active,
             coalesce(j.failed24h, 0)::int as "failed24h",
             j.oldest::int as oldest
      from pgboss.queue q
      left join (
        select name,
               count(*) filter (where state in ('created', 'retry'))::int as queued,
               count(*) filter (where state = 'active')::int as active,
               count(*) filter (where state = 'failed' and completed_on > now() - interval '24 hours')::int as failed24h,
               extract(epoch from now() - min(start_after) filter (where state in ('created', 'retry') and start_after <= now())) as oldest
        from pgboss.job
        where state in ('created', 'retry', 'active')
           or (state = 'failed' and completed_on > now() - interval '24 hours')
        group by name
      ) j on j.name = q.name
      where left(q.name, 10) <> '__pgboss__' -- pg-boss housekeeping queues, not ours
      order by q.name`);
    return {
      available: true,
      items: result.rows.map((r) => {
        const oldest = r.oldest === null ? null : Math.max(0, Number(r.oldest));
        return {
          name: r.name,
          queued: Number(r.queued),
          active: Number(r.active),
          failed24h: Number(r.failed24h),
          oldestQueuedSeconds: oldest,
          level: queueLevel({ failed24h: Number(r.failed24h), oldestQueuedSeconds: oldest }),
        };
      }),
    };
  } catch (error) {
    console.error(`system status: the queues could not be read: ${(error as Error)?.name ?? "error"}`);
    return { available: false, items: [] };
  }
}

/* -------------------------------------------------------------------------- */
/* The whole view                                                              */
/* -------------------------------------------------------------------------- */

export interface UpdaterFacts {
  configured: boolean;
  /** The sidecar's phase, or null if none answers. */
  phase: "idle" | "scheduled" | "running" | "succeeded" | "failed" | null;
  latestAvailable: string | null;
}

export async function buildSystemStatus(
  organizationId: string,
  updater: UpdaterFacts,
  now: Date = new Date(),
): Promise<SystemStatus> {
  const [
    reports,
    lastScan,
    geoipDatasets,
    attackSettings,
    heartbeats,
    queues,
    nextRun,
    lastRun,
    database,
    wazuhRow,
    proxmoxRow,
    unifiRow,
    directoryRow,
    exposureRow,
    aiRow,
    notificationsRow,
  ] = await Promise.all([
    db.select().from(schema.systemReport),
    db
      .select({
        builtAt: schema.scan.vulnDbBuiltAt,
        scannerVersions: schema.scan.scannerVersions,
        finishedAt: schema.scan.finishedAt,
      })
      .from(schema.scan)
      .where(and(eq(schema.scan.organizationId, organizationId), eq(schema.scan.state, "succeeded")))
      .orderBy(desc(schema.scan.finishedAt), desc(schema.scan.id))
      .limit(1),
    datasetStatus(db),
    db
      .select()
      .from(schema.attackSettings)
      .where(eq(schema.attackSettings.organizationId, organizationId))
      .limit(1),
    db.select().from(schema.workerHeartbeat).orderBy(desc(schema.workerHeartbeat.beatAt)).limit(20),
    readQueues(),
    nextNightlyRun(db, organizationId, now),
    db
      .select()
      .from(schema.scanScheduleRun)
      .where(eq(schema.scanScheduleRun.organizationId, organizationId))
      .orderBy(desc(schema.scanScheduleRun.createdAt))
      .limit(1),
    databaseState(db),
    wazuh(organizationId, now),
    proxmox(organizationId, now),
    unifi(organizationId, now),
    directory(organizationId, now),
    exposure(organizationId, now),
    ai(organizationId, now),
    notifications(organizationId),
  ]);

  const report = (key: string) => reports.find((r) => r.key === key)?.data;

  /* Scanners */
  const scannersReport = scannersReportSchema.safeParse(report("scanners"));
  const reportedScanners = scannersReport.success ? scannersReport.data : {};
  const scanVersions = (lastScan[0]?.scannerVersions ?? {}) as Record<string, string>;
  const scannerItems = SCANNER_NAMES.map((name: ScannerName) => {
    const entry = reportedScanners[name];
    // Before the worker has reported, the versions the latest scan used are the best answer.
    const fromScan = scanVersions[name] ?? null;
    const version = entry ? entry.version : fromScan;
    const problem = entry?.problem ?? null;
    const match = scannerMatch(name, version);
    return {
      name,
      level: scannerLevel(match, problem),
      version,
      pinned: PINNED_SCANNERS[name],
      match,
      problem,
      reportedAt: entry ? entry.reportedAt : iso(fromScan ? (lastScan[0]?.finishedAt ?? null) : null),
    };
  });

  /* Vulnerability database */
  const dbReport = vulnDbReportSchema.safeParse(report("vulndb"));
  const updateReport = vulnDbUpdateReportSchema.safeParse(report("vulndb_update"));
  const reported = dbReport.success;
  const builtAt = reported
    ? dbReport.data.builtAt
      ? new Date(dbReport.data.builtAt)
      : null
    : (lastScan[0]?.builtAt ?? null);
  const freshness = vulnDbFreshness(builtAt, now);
  const update = updateReport.success ? updateReport.data : null;
  const updateFailed = update?.lastResult === "failed";
  const vulnLevel = worstLevel([
    reported && !dbReport.data.valid ? "failed" : "inactive",
    reported ? levelOfFreshness(freshness) : "attention",
    updateFailed ? "attention" : "inactive",
  ]);
  const vulnDb: SystemStatus["vulnDb"] = {
    level: vulnLevel === "inactive" ? "ok" : vulnLevel,
    reported,
    freshness,
    valid: reported ? dbReport.data.valid : null,
    problem: reported ? dbReport.data.problem : null,
    builtAt: iso(builtAt),
    ageDays: ageDays(builtAt, now),
    schemaVersion: reported ? dbReport.data.schemaVersion : null,
    source: reported ? dbReport.data.source : null,
    checkedAt: reported ? dbReport.data.checkedAt : null,
    thresholds: { staleAfterDays: VULNDB_STALE_AFTER_DAYS, outdatedAfterDays: VULNDB_OUTDATED_AFTER_DAYS },
    update: {
      mode: update?.mode ?? null,
      lastAttemptAt: update?.lastAttemptAt ?? null,
      lastSuccessAt: update?.lastSuccessAt ?? null,
      lastResult: update?.lastResult ?? null,
      reason: update?.reason ? { family: "vulndb-update", value: update.reason } : null,
      nextAt: update?.nextAt ?? null,
    },
    providers: reported ? dbReport.data.providers : { available: false, items: [] },
  };

  /* Local build (vunnel and grype-db): planned until a builder reports */
  const buildReport = vulnDbBuildReportSchema.safeParse(report("vulndb_build"));
  const build = buildReport.success && buildReport.data.enabled ? buildReport.data : null;
  const buildProviders = (build?.providers ?? []).map((p) => ({
    name: p.name,
    level: buildProviderLevel(p.result),
    lastRunAt: p.lastRunAt,
    result: p.result,
    records: p.records,
    durationMs: p.durationMs,
    reason: p.reason,
  }));
  const localBuild: SystemStatus["localBuild"] = {
    level: build ? worstLevel(buildProviders.map((p) => p.level).concat("ok")) : "inactive",
    state: build ? "set_up" : "not_set_up",
    lastBuildAt: build?.lastBuildAt ?? null,
    providers: buildProviders,
  };

  /* GeoIP */
  const settings = attackSettings[0];
  const datasets = geoipDatasets.map((d): SystemStatus["geoip"]["datasets"][number] => {
    const start = monthStart(d.active?.month);
    const freshnessOfDataset = d.active ? geoipFreshness(start ?? d.active.loadedAt, now) : "unknown";
    const failure = d.lastFailure
      ? { source: d.lastFailure.source, error: d.lastFailure.error, at: d.lastFailure.at.toISOString() }
      : null;
    const level: StatusLevel = d.active
      ? worstLevel([levelOfFreshness(freshnessOfDataset), failure ? "attention" : "ok"])
      : failure
        ? "failed"
        : "inactive";
    return {
      kind: d.kind,
      level,
      state: d.active ? "loaded" : "none",
      month: d.active?.month ?? null,
      ageDays: d.active ? ageDays(start ?? d.active.loadedAt, now) : null,
      freshness: freshnessOfDataset,
      loadedAt: iso(d.active?.loadedAt),
      rows: d.active?.rows ?? null,
      source: d.active?.source ?? null,
      failure,
    };
  });
  const downloadReason = settings?.geoipDownloadLastError
    ? { family: "geoip" as const, value: settings.geoipDownloadLastError }
    : null;
  const geoipLevel = worstLevel([...datasets.map((d) => d.level), downloadReason ? "attention" : "inactive"]);

  /* Worker */
  const beat = heartbeats[0];
  const liveness = workerLiveness(beat?.beatAt ?? null, now);
  const live = heartbeats.filter((h) => workerLiveness(h.beatAt, now) === "running").length;
  const queuesLevel = queues.available ? worstLevel(queues.items.map((q) => q.level)) : "attention";
  const migrationsOk =
    database.migrations.expected > 0 && database.migrations.applied === database.migrations.expected;
  const databaseLevel: StatusLevel =
    database.sizeBytes === null ? "attention" : migrationsOk ? "ok" : "attention";
  const schedule = lastRun[0];
  let nightlyLast: SystemStatus["worker"]["nightly"]["lastRun"] = null;
  if (schedule) {
    const counts = await db
      .select({ state: schema.scan.state, n: sql<number>`count(*)::int` })
      .from(schema.scan)
      .where(
        and(
          eq(schema.scan.organizationId, organizationId),
          eq(schema.scan.trigger, "schedule"),
          sql`${schema.scan.createdAt} >= ${schedule.createdAt}`,
        ),
      )
      .groupBy(schema.scan.state);
    const by = (states: string[]) =>
      counts.filter((c) => states.includes(c.state)).reduce((sum, c) => sum + c.n, 0);
    nightlyLast = {
      at: schedule.createdAt.toISOString(),
      localDate: schedule.localDate,
      queued: schedule.queuedScans,
      succeeded: by(["succeeded"]),
      failed: by(["failed"]),
      pending: by(["queued", "running"]),
    };
  }

  /* App */
  const updaterLevel: StatusLevel = !updater.configured
    ? "inactive"
    : updater.phase === null
      ? "attention"
      : updater.phase === "failed"
        ? "failed"
        : "ok";

  const integrations = [wazuhRow, proxmoxRow, unifiRow, directoryRow, aiRow, exposureRow, notificationsRow];

  // The rows the overall verdict counts: one per thing the page shows a level for.
  const levels: StatusLevel[] = [
    ...scannerItems.map((s) => s.level),
    vulnDb.level,
    ...datasets.map((d) => d.level),
    downloadReason ? "attention" : "inactive",
    ...integrations.map((i) => i.level),
    levelOfWorker(liveness),
    ...queues.items.map((q) => q.level),
    queues.available ? "inactive" : "attention",
    databaseLevel,
    updaterLevel,
    localBuild.level,
  ];
  const attention = levels.filter((l) => l === "attention").length;
  const failed = levels.filter((l) => l === "failed").length;

  return {
    generatedAt: now.toISOString(),
    refreshSeconds: STATUS_REFRESH_SECONDS,
    overall: { level: overallLevel(levels), attention, failed },
    app: {
      version: APP_VERSION,
      updater: {
        configured: updater.configured,
        reachable: updater.phase !== null,
        level: updaterLevel,
        phase: updater.phase,
        latestAvailable: updater.latestAvailable,
      },
    },
    scanners: { level: worstLevel(scannerItems.map((s) => s.level)), items: scannerItems },
    vulnDb,
    localBuild,
    geoip: {
      level: geoipLevel,
      datasets,
      download: {
        enabled: settings?.geoipDownloadEnabled ?? false,
        lastAttemptAt: iso(settings?.geoipDownloadLastAttemptAt),
        reason: downloadReason,
      },
    },
    integrations,
    worker: {
      level: worstLevel([levelOfWorker(liveness), queuesLevel, databaseLevel]),
      liveness,
      heartbeat: beat
        ? {
            version: beat.version,
            startedAt: beat.startedAt.toISOString(),
            beatAt: beat.beatAt.toISOString(),
            instances: live,
          }
        : null,
      queues: { available: queues.available, level: queuesLevel, items: queues.items },
      nightly: {
        enabled: nextRun?.enabled ?? false,
        localTime: nextRun?.localTime ?? "04:00:00",
        timeZone: nextRun?.timeZone ?? "UTC",
        lastRun: nightlyLast,
        nextAt: iso(nextRun?.at),
      },
      database: { level: databaseLevel, sizeBytes: database.sizeBytes, migrations: database.migrations },
    },
  };
}
