/**
 * UniFi (ADR 0022): reading the certificate a console presents, and the read-only sync.
 *
 * A sync opens the sealed API key, connects to the checked address with the pinned certificate, asks only GET
 * endpoints of the official local UniFi Network API on an allow-list, and stores sites, devices (name, model, MAC,
 * address, state, firmware, uptime) and the number of clients per site. Whatever the console sends is data:
 * parsed by packages/core/src/unifi.ts, bounded, stored as text, never executed and never echoed into an error
 * message. Clients themselves are never read: only the total of a one-entry page.
 */
import {
  newId,
  UnifiError,
  type UnifiErrorCode,
  type UnifiWarning,
  unifiErrorMessage,
} from "@garnetops/core";
import {
  type ApiBase,
  MAX_DEVICES_PER_CONNECTION,
  MAX_PAGES,
  MAX_REQUESTS_PER_SYNC,
  notifyDecision,
  PAGE_SIZE,
  parseClientTotal,
  parseDevices,
  parseInfo,
  parsePage,
  parseSites,
  parseUptime,
  SYNC_BUDGET_MINUTES,
  type UfDevice,
  type UfSite,
  UNIFI_SYNC_INTERVAL_MINUTES,
} from "@garnetops/core/unifi";
import { open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, inArray, lt, notInArray, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import {
  type CertificateInfo,
  CertificateMismatch,
  fetchLeafCertificate,
  resolveUnifiAddress,
  type TlsTestOptions,
  UnifiClient,
} from "./unifi-http.ts";
import { tellUsers } from "./user-notify.ts";

export const UNIFI_CERT_QUEUE = "unifi.certificate";
export const UNIFI_SYNC_QUEUE = "unifi.sync";
export const UNIFI_TICK_QUEUE = "unifi.sync-tick";

/** Same job options as syncs queued by the API (apps/api/src/routes/unifi.ts). One try: the next tick is the retry. */
export const UNIFI_SYNC_JOB = { retryLimit: 0, expireInSeconds: (SYNC_BUDGET_MINUTES + 5) * 60 };

export type ConnectionRow = typeof schema.unifiConnection.$inferSelect;
type RunRow = typeof schema.unifiSyncRun.$inferSelect;

/** What a test can replace: name resolution (so a local test server can be used), its CA, limits and the pause between requests. */
export interface UnifiDeps {
  resolve?: (host: string) => Promise<string>;
  test?: TlsTestOptions;
  gapMs?: number;
  maxBytes?: number;
  timeoutMs?: number;
  maxRequests?: number;
  budgetMs?: number;
}

/** Errors that end a sync even when the call that raised them was optional. */
const FATAL: UnifiErrorCode[] = [
  "keyRejected",
  "tlsFailed",
  "unreachable",
  "tooManyRequests",
  "syncTimeout",
  "certificateChanged",
  "addressRefused",
  "addressUnresolvable",
  "rateLimited",
];

export const errorCodeOf = (error: unknown, fallback: UnifiErrorCode = "unexpected"): UnifiErrorCode =>
  error instanceof UnifiError ? error.code : fallback;

/* -------------------------------------------------------------------------- */
/* Secrets                                                                     */
/* -------------------------------------------------------------------------- */

/** Opens a sealed secret of a connection. Only the worker holds the vault private key (ADR 0004). */
export async function openUnifiSecret(
  connection: ConnectionRow,
  secretId: string | null,
  purpose: "unifi-api-key" | "unifi-ips-password",
  missing: UnifiErrorCode,
): Promise<string> {
  if (!secretId) throw new UnifiError(missing);
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, secretId),
        eq(schema.secret.organizationId, connection.organizationId),
        eq(schema.secret.purpose, purpose),
      ),
    )
    .limit(1);
  if (!secret) throw new UnifiError(missing);
  const plain = open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose },
    vaultPrivateKey,
  );
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

/* -------------------------------------------------------------------------- */
/* Certificate                                                                 */
/* -------------------------------------------------------------------------- */

const NO_CANDIDATE = {
  candidateFingerprint: null,
  candidateSubject: null,
  candidateIssuer: null,
  candidateValidFrom: null,
  candidateValidTo: null,
  candidateCaTrusted: null,
  candidateSeenAt: null,
};

/**
 * Records what the console presented: nothing to do if it is the pinned certificate (an earlier alarm clears
 * itself), "changed" with the new one as candidate if another is pinned (audited and announced once, and the sync
 * stays blocked), or the candidate an admin confirms on first contact.
 */
export async function applyObservedCertificate(
  connection: ConnectionRow,
  seen: CertificateInfo,
): Promise<void> {
  const c = schema.unifiConnection;
  const now = new Date();
  const candidate = {
    candidateFingerprint: seen.fingerprint,
    candidateSubject: seen.subject,
    candidateIssuer: seen.issuer,
    candidateValidFrom: seen.validFrom,
    candidateValidTo: seen.validTo,
    candidateCaTrusted: seen.caTrusted,
    candidateSeenAt: now,
  };
  if (connection.certFingerprint && connection.certFingerprint === seen.fingerprint) {
    if (connection.certStatus === "changed" || connection.candidateFingerprint) {
      await db
        .update(c)
        .set({
          certStatus: "confirmed",
          ...NO_CANDIDATE,
          lastError: connection.certStatus === "changed" ? null : connection.lastError,
          updatedAt: now,
        })
        .where(eq(c.id, connection.id));
    }
    return;
  }
  if (connection.certFingerprint) {
    let news = false;
    await db.transaction(async (tx) => {
      await tx
        .update(c)
        .set({
          certStatus: "changed",
          ...candidate,
          lastError: unifiErrorMessage("certificateChanged"),
          updatedAt: now,
        })
        .where(eq(c.id, connection.id));
      if (connection.certStatus !== "changed" || connection.candidateFingerprint !== seen.fingerprint) {
        news = true;
        await tx.insert(schema.auditLog).values({
          organizationId: connection.organizationId,
          action: "unifi.certificate_changed",
          targetType: "unifi_connection",
          targetId: connection.id,
          data: { name: connection.name, pinned: connection.certFingerprint, seen: seen.fingerprint },
        });
      }
    });
    // Owners and admins hear of it once per change, like the audit entry (ADR 0019).
    if (news) {
      await tellUsers({
        organizationId: connection.organizationId,
        titleKey: "unifiCertificateChanged",
        params: { name: connection.name },
        link: "/settings?section=unifi",
      });
    }
    return;
  }
  await db
    .update(c)
    .set({ ...candidate, lastError: null, updatedAt: now })
    .where(eq(c.id, connection.id));
}

/**
 * Reads the certificate the console presents, without sending the key, and stores it as the candidate an admin
 * confirms (or flags a change). Never pins by itself.
 */
export async function readCertificate(connectionId: string, deps: UnifiDeps = {}): Promise<void> {
  const [connection] = await db
    .select()
    .from(schema.unifiConnection)
    .where(eq(schema.unifiConnection.id, connectionId))
    .limit(1);
  if (!connection) return;
  try {
    const address = await (deps.resolve ?? resolveUnifiAddress)(connection.host);
    const seen = await fetchLeafCertificate(
      { host: connection.host, port: connection.port, address },
      deps.test,
    );
    await applyObservedCertificate(connection, seen);
  } catch (error) {
    const code = errorCodeOf(error, "unreachable");
    await db
      .update(schema.unifiConnection)
      .set({ lastError: unifiErrorMessage(code), updatedAt: new Date() })
      .where(eq(schema.unifiConnection.id, connectionId));
    if (!(error instanceof UnifiError)) {
      console.error(`unifi ${connectionId} certificate:`, (error as Error).name);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Sync                                                                        */
/* -------------------------------------------------------------------------- */

/** A running sync older than this lost its worker (matches the job expiry). */
const STALE_RUNNING = sql`now() - interval '15 minutes'`;

async function failRun(run: RunRow, error: UnifiError, requests: number | null) {
  const message = error.message;
  await db.transaction(async (tx) => {
    await tx
      .update(schema.unifiSyncRun)
      .set({ state: "failed", error: message, requestCount: requests, finishedAt: sql`now()` })
      .where(eq(schema.unifiSyncRun.id, run.id));
    await tx
      .update(schema.unifiConnection)
      .set({ lastError: message, updatedAt: new Date() })
      .where(eq(schema.unifiConnection.id, run.connectionId));
  });
}

/** Runs one queued sync. Never throws for a problem of the console; those become the run's error. */
export async function runUnifiSync(runId: string, deps: UnifiDeps = {}): Promise<void> {
  const r = schema.unifiSyncRun;
  const [run] = await db
    .update(r)
    .set({ state: "running", startedAt: sql`now()` })
    .where(
      and(
        eq(r.id, runId),
        sql`(${r.state} = 'queued' or (${r.state} = 'running' and ${r.startedAt} < ${STALE_RUNNING}))`,
      ),
    )
    .returning();
  if (!run) return; // taken, finished or cancelled
  const progress = { requests: 0 };
  try {
    await syncConnection(run, deps, progress);
  } catch (error) {
    if (error instanceof UnifiError) {
      await failRun(run, error, progress.requests);
    } else {
      // Never the message of an unknown error: it could quote what the console sent.
      console.error(`unifi sync ${runId}:`, (error as Error)?.name ?? "error");
      await failRun(run, new UnifiError("unexpected"), progress.requests);
    }
  }
}

interface SiteResult {
  site: UfSite;
  /** False when the device list of this site could not be read: its last known devices stay. */
  read: boolean;
  devices: UfDevice[];
  uptime: Map<string, number | null>;
  clients: number | null;
}

interface Collected {
  version: string;
  base: ApiBase;
  sites: SiteResult[];
  warnings: Set<UnifiWarning>;
}

async function syncConnection(run: RunRow, deps: UnifiDeps, progress: { requests: number }): Promise<void> {
  const [connection] = await db
    .select()
    .from(schema.unifiConnection)
    .where(eq(schema.unifiConnection.id, run.connectionId))
    .limit(1);
  if (!connection) throw new UnifiError("connectionRemoved");
  if (connection.certStatus === "changed") throw new UnifiError("certificateChanged");
  if (connection.certStatus !== "confirmed" || !connection.certFingerprint) {
    throw new UnifiError("certificateNotConfirmed");
  }
  const apiKey = await openUnifiSecret(connection, connection.secretId, "unifi-api-key", "keyMissing");
  const address = await (deps.resolve ?? resolveUnifiAddress)(connection.host);
  const client = new UnifiClient({
    endpoint: { host: connection.host, port: connection.port, address },
    pinned: connection.certFingerprint,
    apiKey,
    base: connection.apiBase === "network-app" ? "network-app" : "unifi-os",
    ...(deps.gapMs !== undefined ? { gapMs: deps.gapMs } : {}),
    ...(deps.maxBytes !== undefined ? { maxBytes: deps.maxBytes } : {}),
    ...(deps.timeoutMs !== undefined ? { timeoutMs: deps.timeoutMs } : {}),
    ...(deps.test ? { test: deps.test } : {}),
  });
  const deadline = Date.now() + (deps.budgetMs ?? SYNC_BUDGET_MINUTES * 60_000);
  const maxRequests = deps.maxRequests ?? MAX_REQUESTS_PER_SYNC;
  let consecutiveTimeouts = 0;

  const call = async (path: string, query?: Record<string, string>) => {
    if (client.requests >= maxRequests) throw new UnifiError("tooManyRequests");
    if (Date.now() > deadline) throw new UnifiError("syncTimeout", { minutes: SYNC_BUDGET_MINUTES });
    try {
      const result = await client.get(path, query);
      consecutiveTimeouts = 0;
      return result;
    } catch (error) {
      consecutiveTimeouts = errorCodeOf(error) === "timeout" ? consecutiveTimeouts + 1 : 0;
      throw error;
    } finally {
      progress.requests = client.requests;
    }
  };
  /** An optional read: a refusal or a malformed answer is tolerated (null), a lost connection is not. */
  const optional = async (path: string, query?: Record<string, string>) => {
    try {
      return { ok: true as const, data: await call(path, query) };
    } catch (error) {
      if (error instanceof CertificateMismatch) throw error;
      if (error instanceof UnifiError && !FATAL.includes(error.code) && consecutiveTimeouts < 5) {
        return { ok: false as const };
      }
      throw error;
    }
  };

  try {
    const collected = await collect(connection, client, call, optional);
    const found = await store(run, connection, collected, client.requests);
    await announce(connection, found);
  } catch (error) {
    // A certificate other than the pin: record what was seen so an admin can decide (the key was never sent).
    const seen = error instanceof CertificateMismatch ? error.seen : client.mismatch;
    if (seen) await applyObservedCertificate(connection, seen);
    throw error;
  } finally {
    client.close();
  }
}

type Call = (path: string, query?: Record<string, string>) => Promise<unknown>;
type Optional = (
  path: string,
  query?: Record<string, string>,
) => Promise<{ ok: true; data: unknown } | { ok: false }>;

/** Reads every page of a list endpoint (`limit`/`offset`) and returns the entries. Null if the answer is not a list. */
async function readAll(
  fetch: (query: Record<string, string>) => Promise<unknown | undefined>,
  cap: number,
): Promise<{ data: unknown[]; truncated: boolean } | null> {
  const data: unknown[] = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const body = await fetch({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) });
    if (body === undefined) return null;
    const parsed = parsePage(body);
    if (!parsed) return null;
    data.push(...parsed.data);
    const total = parsed.totalCount;
    if (parsed.data.length < PAGE_SIZE || (total !== null && data.length >= total)) {
      return { data: data.slice(0, cap), truncated: data.length > cap };
    }
    if (data.length >= cap) return { data: data.slice(0, cap), truncated: true };
  }
  return { data: data.slice(0, cap), truncated: true };
}

async function collect(
  connection: ConnectionRow,
  client: UnifiClient,
  call: Call,
  optional: Optional,
): Promise<Collected> {
  const warnings = new Set<UnifiWarning>();

  // 1. Is this the UniFi Network API, and where does it live? `auto` tries the UniFi OS prefix, then the other.
  let infoBody: unknown;
  try {
    infoBody = await call("/v1/info");
  } catch (error) {
    if (connection.apiBase === "auto" && error instanceof UnifiError && error.code === "notUnifi") {
      client.base = "network-app";
      infoBody = await call("/v1/info");
    } else throw error;
  }
  const version = parseInfo(infoBody);
  if (!version) throw new UnifiError("notUnifi");

  // 2. Sites. A console always has one; an answer without any is not trusted to empty the inventory.
  const sitePages = await readAll(async (query) => call("/v1/sites", query), 1000);
  if (!sitePages) throw new UnifiError("invalidResponse");
  const parsedSites = parseSites(sitePages.data);
  if (parsedSites.sites.length === 0) throw new UnifiError("invalidResponse");
  if (parsedSites.dropped > 0) warnings.add("entriesDropped");
  if (sitePages.truncated) warnings.add("sitesTruncated");

  // 3. Per site: its devices, the uptime of online devices, and the number of clients.
  const sites: SiteResult[] = [];
  let deviceTotal = 0;
  let statisticsFailures = 0;
  for (const site of parsedSites.sites) {
    const result: SiteResult = { site, read: false, devices: [], uptime: new Map(), clients: null };
    sites.push(result);
    const pages = await readAllOptional(optional, `/v1/sites/${site.id}/devices`);
    if (!pages) {
      warnings.add("siteUnreadable");
      continue;
    }
    const parsed = parseDevices(pages.data);
    if (parsed.dropped > 0) warnings.add("entriesDropped");
    if (pages.truncated) warnings.add("devicesTruncated");
    const room = Math.max(0, MAX_DEVICES_PER_CONNECTION - deviceTotal);
    if (parsed.devices.length > room) warnings.add("devicesTruncated");
    result.devices = parsed.devices.slice(0, room);
    result.read = true;
    deviceTotal += result.devices.length;

    for (const device of result.devices) {
      if (device.state !== "online" || statisticsFailures >= 3) continue;
      const stats = await optional(`/v1/sites/${site.id}/devices/${device.id}/statistics/latest`);
      if (stats.ok) result.uptime.set(device.id, parseUptime(stats.data));
      else {
        statisticsFailures++;
        warnings.add("statisticsUnreadable");
      }
    }
    const clients = await optional(`/v1/sites/${site.id}/clients`, { limit: "1" });
    if (clients.ok) result.clients = parseClientTotal(clients.data);
    if (!clients.ok || result.clients === null) warnings.add("clientsUnreadable");
  }
  return { version, base: client.base, sites, warnings };
}

async function readAllOptional(optional: Optional, path: string) {
  let failed = false;
  const pages = await readAll(async (query) => {
    const r = await optional(path, query);
    if (!r.ok) {
      failed = true;
      return undefined;
    }
    return r.data;
  }, MAX_DEVICES_PER_CONNECTION);
  return failed ? null : pages;
}

const toInt = (n: number | null | undefined) => (n === null || n === undefined ? null : Math.round(n));

interface Announcement {
  offline: string[];
  firmware: string[];
}

/** Replaces what is stored about the connection with what was read, in one transaction. Returns what to tell people. */
async function store(
  run: RunRow,
  connection: ConnectionRow,
  d: Collected,
  requests: number,
): Promise<Announcement> {
  const now = new Date();
  const s = schema.unifiSite;
  const dv = schema.unifiDevice;
  const offline: string[] = [];
  const firmware: string[] = [];
  let deviceCount = 0;
  await db.transaction(async (tx) => {
    const oldSites = new Map(
      (await tx.select().from(s).where(eq(s.connectionId, connection.id))).map((x) => [x.unifiId, x]),
    );
    const siteRows = d.sites.map((r) => {
      const prior = oldSites.get(r.site.id);
      return {
        id: prior?.id ?? newId("ufs"),
        organizationId: connection.organizationId,
        connectionId: connection.id,
        unifiId: r.site.id,
        name: r.site.name,
        internalRef: r.site.internalReference,
        clientCount: r.clients ?? prior?.clientCount ?? null,
        lastSeenAt: now,
      };
    });
    await tx
      .insert(s)
      .values(siteRows)
      .onConflictDoUpdate({
        target: [s.connectionId, s.unifiId],
        set: {
          name: sql`excluded.name`,
          internalRef: sql`excluded.internal_ref`,
          clientCount: sql`excluded.client_count`,
          lastSeenAt: sql`excluded.last_seen_at`,
        },
      });
    // Sites that are not in this answer are gone (their devices go with them).
    await tx.delete(s).where(
      and(
        eq(s.connectionId, connection.id),
        notInArray(
          s.unifiId,
          d.sites.map((x) => x.site.id),
        ),
      ),
    );

    const siteIdOf = new Map(siteRows.map((r) => [r.unifiId, r.id]));
    const oldDevices = new Map(
      (await tx.select().from(dv).where(eq(dv.connectionId, connection.id))).map((x) => [x.unifiId, x]),
    );
    const rows: (typeof dv.$inferInsert)[] = [];
    const readSiteIds: string[] = [];
    for (const result of d.sites) {
      const siteId = siteIdOf.get(result.site.id) as string;
      if (!result.read) continue;
      readSiteIds.push(siteId);
      for (const device of result.devices) {
        const prior = oldDevices.get(device.id);
        const offlineSyncs = device.state === "offline" ? (prior?.offlineSyncs ?? 0) + 1 : 0;
        const decision = notifyDecision({
          state: device.state,
          offlineSyncs,
          offlineNotified: device.state === "offline" && (prior?.offlineNotified ?? false),
          firmwareUpdatable: device.firmwareUpdatable,
          firmwareVersion: device.firmwareVersion,
          firmwareNotifiedVersion: prior?.firmwareNotifiedVersion ?? null,
        });
        if (decision.offline) offline.push(device.name);
        if (decision.firmware) firmware.push(device.name);
        rows.push({
          id: prior?.id ?? newId("ufd"),
          organizationId: connection.organizationId,
          connectionId: connection.id,
          siteId,
          unifiId: device.id,
          name: device.name,
          model: device.model,
          mac: device.mac,
          ip: device.ip,
          state: device.state,
          rawState: device.rawState,
          // The console does not say since when a device is in a state: we count from when we first saw it.
          stateSince: prior && prior.state === device.state ? prior.stateSince : now,
          firmwareVersion: device.firmwareVersion,
          firmwareUpdatable: device.firmwareUpdatable,
          latestFirmware: device.latestFirmware,
          uptimeSec: device.state === "online" ? toInt(result.uptime.get(device.id)) : null,
          offlineSyncs,
          offlineNotified:
            decision.offline || (device.state === "offline" && (prior?.offlineNotified ?? false)),
          firmwareNotifiedVersion: decision.firmware
            ? device.firmwareVersion
            : (prior?.firmwareNotifiedVersion ?? null),
          firstSeenAt: prior?.firstSeenAt ?? now,
          lastSeenAt: now,
        });
      }
    }
    for (let i = 0; i < rows.length; i += 400) {
      await tx
        .insert(dv)
        .values(rows.slice(i, i + 400))
        .onConflictDoUpdate({
          target: [dv.connectionId, dv.unifiId],
          set: {
            siteId: sql`excluded.site_id`,
            name: sql`excluded.name`,
            model: sql`excluded.model`,
            mac: sql`excluded.mac`,
            ip: sql`excluded.ip`,
            state: sql`excluded.state`,
            rawState: sql`excluded.raw_state`,
            stateSince: sql`excluded.state_since`,
            firmwareVersion: sql`excluded.firmware_version`,
            firmwareUpdatable: sql`excluded.firmware_updatable`,
            latestFirmware: sql`excluded.latest_firmware`,
            uptimeSec: sql`excluded.uptime_sec`,
            offlineSyncs: sql`excluded.offline_syncs`,
            offlineNotified: sql`excluded.offline_notified`,
            firmwareNotifiedVersion: sql`excluded.firmware_notified_version`,
            lastSeenAt: sql`excluded.last_seen_at`,
          },
        });
    }
    deviceCount = rows.length;
    // Devices of a site that was read but are not in its answer any more are gone (removed or migrated).
    // A site that could not be read keeps its last known devices.
    if (readSiteIds.length > 0) {
      await tx.delete(dv).where(and(inArray(dv.siteId, readSiteIds), lt(dv.lastSeenAt, now)));
    }

    await tx
      .update(schema.unifiConnection)
      .set({
        version: d.version,
        ...(connection.apiBase === "auto" ? { apiBase: d.base } : {}),
        lastSyncAt: now,
        lastError: null,
        updatedAt: now,
      })
      .where(eq(schema.unifiConnection.id, connection.id));
    await tx
      .update(schema.unifiSyncRun)
      .set({
        state: "succeeded",
        finishedAt: now,
        siteCount: siteRows.length,
        deviceCount,
        requestCount: requests,
        warnings: [...d.warnings],
        error: null,
      })
      .where(eq(schema.unifiSyncRun.id, run.id));
  });
  return { offline, firmware };
}

/** Tells owners and admins what the sync found (ADR 0019): one message per kind and sync, never per device. */
async function announce(connection: ConnectionRow, found: Announcement): Promise<void> {
  const link = "/servers?view=unifi";
  if (found.offline.length > 0) {
    await tellUsers({
      organizationId: connection.organizationId,
      titleKey: "unifiDeviceOffline",
      params: { name: connection.name, device: found.offline[0] as string, count: found.offline.length },
      link,
    });
  }
  if (found.firmware.length > 0) {
    await tellUsers({
      organizationId: connection.organizationId,
      titleKey: "unifiFirmwareUpdate",
      params: { name: connection.name, device: found.firmware[0] as string, count: found.firmware.length },
      link,
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Schedule                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * One tick of the UniFi schedule: queues a sync for every enabled connection whose certificate is confirmed,
 * unless one is waiting, running or was queued in the last ten minutes. Also sends again syncs that may have been
 * lost between queueing and sending, and looks again at the certificate of connections blocked by a changed one.
 */
export async function unifiTick(boss: PgBoss): Promise<void> {
  const c = schema.unifiConnection;
  const r = schema.unifiSyncRun;
  const due = await db
    .select()
    .from(c)
    .where(
      and(
        eq(c.enabled, true),
        eq(c.certStatus, "confirmed"),
        sql`not exists (select 1 from ${r} where ${r.connectionId} = ${c.id}
              and (${r.state} in ('queued', 'running') or ${r.createdAt} > now() - interval '10 minutes'))`,
      ),
    );
  for (const connection of due) {
    const runId = newId("ufr");
    await db.insert(r).values({
      id: runId,
      organizationId: connection.organizationId,
      connectionId: connection.id,
      state: "queued",
      trigger: "schedule",
      createdAt: new Date(),
    });
    await boss.send(UNIFI_SYNC_QUEUE, { runId }, { ...UNIFI_SYNC_JOB, singletonKey: connection.id });
  }
  // A connection whose certificate changed is not synced, but looked at again now and then (no key is sent):
  // if the pinned certificate is back, the alarm clears itself; otherwise the candidate stays current.
  const changed = await db
    .select({ id: c.id })
    .from(c)
    .where(and(eq(c.enabled, true), eq(c.certStatus, "changed")));
  for (const connection of changed) {
    await boss.send(
      UNIFI_CERT_QUEUE,
      { connectionId: connection.id },
      { retryLimit: 0, singletonKey: connection.id },
    );
  }
  const stranded = await db
    .select({ id: r.id, connectionId: r.connectionId })
    .from(r)
    .where(and(eq(r.state, "queued"), sql`${r.createdAt} < now() - interval '2 minutes'`))
    .limit(100);
  for (const run of stranded) {
    await boss.send(
      UNIFI_SYNC_QUEUE,
      { runId: run.id },
      { ...UNIFI_SYNC_JOB, singletonKey: run.connectionId },
    );
  }
}

/** Registers the tick: every 15 minutes, cron evaluated in UTC. */
export async function startUnifiScheduler(boss: PgBoss): Promise<void> {
  await boss.createQueue(UNIFI_TICK_QUEUE);
  await boss.schedule(UNIFI_TICK_QUEUE, `*/${UNIFI_SYNC_INTERVAL_MINUTES} * * * *`, null, { tz: "UTC" });
  await boss.work(UNIFI_TICK_QUEUE, { batchSize: 1 }, async () => {
    await unifiTick(boss);
  });
}
