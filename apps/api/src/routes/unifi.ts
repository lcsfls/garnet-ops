/**
 * UniFi (ADR 0022): a read-only inventory of the network devices of UniFi consoles, from the official local
 * UniFi Network API, and the optional, off-by-default IPS preview. Everyone in the organisation reads; owners and
 * admins configure. Creating, re-pointing and removing a connection, entering a key or a password, switching the
 * preview on and confirming a certificate also need a recent sign-in (step-up). The API only seals the API key and
 * the password; the worker opens them and is the only component that talks to a console. Responses never contain a
 * key, a password, a certificate or anything a console sent beyond the fields stored by the sync.
 */
import { newId } from "@garnetops/core";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { normalizeFingerprint } from "@garnetops/core/proxmox";
import {
  API_BASE_CHOICES,
  API_KEY_PATTERN,
  checkConnectionName,
  checkUnifiUrl,
  deviceFlags,
  firmwareStatus,
  MAX_UNIFI_CONNECTIONS,
  UNIFI_SYNC_INTERVAL_MINUTES,
} from "@garnetops/core/unifi";
import {
  checkIpsUsername,
  IPS_INTERVAL_SECONDS,
  IPS_PASSWORD_PATTERN,
  ipsRightsAcknowledged,
  ipsStatus,
  isIpsInterval,
  sameRights,
} from "@garnetops/core/unifi-ips";
import { seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, getTableColumns, ilike, inArray, or, sql } from "drizzle-orm";
import type { AnyPgColumn } from "drizzle-orm/pg-core";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import {
  type KeysetSpec,
  keysetQuery,
  parseDate,
  parseNumber,
  parseText,
  type SortOption,
  sortSpec,
  toPage,
} from "../lib/paginate.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const c = schema.unifiConnection;
const s = schema.unifiSite;
/** What is reset whenever the IPS user (or the console) changes: the reported rights and their acknowledgement. */
const NO_RIGHTS = {
  ipsRights: [] as string[],
  ipsRightsAcknowledged: [] as string[],
  ipsRightsAcknowledgedAt: null,
  ipsRightsAcknowledgedBy: null,
};
const d = schema.unifiDevice;
type ConnectionRow = typeof c.$inferSelect;
type DeviceRow = typeof d.$inferSelect;
type SortKey = string | number | Date;

/** Same job options as the worker uses when its schedule queues a sync (apps/worker/src/unifi.ts). */
const SYNC_JOB = { retryLimit: 0, expireInSeconds: 15 * 60 };
const CERT_JOB = { retryLimit: 1, expireInSeconds: 5 * 60 };

const escapeLike = (text: string) => `%${text.replace(/[%_\\]/g, "\\$&")}%`;
const iso = (date: Date | null) => date?.toISOString() ?? null;

type FieldError = { field: string; code: string };
function invalid(errors: FieldError[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((e) => ({ path: e.field, message: e.code })),
  });
}

async function ownConnection(organizationId: string, id: string): Promise<ConnectionRow> {
  const [row] = await db
    .select()
    .from(c)
    .where(and(eq(c.id, id), eq(c.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("UniFi connection");
  return row;
}

const queueCertificate = (connectionId: string) =>
  boss.send(QUEUES.unifiCertificate, { connectionId }, { ...CERT_JOB, singletonKey: connectionId });

/** Queues a sync unless one is already waiting or running. */
async function queueSync(
  organizationId: string,
  connectionId: string,
  requestedBy: string | null,
  trigger: "manual" | "setup",
): Promise<{ runId: string; alreadyQueued: boolean }> {
  const r = schema.unifiSyncRun;
  const [active] = await db
    .select({ id: r.id })
    .from(r)
    .where(and(eq(r.connectionId, connectionId), inArray(r.state, ["queued", "running"])))
    .limit(1);
  if (active) return { runId: active.id, alreadyQueued: true };
  const runId = newId("ufr");
  await db.insert(r).values({
    id: runId,
    organizationId,
    connectionId,
    state: "queued",
    trigger,
    requestedBy,
    // Millisecond precision on purpose: this column is a pagination key (see lib/paginate.ts).
    createdAt: new Date(),
  });
  await boss.send(QUEUES.unifiSync, { runId }, { ...SYNC_JOB, singletonKey: connectionId });
  return { runId, alreadyQueued: false };
}

async function storeSecret(
  organizationId: string,
  userId: string,
  purpose: "unifi-api-key" | "unifi-ips-password",
  plain: string,
) {
  const id = newId("sec");
  await db.insert(schema.secret).values({
    id,
    organizationId,
    purpose,
    sealed: seal(plain, { organizationId, recordId: id, purpose }, vaultPublicKey),
    vaultKeyId: vaultPublicKey.id,
    createdBy: userId,
  });
  return id;
}

/* -------------------------------------------------------------------------- */
/* Presentation                                                                */
/* -------------------------------------------------------------------------- */

async function connectionStats(organizationId: string) {
  const devices = await db
    .select({
      connectionId: d.connectionId,
      devices: sql<number>`count(*)::int`,
      online: sql<number>`(count(*) filter (where ${d.state} = 'online'))::int`,
      offline: sql<number>`(count(*) filter (where ${d.state} = 'offline'))::int`,
      updatable: sql<number>`(count(*) filter (where ${d.firmwareUpdatable} is true))::int`,
    })
    .from(d)
    .where(eq(d.organizationId, organizationId))
    .groupBy(d.connectionId);
  const sites = await db
    .select({
      connectionId: s.connectionId,
      sites: sql<number>`count(*)::int`,
      clients: sql<number | null>`sum(${s.clientCount})::int`,
    })
    .from(s)
    .where(eq(s.organizationId, organizationId))
    .groupBy(s.connectionId);
  return (id: string) => {
    const a = devices.find((r) => r.connectionId === id);
    const b = sites.find((r) => r.connectionId === id);
    return {
      sites: b?.sites ?? 0,
      clients: b?.clients ?? null,
      devices: a?.devices ?? 0,
      online: a?.online ?? 0,
      offline: a?.offline ?? 0,
      updatable: a?.updatable ?? 0,
    };
  };
}

type Run = {
  id: string;
  state: "queued" | "running" | "succeeded" | "failed";
  trigger: "manual" | "schedule" | "setup";
  error: string | null;
  warnings: string[];
  createdAt: Date;
  finishedAt: Date | null;
};

async function latestRuns(connectionIds: string[]) {
  if (connectionIds.length === 0) return new Map<string, Run>();
  const r = schema.unifiSyncRun;
  const rows = await db
    .selectDistinctOn([r.connectionId], {
      connectionId: r.connectionId,
      id: r.id,
      state: r.state,
      trigger: r.trigger,
      error: r.error,
      warnings: r.warnings,
      createdAt: r.createdAt,
      finishedAt: r.finishedAt,
    })
    .from(r)
    .where(inArray(r.connectionId, connectionIds))
    .orderBy(r.connectionId, desc(r.createdAt), desc(r.id));
  return new Map(rows.map(({ connectionId, ...run }) => [connectionId, run]));
}

/** The state of the IPS preview of one connection, derived from facts (shared with the Attacks page). */
export function presentIps(row: ConnectionRow, admin: boolean, now = new Date()) {
  const status = ipsStatus({
    enabled: row.ipsEnabled,
    connectionEnabled: row.enabled,
    certificateOk: row.certStatus === "confirmed",
    hasCredentials: Boolean(row.ipsUsername && row.ipsSecretId),
    synced: row.apiBase !== "auto" && row.lastSyncAt !== null,
    rights: row.ipsRights,
    rightsAcknowledged: row.ipsRightsAcknowledged,
    lastPollAt: row.ipsLastPollAt,
    lastError: row.ipsLastError,
    intervalSeconds: row.ipsIntervalSeconds,
    now,
  });
  return {
    enabled: row.ipsEnabled,
    username: admin ? row.ipsUsername : null,
    hasPassword: row.ipsSecretId !== null,
    intervalSeconds: row.ipsIntervalSeconds,
    // Rights beyond viewing that the last login reported; the preview does not poll until an admin acknowledged them.
    rights: {
      reported: row.ipsRights,
      acknowledged: ipsRightsAcknowledged(row.ipsRights, row.ipsRightsAcknowledged),
      acknowledgedAt: iso(row.ipsRightsAcknowledgedAt),
    },
    state: status.state,
    reason: status.reason,
    error: status.error,
    lastPollAt: iso(row.ipsLastPollAt),
    lastEventAt: iso(row.ipsLastEventAt),
    enabledAt: iso(row.ipsEnabledAt),
  };
}

/** What the web app shows of a connection. Never the key or the password; the IPS user name only to admins. */
function presentConnection(
  row: ConnectionRow,
  admin: boolean,
  stats: ReturnType<Awaited<ReturnType<typeof connectionStats>>>,
  run: Run | null,
) {
  return {
    id: row.id,
    name: row.name,
    apiUrl: row.apiUrl,
    host: row.host,
    port: row.port,
    apiBase: row.apiBase,
    enabled: row.enabled,
    hasKey: row.secretId !== null,
    certificate: {
      status: row.certStatus,
      fingerprint: row.certFingerprint,
      subject: row.certSubject,
      issuer: row.certIssuer,
      validFrom: iso(row.certValidFrom),
      validTo: iso(row.certValidTo),
      confirmedAt: iso(row.certConfirmedAt),
      candidate: row.candidateFingerprint
        ? {
            fingerprint: row.candidateFingerprint,
            subject: row.candidateSubject,
            issuer: row.candidateIssuer,
            validFrom: iso(row.candidateValidFrom),
            validTo: iso(row.candidateValidTo),
            caTrusted: row.candidateCaTrusted,
            seenAt: iso(row.candidateSeenAt),
          }
        : null,
    },
    version: row.version,
    lastSyncAt: iso(row.lastSyncAt),
    lastError: row.lastError,
    counts: stats,
    ips: presentIps(row, admin),
    run,
    createdAt: row.createdAt,
  };
}

function presentDevice(row: DeviceRow & { connectionName: string; siteName: string }) {
  return {
    id: row.id,
    connectionId: row.connectionId,
    connectionName: row.connectionName,
    siteId: row.siteId,
    siteName: row.siteName,
    name: row.name,
    model: row.model,
    mac: row.mac,
    ip: row.ip,
    state: row.state,
    rawState: row.rawState,
    stateSince: iso(row.stateSince),
    firmwareVersion: row.firmwareVersion,
    firmwareUpdatable: row.firmwareUpdatable,
    latestFirmware: row.latestFirmware,
    firmware: firmwareStatus(row),
    uptimeSec: row.uptimeSec,
    flags: deviceFlags(row),
    firstSeenAt: iso(row.firstSeenAt),
    lastSeenAt: iso(row.lastSeenAt),
  };
}

/* -------------------------------------------------------------------------- */
/* Device list                                                                 */
/* -------------------------------------------------------------------------- */

const msKey = (col: AnyPgColumn) => sql`coalesce(date_trunc('milliseconds', ${col}), 'epoch'::timestamptz)`;
const SORTS = {
  name: { keys: [d.name], parse: [parseText], dir: "asc" },
  model: { keys: [sql`coalesce(${d.model}, '')`], parse: [parseText], dir: "asc" },
  site: { keys: [s.name], parse: [parseText], dir: "asc" },
  state: { keys: [d.state], parse: [parseText], dir: "asc" },
  ip: { keys: [sql`coalesce(${d.ip}, '')`], parse: [parseText], dir: "asc" },
  firmware: { keys: [sql`coalesce(${d.firmwareVersion}, '')`], parse: [parseText], dir: "asc" },
  uptime: { keys: [sql`coalesce(${d.uptimeSec}, -1)`], parse: [parseNumber], dir: "desc" },
  lastSeen: { keys: [msKey(d.lastSeenAt)], parse: [parseDate], dir: "desc" },
} satisfies Record<string, SortOption>;
type SortName = keyof typeof SORTS;
const sortNames = Object.keys(SORTS) as [SortName, ...SortName[]];

type ListRow = DeviceRow & { connectionName: string; siteName: string; sortKeys?: SortKey[] };
const defaultSpec: KeysetSpec<ListRow> = {
  keys: [d.name, d.id],
  direction: "asc",
  keyOf: (row) => [row.name, row.id],
  parse: [parseText, parseText],
};

const deviceFilters = {
  q: z.string().trim().max(100).optional(),
  connection: z.string().max(60).optional(),
  site: z.string().max(60).optional(),
  state: z.enum(["online", "offline", "other"]).optional(),
  /** "offline": the console calls the device offline. "update": a newer firmware is available. */
  flag: z.enum(["all", "offline", "update"]).default("all"),
};
const listQuery = z.object({
  ...deviceFilters,
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  sort: z.enum(sortNames).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

function deviceWhere(
  organizationId: string,
  input: z.infer<z.ZodObject<typeof deviceFilters>>,
  flag: string,
) {
  const like = input.q ? escapeLike(input.q) : null;
  return and(
    eq(d.organizationId, organizationId),
    input.connection ? eq(d.connectionId, input.connection) : undefined,
    input.site ? eq(d.siteId, input.site) : undefined,
    input.state ? eq(d.state, input.state) : undefined,
    like
      ? or(
          ilike(d.name, like),
          ilike(sql<string>`coalesce(${d.model}, '')`, like),
          ilike(sql<string>`coalesce(${d.mac}, '')`, like),
          ilike(sql<string>`coalesce(${d.ip}, '')`, like),
          ilike(sql<string>`coalesce(${d.firmwareVersion}, '')`, like),
        )
      : undefined,
    flag === "offline"
      ? eq(d.state, "offline")
      : flag === "update"
        ? eq(d.firmwareUpdatable, true)
        : undefined,
  );
}

/* -------------------------------------------------------------------------- */
/* Writes                                                                      */
/* -------------------------------------------------------------------------- */

const createBody = z.object({
  name: z.string().max(300),
  apiUrl: z.string().max(400),
  apiKey: z.string().max(400),
  apiBase: z.enum(API_BASE_CHOICES).default("auto"),
});
const patchBody = z.object({
  name: z.string().max(300).optional(),
  enabled: z.boolean().optional(),
  apiUrl: z.string().max(400).optional(),
  apiKey: z.string().max(400).optional(),
  apiBase: z.enum(API_BASE_CHOICES).optional(),
});
const acknowledgeRightsBody = z.object({ rights: z.array(z.string().max(64)).max(20) });

const ipsBody = z
  .object({
    enabled: z.boolean().optional(),
    intervalSeconds: z.number().optional(),
    username: z.string().max(200).optional(),
    password: z.string().max(400).optional(),
    /** Switching the preview on needs this: the admin has read what "preview" means. */
    acknowledgePreview: z.boolean().optional(),
  })
  .strict();
const confirmBody = z.object({ fingerprint: z.string().max(100) });

export const unifiRoutes = new Hono<AppEnv>()
  /* ------------------------------ connections ------------------------------ */
  .get("/connections", async (c2) => {
    const actor = c2.get("actor");
    const admin = actor.role === "owner" || actor.role === "admin";
    const rows = await db.select().from(c).where(eq(c.organizationId, actor.organizationId)).orderBy(c.name);
    const [stats, runs] = await Promise.all([
      connectionStats(actor.organizationId),
      latestRuns(rows.map((r) => r.id)),
    ]);
    return c2.json({
      syncIntervalMinutes: UNIFI_SYNC_INTERVAL_MINUTES,
      ips: { intervalSeconds: IPS_INTERVAL_SECONDS },
      items: rows.map((row) => presentConnection(row, admin, stats(row.id), runs.get(row.id) ?? null)),
    });
  })
  .post("/connections", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = createBody.parse(await c2.req.json());
    const errors: FieldError[] = [];
    const name = checkConnectionName(body.name);
    if (name === null) errors.push({ field: "name", code: "name_invalid" });
    const url = checkUnifiUrl(body.apiUrl);
    if (!url.ok) errors.push({ field: "apiUrl", code: `url_${url.problem}` });
    if (!API_KEY_PATTERN.test(body.apiKey)) errors.push({ field: "apiKey", code: "key_invalid" });
    if (errors.length > 0 || name === null || !url.ok) throw invalid(errors);
    requireRecentSignIn(actor);

    const existing = await db
      .select({ name: c.name, host: c.host, port: c.port })
      .from(c)
      .where(eq(c.organizationId, actor.organizationId));
    if (existing.length >= MAX_UNIFI_CONNECTIONS) {
      throw new ProblemError(
        409,
        "limit-reached",
        "The organisation has reached the number of UniFi connections it may have",
      );
    }
    if (existing.some((e) => e.name === name || (e.host === url.host && e.port === url.port))) {
      throw new ProblemError(409, "duplicate", "This UniFi connection is already added");
    }
    const id = newId("ufc");
    const secretId = await storeSecret(actor.organizationId, actor.userId, "unifi-api-key", body.apiKey);
    await db.insert(c).values({
      id,
      organizationId: actor.organizationId,
      name,
      apiUrl: url.url,
      host: url.host,
      port: url.port,
      apiBase: body.apiBase,
      secretId,
      createdBy: actor.userId,
    });
    await audit(
      actor,
      "unifi.connection_created",
      { type: "unifi_connection", id },
      { name, apiUrl: url.url, apiBase: body.apiBase },
    );
    await queueCertificate(id);
    return c2.json({ id }, 201);
  })
  .patch("/connections/:id", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = patchBody.parse(await c2.req.json());
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    const errors: FieldError[] = [];
    const changes: Partial<typeof c.$inferInsert> = {};
    const changed: string[] = [];

    if (body.name !== undefined) {
      const name = checkConnectionName(body.name);
      if (name === null) errors.push({ field: "name", code: "name_invalid" });
      else if (name !== row.name) {
        changes.name = name;
        changed.push("name");
      }
    }
    if (body.enabled !== undefined && body.enabled !== row.enabled) {
      changes.enabled = body.enabled;
      changed.push("enabled");
    }
    let repoint = false;
    if (body.apiUrl !== undefined) {
      const url = checkUnifiUrl(body.apiUrl);
      if (!url.ok) errors.push({ field: "apiUrl", code: `url_${url.problem}` });
      else if (url.host !== row.host || url.port !== row.port) {
        Object.assign(changes, { apiUrl: url.url, host: url.host, port: url.port });
        changed.push("apiUrl");
        repoint = true;
      }
    }
    if (body.apiBase !== undefined && body.apiBase !== row.apiBase) {
      changes.apiBase = body.apiBase;
      changed.push("apiBase");
    }
    let newKey = false;
    if (body.apiKey !== undefined) {
      if (!API_KEY_PATTERN.test(body.apiKey)) errors.push({ field: "apiKey", code: "key_invalid" });
      else {
        changed.push("key");
        newKey = true;
      }
    }
    if (errors.length > 0) throw invalid(errors);
    if (changed.length === 0) return c2.body(null, 204);
    // Renaming, switching on or off and the API path are harmless; where the platform connects and with what is not.
    if (repoint || newKey) requireRecentSignIn(actor);
    if (changes.name || changes.host !== undefined) {
      const others = await db
        .select({ id: c.id, name: c.name, host: c.host, port: c.port })
        .from(c)
        .where(eq(c.organizationId, actor.organizationId));
      const host = changes.host ?? row.host;
      const port = changes.port ?? row.port;
      const name = changes.name ?? row.name;
      if (others.some((o) => o.id !== row.id && (o.name === name || (o.host === host && o.port === port)))) {
        throw new ProblemError(409, "duplicate", "This UniFi connection is already added");
      }
    }

    let oldSecretId: string | null = null;
    if (newKey && body.apiKey !== undefined) {
      changes.secretId = await storeSecret(actor.organizationId, actor.userId, "unifi-api-key", body.apiKey);
      oldSecretId = row.secretId;
    }
    if (repoint) {
      // Another console: nothing about the old one is trusted any more, and the IPS preview stops until it is set up again.
      Object.assign(changes, {
        certStatus: "pending",
        certFingerprint: null,
        certSubject: null,
        certIssuer: null,
        certValidFrom: null,
        certValidTo: null,
        certConfirmedAt: null,
        certConfirmedBy: null,
        candidateFingerprint: null,
        candidateSubject: null,
        candidateIssuer: null,
        candidateValidFrom: null,
        candidateValidTo: null,
        candidateCaTrusted: null,
        candidateSeenAt: null,
        lastError: null,
        ipsCursorAt: null,
        ...NO_RIGHTS,
      });
    }
    await db.transaction(async (tx) => {
      await tx
        .update(c)
        .set({ ...changes, updatedAt: new Date() })
        .where(eq(c.id, row.id));
      if (oldSecretId) await tx.delete(schema.secret).where(eq(schema.secret.id, oldSecretId));
    });
    await audit(
      actor,
      "unifi.connection_changed",
      { type: "unifi_connection", id: row.id },
      {
        name: changes.name ?? row.name,
        changed,
        ...(changes.apiUrl ? { apiUrl: changes.apiUrl, previous: row.apiUrl } : {}),
      },
    );
    if (repoint) await queueCertificate(row.id);
    else if (newKey && row.certStatus === "confirmed") {
      await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    }
    return c2.body(null, 204);
  })
  .delete("/connections/:id", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    await db.transaction(async (tx) => {
      await tx.delete(c).where(eq(c.id, row.id));
      const secrets = [row.secretId, row.ipsSecretId].filter((x): x is string => x !== null);
      if (secrets.length > 0) await tx.delete(schema.secret).where(inArray(schema.secret.id, secrets));
    });
    await audit(
      actor,
      "unifi.connection_deleted",
      { type: "unifi_connection", id: row.id },
      { name: row.name, apiUrl: row.apiUrl },
    );
    return c2.body(null, 204);
  })
  .post("/connections/:id/certificate/scan", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    await rateLimit(`unifi-cert:${actor.organizationId}`, 30, 60 * 60_000);
    await queueCertificate(row.id);
    await audit(
      actor,
      "unifi.certificate_scan_requested",
      { type: "unifi_connection", id: row.id },
      { name: row.name },
    );
    return c2.body(null, 202);
  })
  .post("/connections/:id/certificate/confirm", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const input = confirmBody.parse(await c2.req.json());
    const fingerprint = normalizeFingerprint(input.fingerprint);
    if (!fingerprint) throw invalid([{ field: "fingerprint", code: "fingerprint_invalid" }]);
    requireRecentSignIn(actor);
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    if (!row.candidateFingerprint) {
      throw new ProblemError(409, "no-certificate", "There is no certificate waiting for confirmation");
    }
    // The admin confirms the fingerprint they compared, not "whatever is pending now".
    if (row.candidateFingerprint !== fingerprint) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The certificate has changed since it was shown; compare the new fingerprint",
      );
    }
    const now = new Date();
    const updated = await db
      .update(c)
      .set({
        certStatus: "confirmed",
        certFingerprint: row.candidateFingerprint,
        certSubject: row.candidateSubject,
        certIssuer: row.candidateIssuer,
        certValidFrom: row.candidateValidFrom,
        certValidTo: row.candidateValidTo,
        certConfirmedAt: now,
        certConfirmedBy: actor.userId,
        candidateFingerprint: null,
        candidateSubject: null,
        candidateIssuer: null,
        candidateValidFrom: null,
        candidateValidTo: null,
        candidateCaTrusted: null,
        candidateSeenAt: null,
        lastError: null,
        updatedAt: now,
      })
      .where(and(eq(c.id, row.id), eq(c.candidateFingerprint, fingerprint)))
      .returning({ id: c.id });
    if (updated.length === 0) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The certificate has changed since it was shown; compare the new fingerprint",
      );
    }
    await audit(
      actor,
      "unifi.certificate_confirmed",
      { type: "unifi_connection", id: row.id },
      {
        name: row.name,
        fingerprint,
        subject: row.candidateSubject,
        issuer: row.candidateIssuer,
        caTrusted: row.candidateCaTrusted,
        previous: row.certFingerprint,
      },
    );
    const run = await queueSync(
      actor.organizationId,
      row.id,
      actor.userId,
      row.certFingerprint ? "manual" : "setup",
    );
    return c2.json({ runId: run.runId });
  })
  .post("/connections/:id/sync", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    if (row.certStatus !== "confirmed") {
      throw new ProblemError(
        409,
        "certificate-unconfirmed",
        "Confirm the certificate of this UniFi console first",
      );
    }
    await rateLimit(`unifi-sync:${actor.organizationId}`, 60, 60 * 60_000);
    const result = await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    if (!result.alreadyQueued) {
      await audit(
        actor,
        "unifi.sync_requested",
        { type: "unifi_connection", id: row.id },
        { runId: result.runId, name: row.name },
      );
    }
    return c2.json(result, result.alreadyQueued ? 200 : 202);
  })
  .get("/connections/:id/runs", async (c2) => {
    const actor = c2.get("actor");
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    const r = schema.unifiSyncRun;
    const runs = await db
      .select({
        id: r.id,
        state: r.state,
        trigger: r.trigger,
        siteCount: r.siteCount,
        deviceCount: r.deviceCount,
        requestCount: r.requestCount,
        warnings: r.warnings,
        error: r.error,
        startedAt: r.startedAt,
        finishedAt: r.finishedAt,
        createdAt: r.createdAt,
      })
      .from(r)
      .where(eq(r.connectionId, row.id))
      .orderBy(desc(r.createdAt), desc(r.id))
      .limit(10);
    return c2.json(runs);
  })

  /* ------------------------------ IPS preview ------------------------------ */
  .put("/connections/:id/ips", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = ipsBody.parse(await c2.req.json());
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    const errors: FieldError[] = [];
    const changes: Partial<typeof c.$inferInsert> = {};
    const changed: string[] = [];

    let username = row.ipsUsername;
    if (body.username !== undefined) {
      const check = checkIpsUsername(body.username);
      if (!check.ok) errors.push({ field: "username", code: `username_${check.problem}` });
      else if (check.value !== row.ipsUsername) {
        username = check.value;
        changes.ipsUsername = check.value;
        changed.push("username");
      }
    }
    let newPassword = false;
    if (body.password !== undefined) {
      if (!IPS_PASSWORD_PATTERN.test(body.password))
        errors.push({ field: "password", code: "password_invalid" });
      else {
        newPassword = true;
        changed.push("password");
      }
    }
    if (body.intervalSeconds !== undefined) {
      if (!isIpsInterval(body.intervalSeconds))
        errors.push({ field: "intervalSeconds", code: "interval_invalid" });
      else if (body.intervalSeconds !== row.ipsIntervalSeconds) {
        changes.ipsIntervalSeconds = body.intervalSeconds;
        changed.push("interval");
      }
    }
    const enabling = body.enabled === true && !row.ipsEnabled;
    if (body.enabled !== undefined && body.enabled !== row.ipsEnabled) {
      changes.ipsEnabled = body.enabled;
      changed.push(body.enabled ? "enabled" : "disabled");
    }
    if (enabling) {
      if (body.acknowledgePreview !== true)
        errors.push({ field: "acknowledgePreview", code: "preview_not_acknowledged" });
      if (!username && !errors.some((e) => e.field === "username")) {
        errors.push({ field: "username", code: "username_missing" });
      }
      if (!newPassword && !row.ipsSecretId) errors.push({ field: "password", code: "password_missing" });
    }
    // A user name or a password change on a preview that is on (or stays on) needs the pair.
    if (
      (body.username !== undefined || newPassword) &&
      !username &&
      !errors.some((e) => e.field === "username")
    ) {
      errors.push({ field: "username", code: "username_missing" });
    }
    if (errors.length > 0) throw invalid(errors);
    if (changed.length === 0) return c2.body(null, 204);
    // Switching the preview off is always allowed. Everything that starts it or changes who logs in is a credential matter.
    if (enabling || newPassword || changes.ipsUsername !== undefined) requireRecentSignIn(actor);

    let oldSecretId: string | null = null;
    if (newPassword && body.password !== undefined) {
      changes.ipsSecretId = await storeSecret(
        actor.organizationId,
        actor.userId,
        "unifi-ips-password",
        body.password,
      );
      oldSecretId = row.ipsSecretId;
    }
    if (newPassword || changes.ipsUsername !== undefined) {
      // Another user: what was reported and acknowledged for the earlier one counts for nothing. The next login
      // reports the rights of this one, and the preview does not read anything before that.
      Object.assign(changes, { ...NO_RIGHTS, ipsFailures: 0, ipsLastError: null, ipsNextPollAt: new Date() });
    }
    if (enabling) {
      Object.assign(changes, {
        ipsEnabledBy: actor.userId,
        ipsEnabledAt: new Date(),
        ipsNextPollAt: new Date(),
        ipsFailures: 0,
        ipsLastError: null,
      });
    }
    await db.transaction(async (tx) => {
      await tx
        .update(c)
        .set({ ...changes, updatedAt: new Date() })
        .where(eq(c.id, row.id));
      if (oldSecretId) await tx.delete(schema.secret).where(eq(schema.secret.id, oldSecretId));
    });
    await audit(
      actor,
      "unifi.ips_changed",
      { type: "unifi_connection", id: row.id },
      {
        name: row.name,
        changed,
        ...(username ? { user: username } : {}),
        ...(changes.ipsIntervalSeconds ? { intervalSeconds: changes.ipsIntervalSeconds } : {}),
      },
    );
    return c2.body(null, 204);
  })
  .post("/connections/:id/ips/rights/acknowledge", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const input = acknowledgeRightsBody.parse(await c2.req.json());
    requireRecentSignIn(actor);
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    if (row.ipsRights.length === 0) {
      throw new ProblemError(409, "no-extra-rights", "The IPS user has no rights beyond viewing");
    }
    // The admin acknowledges the list they were shown, not "whatever the user can do now".
    if (!sameRights(input.rights, row.ipsRights)) {
      throw new ProblemError(
        409,
        "rights-changed",
        "The rights of the IPS user have changed since they were shown",
      );
    }
    const updated = await db
      .update(c)
      .set({
        ipsRightsAcknowledged: row.ipsRights,
        ipsRightsAcknowledgedAt: new Date(),
        ipsRightsAcknowledgedBy: actor.userId,
        ipsLastError: null,
        // The poll starts at once; the worker looks at the rights again with its next login.
        ipsNextPollAt: new Date(),
        updatedAt: new Date(),
      })
      // Only if the worker has not recorded other rights meanwhile.
      .where(and(eq(c.id, row.id), sql`${c.ipsRights} = ${JSON.stringify(row.ipsRights)}::jsonb`))
      .returning({ id: c.id });
    if (updated.length === 0) {
      throw new ProblemError(
        409,
        "rights-changed",
        "The rights of the IPS user have changed since they were shown",
      );
    }
    await audit(
      actor,
      "unifi.ips_rights_acknowledged",
      { type: "unifi_connection", id: row.id },
      { name: row.name, user: row.ipsUsername, rights: row.ipsRights.slice(0, 20) },
    );
    return c2.body(null, 204);
  })
  .delete("/connections/:id/ips", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const row = await ownConnection(actor.organizationId, c2.req.param("id"));
    await db.transaction(async (tx) => {
      await tx
        .update(c)
        .set({
          ipsEnabled: false,
          ipsUsername: null,
          ipsSecretId: null,
          ...NO_RIGHTS,
          ipsFailures: 0,
          ipsLastError: null,
          updatedAt: new Date(),
        })
        .where(eq(c.id, row.id));
      if (row.ipsSecretId) await tx.delete(schema.secret).where(eq(schema.secret.id, row.ipsSecretId));
    });
    await audit(actor, "unifi.ips_removed", { type: "unifi_connection", id: row.id }, { name: row.name });
    return c2.body(null, 204);
  })

  /* ------------------------------ sites and devices ------------------------------ */
  .get("/sites", async (c2) => {
    const actor = c2.get("actor");
    const rows = await db
      .select({ ...getTableColumns(s), connectionName: c.name })
      .from(s)
      .innerJoin(c, eq(c.id, s.connectionId))
      .where(eq(s.organizationId, actor.organizationId))
      .orderBy(c.name, s.name)
      .limit(500);
    return c2.json(
      rows.map((r) => ({
        id: r.id,
        connectionId: r.connectionId,
        connectionName: r.connectionName,
        name: r.name,
        clients: r.clientCount,
      })),
    );
  })
  .get("/devices", async (c2) => {
    const actor = c2.get("actor");
    const input = listQuery.parse(c2.req.query());
    const where = deviceWhere(actor.organizationId, input, input.flag);
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, d.id) : null;
    const activeSpec = (sorted?.spec ?? defaultSpec) as KeysetSpec<ListRow>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          ...getTableColumns(d),
          connectionName: c.name,
          siteName: s.name,
          sortKeys: sorted ? sorted.select : sql<null>`null`,
        })
        .from(d)
        .innerJoin(c, eq(c.id, d.connectionId))
        .innerJoin(s, eq(s.id, d.siteId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db
        .select({ n: count() })
        .from(d)
        .innerJoin(c, eq(c.id, d.connectionId))
        .innerJoin(s, eq(s.id, d.siteId))
        .where(where),
    ]);
    const page = toPage(
      activeSpec,
      q,
      rows as ListRow[],
      totalRow[0]?.n ?? 0,
      input.pageSize,
      Boolean(input.cursor),
      (row) => row,
    );
    return c2.json({ ...page, items: page.items.map(presentDevice) });
  })
  .get("/devices/counts", async (c2) => {
    const actor = c2.get("actor");
    const input = z.object(deviceFilters).parse(c2.req.query());
    const counts = await Promise.all(
      (["all", "offline", "update"] as const).map(async (flag) => {
        const [row] = await db
          .select({ n: count() })
          .from(d)
          .where(deviceWhere(actor.organizationId, input, flag));
        return [flag, row?.n ?? 0] as const;
      }),
    );
    return c2.json(Object.fromEntries(counts));
  })
  .get("/devices/:id", async (c2) => {
    const actor = c2.get("actor");
    const [row] = await db
      .select({ ...getTableColumns(d), connectionName: c.name, siteName: s.name })
      .from(d)
      .innerJoin(c, eq(c.id, d.connectionId))
      .innerJoin(s, eq(s.id, d.siteId))
      .where(and(eq(d.id, c2.req.param("id")), eq(d.organizationId, actor.organizationId)))
      .limit(1);
    if (!row) throw notFound("Device");
    return c2.json(presentDevice(row));
  });
