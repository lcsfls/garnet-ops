/**
 * Proxmox VE (ADR 0012): read-only inventory of clusters, nodes and guests. Everyone in the
 * organisation reads; owners and admins configure. Creating, re-pointing and removing a
 * connection, confirming a certificate and acknowledging a token with more than audit
 * privileges also need a recent sign-in (step-up). The API only seals the token secret; the
 * worker opens it and is the only component that talks to Proxmox. Responses never contain the
 * secret, certificates or anything Proxmox sent beyond the fields stored by the sync.
 */
import { newId } from "@garnetops/core";
import { pageSizeSchema } from "@garnetops/core/pagination";
import {
  checkClusterName,
  checkProxmoxUrl,
  checkTokenId,
  MAX_PROXMOX_CLUSTERS,
  normalizeFingerprint,
  privilegesAcknowledged,
  TOKEN_SECRET_PATTERN,
} from "@garnetops/core/proxmox";
import {
  GUEST_STATUSES,
  type GuestFlag,
  guestFlags,
  PROXMOX_SYNC_INTERVAL_MINUTES,
  proxmoxSourceRef,
  STALE_BACKUP_DAYS,
  STALE_SNAPSHOT_DAYS,
  STALE_STOPPED_DAYS,
} from "@garnetops/core/proxmox-flags";
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

const c = schema.proxmoxCluster;
const g = schema.proxmoxGuest;
const n = schema.proxmoxNode;
const h = schema.host;
type ClusterRow = typeof c.$inferSelect;
type GuestRow = typeof g.$inferSelect;
type SortKey = string | number | Date;

/** Same job options as the worker uses when its schedule queues a sync (apps/worker/src/proxmox.ts). */
const SYNC_JOB = { retryLimit: 0, expireInSeconds: 15 * 60 };
const CERT_JOB = { retryLimit: 1, expireInSeconds: 5 * 60 };

const escapeLike = (text: string) => `%${text.replace(/[%_\\]/g, "\\$&")}%`;

function invalid(errors: { field: string; code: string }[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((e) => ({ path: e.field, message: e.code })),
  });
}

async function ownCluster(organizationId: string, id: string): Promise<ClusterRow> {
  const [row] = await db
    .select()
    .from(c)
    .where(and(eq(c.id, id), eq(c.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Proxmox connection");
  return row;
}

const queueCertificate = (clusterId: string) =>
  boss.send(QUEUES.proxmoxCertificate, { clusterId }, { ...CERT_JOB, singletonKey: clusterId });

/** Queues a sync unless one is already waiting or running. */
async function queueSync(
  organizationId: string,
  clusterId: string,
  requestedBy: string | null,
  trigger: "manual" | "setup",
): Promise<{ runId: string; alreadyQueued: boolean }> {
  const r = schema.proxmoxSyncRun;
  const [active] = await db
    .select({ id: r.id })
    .from(r)
    .where(and(eq(r.clusterId, clusterId), inArray(r.state, ["queued", "running"])))
    .limit(1);
  if (active) return { runId: active.id, alreadyQueued: true };
  const runId = newId("pxr");
  await db.insert(r).values({
    id: runId,
    organizationId,
    clusterId,
    state: "queued",
    trigger,
    requestedBy,
    // Millisecond precision on purpose: this column is a pagination key (see lib/paginate.ts).
    createdAt: new Date(),
  });
  await boss.send(QUEUES.proxmoxSync, { runId }, { ...SYNC_JOB, singletonKey: clusterId });
  return { runId, alreadyQueued: false };
}

/* -------------------------------------------------------------------------- */
/* Flags as SQL: the same rules as packages/core/src/proxmox-flags.ts           */
/* -------------------------------------------------------------------------- */

const days = (d: number) => sql.raw(`interval '${Math.trunc(d)} days'`);
/** A server of the Servers list is linked to the guest through source_ref (`cluster:vmid`). */
const linked = sql`exists (select 1 from ${h} where ${h.organizationId} = ${g.organizationId}
  and ${h.source} = 'proxmox' and ${h.sourceRef} = ${g.clusterId} || ':' || ${g.vmid}::text)`;
const stoppedLong = sql`(${g.status} = 'stopped' and not ${g.template} and ${g.statusSince} < now() - ${days(STALE_STOPPED_DAYS)})`;
const noBackup = sql`(not ${g.template} and ${c.backupsReadable} and (${g.lastBackupAt} is null or ${g.lastBackupAt} < now() - ${days(STALE_BACKUP_DAYS)}))`;
const oldSnapshot = sql`(not ${g.template} and ${g.oldestSnapshotAt} < now() - ${days(STALE_SNAPSHOT_DAYS)})`;
const untracked = sql`(${g.status} = 'running' and not ${g.template} and not ${linked})`;
const stale = sql`(${stoppedLong} or ${noBackup} or ${oldSnapshot})`;

/* -------------------------------------------------------------------------- */
/* Presentation                                                                */
/* -------------------------------------------------------------------------- */

const iso = (d: Date | null) => d?.toISOString() ?? null;

async function clusterStats(organizationId: string) {
  const rows = await db
    .select({
      clusterId: g.clusterId,
      guests: sql<number>`count(*)::int`,
      running: sql<number>`(count(*) filter (where ${g.status} = 'running'))::int`,
      templates: sql<number>`(count(*) filter (where ${g.template}))::int`,
      stale: sql<number>`(count(*) filter (where ${stale}))::int`,
      untracked: sql<number>`(count(*) filter (where ${untracked}))::int`,
    })
    .from(g)
    .innerJoin(c, eq(c.id, g.clusterId))
    .where(eq(g.organizationId, organizationId))
    .groupBy(g.clusterId);
  const nodes = await db
    .select({
      clusterId: n.clusterId,
      nodes: sql<number>`count(*)::int`,
      online: sql<number>`(count(*) filter (where ${n.online}))::int`,
      withUpdates: sql<number>`(count(*) filter (where coalesce(${n.pendingUpdates}, 0) > 0))::int`,
      updates: sql<number>`coalesce(sum(${n.pendingUpdates}), 0)::int`,
    })
    .from(n)
    .where(eq(n.organizationId, organizationId))
    .groupBy(n.clusterId);
  const empty = { guests: 0, running: 0, templates: 0, stale: 0, untracked: 0 };
  const emptyNodes = { nodes: 0, online: 0, withUpdates: 0, updates: 0 };
  return (id: string) => {
    const { clusterId: _g, ...guestFigures } = rows.find((r) => r.clusterId === id) ?? {
      clusterId: id,
      ...empty,
    };
    const { clusterId: _n, ...nodeFigures } = nodes.find((r) => r.clusterId === id) ?? {
      clusterId: id,
      ...emptyNodes,
    };
    return { ...guestFigures, ...nodeFigures };
  };
}

async function latestRuns(clusterIds: string[]) {
  if (clusterIds.length === 0) return new Map<string, Run>();
  const r = schema.proxmoxSyncRun;
  const rows = await db
    .selectDistinctOn([r.clusterId], {
      clusterId: r.clusterId,
      id: r.id,
      state: r.state,
      trigger: r.trigger,
      error: r.error,
      warnings: r.warnings,
      createdAt: r.createdAt,
      finishedAt: r.finishedAt,
    })
    .from(r)
    .where(inArray(r.clusterId, clusterIds))
    .orderBy(r.clusterId, desc(r.createdAt), desc(r.id));
  return new Map(rows.map(({ clusterId, ...run }) => [clusterId, run]));
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

/** What the web app shows of a connection. Never the secret; the token id and the endpoint only to admins. */
function presentCluster(
  row: ClusterRow,
  admin: boolean,
  stats: ReturnType<Awaited<ReturnType<typeof clusterStats>>>,
  run: Run | null,
) {
  return {
    id: row.id,
    name: row.name,
    apiUrl: row.apiUrl,
    host: row.host,
    port: row.port,
    tokenId: admin ? row.tokenId : null,
    enabled: row.enabled,
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
    privileges: {
      /** Privileges of the token beyond *.Audit; empty means the token can only read. */
      extra: row.extraPrivileges,
      acknowledged: privilegesAcknowledged(row.extraPrivileges, row.acknowledgedPrivileges),
      acknowledgedAt: iso(row.privilegesAcknowledgedAt),
      checkedAt: iso(row.permissionsCheckedAt),
    },
    version: row.version,
    clusterName: row.clusterName,
    quorate: row.quorate,
    backupsReadable: row.backupsReadable,
    lastSyncAt: iso(row.lastSyncAt),
    lastError: row.lastError,
    counts: stats,
    run,
    createdAt: row.createdAt,
  };
}

/** Servers linked to the guests of one page: `source = proxmox` and `source_ref = cluster:vmid`. */
async function linkedServers(organizationId: string, rows: Pick<GuestRow, "clusterId" | "vmid">[]) {
  const map = new Map<string, { id: string; name: string }>();
  if (rows.length === 0) return map;
  const refs = rows.map((r) => proxmoxSourceRef(r.clusterId, r.vmid));
  const found = await db
    .select({ id: h.id, name: h.name, ref: h.sourceRef })
    .from(h)
    .where(and(eq(h.organizationId, organizationId), eq(h.source, "proxmox"), inArray(h.sourceRef, refs)));
  for (const f of found) if (f.ref) map.set(f.ref, { id: f.id, name: f.name });
  return map;
}

function presentGuest(
  row: GuestRow & { clusterName: string; backupsReadable: boolean },
  server: { id: string; name: string } | null,
  now: Date,
) {
  const flags: GuestFlag[] = guestFlags(
    {
      status: row.status,
      template: row.template,
      statusSince: row.statusSince,
      lastBackupAt: row.lastBackupAt,
      oldestSnapshotAt: row.oldestSnapshotAt,
      backupsReadable: row.backupsReadable,
      linked: server !== null,
    },
    now,
  );
  return {
    id: row.id,
    clusterId: row.clusterId,
    clusterName: row.clusterName,
    vmid: row.vmid,
    type: row.type,
    name: row.name,
    node: row.node,
    status: row.status,
    statusSince: iso(row.statusSince),
    cpu: row.cpu,
    cpus: row.cpus,
    mem: row.mem,
    maxMem: row.maxMem,
    disk: row.disk,
    maxDisk: row.maxDisk,
    uptime: row.uptime,
    ostype: row.ostype,
    tags: row.tags,
    template: row.template,
    haState: row.haState,
    backup: { inJob: row.inBackupJob, lastAt: iso(row.lastBackupAt), readable: row.backupsReadable },
    snapshots: {
      count: row.snapshotCount,
      newestAt: iso(row.newestSnapshotAt),
      oldestAt: iso(row.oldestSnapshotAt),
    },
    ips: row.ips,
    flags,
    server,
    lastSeenAt: iso(row.lastSeenAt),
  };
}

/* -------------------------------------------------------------------------- */
/* Guest list                                                                  */
/* -------------------------------------------------------------------------- */

const msKey = (col: AnyPgColumn) => sql`coalesce(date_trunc('milliseconds', ${col}), 'epoch'::timestamptz)`;
const SORTS = {
  name: { keys: [g.name], parse: [parseText], dir: "asc" },
  vmid: { keys: [g.vmid], parse: [parseNumber], dir: "asc" },
  node: { keys: [g.node], parse: [parseText], dir: "asc" },
  status: { keys: [g.status], parse: [parseText], dir: "asc" },
  cpu: { keys: [sql`coalesce(${g.cpu}, -1)`], parse: [parseNumber], dir: "desc" },
  mem: { keys: [sql`coalesce(${g.mem}, -1)`], parse: [parseNumber], dir: "desc" },
  disk: { keys: [sql`coalesce(${g.maxDisk}, -1)`], parse: [parseNumber], dir: "desc" },
  uptime: { keys: [sql`coalesce(${g.uptime}, -1)`], parse: [parseNumber], dir: "desc" },
  lastBackup: { keys: [msKey(g.lastBackupAt)], parse: [parseDate], dir: "asc" },
  snapshot: { keys: [msKey(g.oldestSnapshotAt)], parse: [parseDate], dir: "asc" },
} satisfies Record<string, SortOption>;
type SortName = keyof typeof SORTS;
const sortNames = Object.keys(SORTS) as [SortName, ...SortName[]];

type ListRow = GuestRow & { clusterName: string; backupsReadable: boolean; sortKeys?: SortKey[] };
const defaultSpec: KeysetSpec<ListRow> = {
  keys: [g.name, g.id],
  direction: "asc",
  keyOf: (row) => [row.name, row.id],
  parse: [parseText, parseText],
};

const guestFilters = {
  q: z.string().trim().max(100).optional(),
  cluster: z.string().max(60).optional(),
  type: z.enum(["qemu", "lxc"]).optional(),
  status: z.enum(GUEST_STATUSES).optional(),
  node: z.string().max(63).optional(),
  /** "stale": stopped for long, no recent backup or an old snapshot. "untracked": running, no linked server. */
  flag: z.enum(["all", "stale", "untracked"]).default("all"),
};
const listQuery = z.object({
  ...guestFilters,
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  sort: z.enum(sortNames).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

function guestWhere(organizationId: string, input: z.infer<z.ZodObject<typeof guestFilters>>, flag: string) {
  const like = input.q ? escapeLike(input.q) : null;
  return and(
    eq(g.organizationId, organizationId),
    input.cluster ? eq(g.clusterId, input.cluster) : undefined,
    input.type ? eq(g.type, input.type) : undefined,
    input.status ? eq(g.status, input.status) : undefined,
    input.node ? eq(g.node, input.node) : undefined,
    like
      ? or(
          ilike(g.name, like),
          sql`${g.vmid}::text like ${like}`,
          ilike(sql<string>`coalesce(${g.ostype}, '')`, like),
          sql`${g.ips}::text ilike ${like}`,
          sql`${g.tags}::text ilike ${like}`,
        )
      : undefined,
    flag === "stale" ? stale : flag === "untracked" ? untracked : undefined,
  );
}

/* -------------------------------------------------------------------------- */
/* Writes                                                                      */
/* -------------------------------------------------------------------------- */

const createBody = z.object({
  name: z.string().max(300),
  apiUrl: z.string().max(400),
  tokenId: z.string().max(200),
  tokenSecret: z.string().max(400),
});
const patchBody = z.object({
  name: z.string().max(300).optional(),
  enabled: z.boolean().optional(),
  apiUrl: z.string().max(400).optional(),
  tokenId: z.string().max(200).optional(),
  tokenSecret: z.string().max(400).optional(),
});

function validateEndpoint(apiUrl: string, errors: { field: string; code: string }[]) {
  const url = checkProxmoxUrl(apiUrl);
  if (!url.ok) errors.push({ field: "apiUrl", code: `url_${url.problem}` });
  return url.ok ? url : null;
}
function validateToken(
  tokenId: string,
  tokenSecret: string | undefined,
  errors: { field: string; code: string }[],
) {
  const id = checkTokenId(tokenId);
  if (!id.ok) errors.push({ field: "tokenId", code: `token_${id.problem}` });
  if (tokenSecret !== undefined && !TOKEN_SECRET_PATTERN.test(tokenSecret)) {
    errors.push({ field: "tokenSecret", code: "secret_invalid" });
  }
  return id.ok ? id.value : null;
}

async function storeSecret(organizationId: string, userId: string, plain: string) {
  const id = newId("sec");
  await db.insert(schema.secret).values({
    id,
    organizationId,
    purpose: "proxmox-token",
    sealed: seal(plain, { organizationId, recordId: id, purpose: "proxmox-token" }, vaultPublicKey),
    vaultKeyId: vaultPublicKey.id,
    createdBy: userId,
  });
  return id;
}

const confirmBody = z.object({ fingerprint: z.string().max(100) });
const acknowledgeBody = z.object({ privileges: z.array(z.string().max(64)).max(200) });

export const proxmoxRoutes = new Hono<AppEnv>()
  /* ------------------------------ connections ------------------------------ */
  .get("/clusters", async (c2) => {
    const actor = c2.get("actor");
    const admin = actor.role === "owner" || actor.role === "admin";
    const rows = await db.select().from(c).where(eq(c.organizationId, actor.organizationId)).orderBy(c.name);
    const [stats, runs] = await Promise.all([
      clusterStats(actor.organizationId),
      latestRuns(rows.map((r) => r.id)),
    ]);
    return c2.json({
      syncIntervalMinutes: PROXMOX_SYNC_INTERVAL_MINUTES,
      thresholds: {
        stoppedDays: STALE_STOPPED_DAYS,
        backupDays: STALE_BACKUP_DAYS,
        snapshotDays: STALE_SNAPSHOT_DAYS,
      },
      items: rows.map((row) => presentCluster(row, admin, stats(row.id), runs.get(row.id) ?? null)),
    });
  })
  .post("/clusters", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = createBody.parse(await c2.req.json());
    const errors: { field: string; code: string }[] = [];
    const name = checkClusterName(body.name);
    if (name === null) errors.push({ field: "name", code: "name_invalid" });
    const url = validateEndpoint(body.apiUrl, errors);
    const tokenId = validateToken(body.tokenId, body.tokenSecret, errors);
    if (errors.length > 0 || name === null || !url || !tokenId) throw invalid(errors);
    requireRecentSignIn(actor);

    const existing = await db
      .select({ name: c.name, host: c.host, port: c.port })
      .from(c)
      .where(eq(c.organizationId, actor.organizationId));
    if (existing.length >= MAX_PROXMOX_CLUSTERS) {
      throw new ProblemError(
        409,
        "limit-reached",
        "The organisation has reached the number of Proxmox connections it may have",
      );
    }
    if (existing.some((e) => e.name === name || (e.host === url.host && e.port === url.port))) {
      throw new ProblemError(409, "duplicate", "This Proxmox connection is already added");
    }
    const id = newId("pxc");
    const secretId = await storeSecret(actor.organizationId, actor.userId, body.tokenSecret);
    await db.insert(c).values({
      id,
      organizationId: actor.organizationId,
      name,
      apiUrl: url.url,
      host: url.host,
      port: url.port,
      tokenId,
      secretId,
      createdBy: actor.userId,
    });
    await audit(
      actor,
      "proxmox.cluster_created",
      { type: "proxmox_cluster", id },
      { name, apiUrl: url.url, tokenId },
    );
    await queueCertificate(id);
    return c2.json({ id }, 201);
  })
  .patch("/clusters/:id", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = patchBody.parse(await c2.req.json());
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
    const errors: { field: string; code: string }[] = [];
    const changes: Partial<typeof c.$inferInsert> = {};
    const changed: string[] = [];

    if (body.name !== undefined) {
      const name = checkClusterName(body.name);
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
      const url = validateEndpoint(body.apiUrl, errors);
      if (url && (url.host !== row.host || url.port !== row.port)) {
        Object.assign(changes, { apiUrl: url.url, host: url.host, port: url.port });
        changed.push("apiUrl");
        repoint = true;
      }
    }
    let newToken = false;
    if (body.tokenId !== undefined || body.tokenSecret !== undefined) {
      // A new secret needs its token id (a token ID is not a secret, but the pair belongs together).
      const tokenId = validateToken(body.tokenId ?? row.tokenId, body.tokenSecret, errors);
      if (tokenId && (tokenId !== row.tokenId || body.tokenSecret !== undefined)) {
        if (body.tokenSecret === undefined) errors.push({ field: "tokenSecret", code: "secret_invalid" });
        else {
          changes.tokenId = tokenId;
          changed.push("token");
          newToken = true;
        }
      }
    }
    if (errors.length > 0) throw invalid(errors);
    if (changed.length === 0) return c2.body(null, 204);
    // Renaming and switching on or off are harmless; where the platform connects and with what is not.
    if (repoint || newToken) requireRecentSignIn(actor);
    if (changes.name || changes.host !== undefined) {
      const others = await db
        .select({ id: c.id, name: c.name, host: c.host, port: c.port })
        .from(c)
        .where(eq(c.organizationId, actor.organizationId));
      const host = changes.host ?? row.host;
      const port = changes.port ?? row.port;
      const name = changes.name ?? row.name;
      if (others.some((o) => o.id !== row.id && (o.name === name || (o.host === host && o.port === port)))) {
        throw new ProblemError(409, "duplicate", "This Proxmox connection is already added");
      }
    }

    let oldSecretId: string | null = null;
    if (newToken && body.tokenSecret !== undefined) {
      changes.secretId = await storeSecret(actor.organizationId, actor.userId, body.tokenSecret);
      oldSecretId = row.secretId;
      // A new token may have other privileges: look at them again, acknowledge again.
      Object.assign(changes, {
        extraPrivileges: [],
        acknowledgedPrivileges: [],
        privilegesAcknowledgedAt: null,
        privilegesAcknowledgedBy: null,
        permissionsCheckedAt: null,
      });
    }
    if (repoint) {
      // Another server: nothing about the old one is trusted any more.
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
        extraPrivileges: [],
        acknowledgedPrivileges: [],
        privilegesAcknowledgedAt: null,
        privilegesAcknowledgedBy: null,
        permissionsCheckedAt: null,
        lastError: null,
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
      "proxmox.cluster_changed",
      { type: "proxmox_cluster", id: row.id },
      {
        name: changes.name ?? row.name,
        changed,
        ...(changes.apiUrl ? { apiUrl: changes.apiUrl, previous: row.apiUrl } : {}),
        ...(changes.tokenId ? { tokenId: changes.tokenId } : {}),
      },
    );
    if (repoint) await queueCertificate(row.id);
    else if (newToken && row.certStatus === "confirmed")
      await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    return c2.body(null, 204);
  })
  .delete("/clusters/:id", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
    await db.transaction(async (tx) => {
      await tx.delete(c).where(eq(c.id, row.id));
      if (row.secretId) await tx.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    });
    await audit(
      actor,
      "proxmox.cluster_deleted",
      { type: "proxmox_cluster", id: row.id },
      { name: row.name, apiUrl: row.apiUrl },
    );
    return c2.body(null, 204);
  })
  .post("/clusters/:id/certificate/scan", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
    await rateLimit(`proxmox-cert:${actor.organizationId}`, 30, 60 * 60_000);
    await queueCertificate(row.id);
    await audit(
      actor,
      "proxmox.certificate_scan_requested",
      { type: "proxmox_cluster", id: row.id },
      { name: row.name },
    );
    return c2.body(null, 202);
  })
  .post("/clusters/:id/certificate/confirm", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const input = confirmBody.parse(await c2.req.json());
    const fingerprint = normalizeFingerprint(input.fingerprint);
    if (!fingerprint) throw invalid([{ field: "fingerprint", code: "fingerprint_invalid" }]);
    requireRecentSignIn(actor);
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
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
      "proxmox.certificate_confirmed",
      { type: "proxmox_cluster", id: row.id },
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
  .post("/clusters/:id/privileges/acknowledge", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const input = acknowledgeBody.parse(await c2.req.json());
    requireRecentSignIn(actor);
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
    if (row.extraPrivileges.length === 0) {
      throw new ProblemError(409, "no-extra-privileges", "The token has no privileges beyond reading");
    }
    // The admin acknowledges the list they were shown, not "whatever the token can do now".
    const shown = [...new Set(input.privileges)].sort();
    if (shown.join("\n") !== [...row.extraPrivileges].sort().join("\n")) {
      throw new ProblemError(
        409,
        "privileges-changed",
        "The token's privileges have changed since they were shown",
      );
    }
    await db
      .update(c)
      .set({
        acknowledgedPrivileges: row.extraPrivileges,
        privilegesAcknowledgedAt: new Date(),
        privilegesAcknowledgedBy: actor.userId,
        lastError: null,
        updatedAt: new Date(),
      })
      .where(eq(c.id, row.id));
    await audit(
      actor,
      "proxmox.privileges_acknowledged",
      { type: "proxmox_cluster", id: row.id },
      { name: row.name, privileges: row.extraPrivileges.slice(0, 50) },
    );
    if (row.certStatus === "confirmed") await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    return c2.body(null, 204);
  })
  .post("/clusters/:id/sync", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
    if (row.certStatus !== "confirmed") {
      throw new ProblemError(
        409,
        "certificate-unconfirmed",
        "Confirm the certificate of this Proxmox server first",
      );
    }
    await rateLimit(`proxmox-sync:${actor.organizationId}`, 60, 60 * 60_000);
    const result = await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    if (!result.alreadyQueued) {
      await audit(
        actor,
        "proxmox.sync_requested",
        { type: "proxmox_cluster", id: row.id },
        { runId: result.runId, name: row.name },
      );
    }
    return c2.json(result, result.alreadyQueued ? 200 : 202);
  })
  .get("/clusters/:id/runs", async (c2) => {
    const actor = c2.get("actor");
    const row = await ownCluster(actor.organizationId, c2.req.param("id"));
    const r = schema.proxmoxSyncRun;
    const runs = await db
      .select({
        id: r.id,
        state: r.state,
        trigger: r.trigger,
        nodeCount: r.nodeCount,
        guestCount: r.guestCount,
        requestCount: r.requestCount,
        warnings: r.warnings,
        error: r.error,
        startedAt: r.startedAt,
        finishedAt: r.finishedAt,
        createdAt: r.createdAt,
      })
      .from(r)
      .where(eq(r.clusterId, row.id))
      .orderBy(desc(r.createdAt), desc(r.id))
      .limit(10);
    return c2.json(runs);
  })

  /* ------------------------------ nodes and storage ------------------------------ */
  .get("/nodes", async (c2) => {
    const actor = c2.get("actor");
    const input = z.object({ cluster: z.string().max(60).optional() }).parse(c2.req.query());
    const rows = await db
      .select({
        ...getTableColumns(n),
        clusterName: c.name,
        guests: sql<number>`(select count(*)::int from ${g} where ${g.clusterId} = ${n.clusterId} and ${g.node} = ${n.name})`,
      })
      .from(n)
      .innerJoin(c, eq(c.id, n.clusterId))
      .where(
        and(
          eq(n.organizationId, actor.organizationId),
          input.cluster ? eq(n.clusterId, input.cluster) : undefined,
        ),
      )
      .orderBy(c.name, n.name)
      .limit(500);
    return c2.json(
      rows.map((r) => ({
        id: r.id,
        clusterId: r.clusterId,
        clusterName: r.clusterName,
        name: r.name,
        online: r.online,
        cpu: r.cpu,
        cpus: r.cpus,
        mem: r.mem,
        maxMem: r.maxMem,
        disk: r.disk,
        maxDisk: r.maxDisk,
        uptime: r.uptime,
        pveVersion: r.pveVersion,
        kernel: r.kernel,
        pendingUpdates: r.pendingUpdates,
        guests: r.guests,
        lastSeenAt: iso(r.lastSeenAt),
      })),
    );
  })
  .get("/storage", async (c2) => {
    const actor = c2.get("actor");
    const input = z.object({ cluster: z.string().max(60).optional() }).parse(c2.req.query());
    const s = schema.proxmoxStorage;
    const rows = await db
      .select({ ...getTableColumns(s), clusterName: c.name })
      .from(s)
      .innerJoin(c, eq(c.id, s.clusterId))
      .where(
        and(
          eq(s.organizationId, actor.organizationId),
          input.cluster ? eq(s.clusterId, input.cluster) : undefined,
        ),
      )
      .orderBy(c.name, s.name, s.node)
      .limit(1000);
    return c2.json(
      rows.map((r) => ({
        id: r.id,
        clusterId: r.clusterId,
        clusterName: r.clusterName,
        node: r.node,
        name: r.name,
        type: r.type,
        content: r.content,
        shared: r.shared,
        status: r.status,
        used: r.used,
        total: r.total,
      })),
    );
  })

  /* ------------------------------ guests ------------------------------ */
  .get("/guests", async (c2) => {
    const actor = c2.get("actor");
    const input = listQuery.parse(c2.req.query());
    const where = guestWhere(actor.organizationId, input, input.flag);
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, g.id) : null;
    const activeSpec = (sorted?.spec ?? defaultSpec) as KeysetSpec<ListRow>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          ...getTableColumns(g),
          clusterName: c.name,
          backupsReadable: c.backupsReadable,
          sortKeys: sorted ? sorted.select : sql<null>`null`,
        })
        .from(g)
        .innerJoin(c, eq(c.id, g.clusterId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(g).innerJoin(c, eq(c.id, g.clusterId)).where(where),
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
    const servers = await linkedServers(actor.organizationId, page.items);
    const now = new Date();
    return c2.json({
      ...page,
      items: page.items.map((row) =>
        presentGuest(row, servers.get(proxmoxSourceRef(row.clusterId, row.vmid)) ?? null, now),
      ),
    });
  })
  .get("/guests/counts", async (c2) => {
    const actor = c2.get("actor");
    const input = z.object(guestFilters).parse(c2.req.query());
    const counts = await Promise.all(
      (["all", "stale", "untracked"] as const).map(async (flag) => {
        const [row] = await db
          .select({ n: count() })
          .from(g)
          .innerJoin(c, eq(c.id, g.clusterId))
          .where(guestWhere(actor.organizationId, input, flag));
        return [flag, row?.n ?? 0] as const;
      }),
    );
    return c2.json(Object.fromEntries(counts));
  })
  .get("/guests/:id", async (c2) => {
    const actor = c2.get("actor");
    const [row] = await db
      .select({ ...getTableColumns(g), clusterName: c.name, backupsReadable: c.backupsReadable })
      .from(g)
      .innerJoin(c, eq(c.id, g.clusterId))
      .where(and(eq(g.id, c2.req.param("id")), eq(g.organizationId, actor.organizationId)))
      .limit(1);
    if (!row) throw notFound("Guest");
    const servers = await linkedServers(actor.organizationId, [row]);
    return c2.json(
      presentGuest(row, servers.get(proxmoxSourceRef(row.clusterId, row.vmid)) ?? null, new Date()),
    );
  });
