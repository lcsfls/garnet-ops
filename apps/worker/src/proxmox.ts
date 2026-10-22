/**
 * Proxmox VE (ADR 0012): reading the certificate a server presents, and the read-only sync.
 *
 * A sync opens the sealed API token, connects to the checked address with the pinned
 * certificate, asks only GET endpoints on an allow-list, and stores nodes, guests and
 * storage. Whatever Proxmox sends is data: parsed by packages/core/src/proxmox.ts, bounded,
 * stored as text, never executed and never echoed into an error message. Guest descriptions,
 * cloud-init data and the like are not read at all.
 */
import {
  newId,
  ProxmoxError,
  type ProxmoxErrorCode,
  type ProxmoxWarning,
  proxmoxErrorMessage,
} from "@garnetops/core";
import {
  type BackupJob,
  coveredByBackupJob,
  extraPrivileges,
  MAX_REQUESTS_PER_SYNC,
  type PxGuest,
  type PxGuestConfig,
  type PxNodeStatus,
  parseAgentInterfaces,
  parseAptUpdates,
  parseBackupContent,
  parseBackupJobs,
  parseClusterStatus,
  parseGuestConfig,
  parseHaResources,
  parseLxcInterfaces,
  parseNodeStatus,
  parseResources,
  parseSnapshots,
  parseVersion,
  privilegesAcknowledged,
  type SnapshotInfo,
  SYNC_BUDGET_MINUTES,
} from "@garnetops/core/proxmox";
import { PROXMOX_SYNC_INTERVAL_MINUTES } from "@garnetops/core/proxmox-flags";
import { open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, lt, notInArray, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import {
  type CertificateInfo,
  CertificateMismatch,
  fetchLeafCertificate,
  ProxmoxClient,
  resolveProxmoxAddress,
  type TlsTestOptions,
} from "./proxmox-http.ts";

export const PROXMOX_CERT_QUEUE = "proxmox.certificate";
export const PROXMOX_SYNC_QUEUE = "proxmox.sync";
export const PROXMOX_TICK_QUEUE = "proxmox.sync-tick";

/** Same job options as syncs queued by the API (apps/api/src/routes/proxmox.ts). One try: the next tick is the retry. */
export const PROXMOX_SYNC_JOB = { retryLimit: 0, expireInSeconds: (SYNC_BUDGET_MINUTES + 5) * 60 };

type ClusterRow = typeof schema.proxmoxCluster.$inferSelect;
type RunRow = typeof schema.proxmoxSyncRun.$inferSelect;

/** What a test can replace: name resolution (so a local test server can be used), its CA, limits and the pause between requests. */
export interface ProxmoxDeps {
  resolve?: (host: string) => Promise<string>;
  test?: TlsTestOptions;
  gapMs?: number;
  maxBytes?: number;
  timeoutMs?: number;
  maxRequests?: number;
  budgetMs?: number;
}

/** Errors that end a sync even when the call that raised them was optional. */
const FATAL: ProxmoxErrorCode[] = [
  "tokenRejected",
  "tlsFailed",
  "unreachable",
  "tooManyRequests",
  "syncTimeout",
  "certificateChanged",
  "addressRefused",
  "addressUnresolvable",
];

const errorCodeOf = (error: unknown, fallback: ProxmoxErrorCode = "unexpected"): ProxmoxErrorCode =>
  error instanceof ProxmoxError ? error.code : fallback;

/* -------------------------------------------------------------------------- */
/* Token                                                                       */
/* -------------------------------------------------------------------------- */

/** Opens the sealed token secret. Only the worker holds the vault private key (ADR 0004). */
async function openToken(cluster: ClusterRow): Promise<string> {
  if (!cluster.secretId) throw new ProxmoxError("tokenMissing");
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, cluster.secretId),
        eq(schema.secret.organizationId, cluster.organizationId),
        eq(schema.secret.purpose, "proxmox-token"),
      ),
    )
    .limit(1);
  if (!secret) throw new ProxmoxError("tokenMissing");
  const plain = open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose: "proxmox-token" },
    vaultPrivateKey,
  );
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

/* -------------------------------------------------------------------------- */
/* Certificate                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Records what the server presented: nothing to do if it is the pinned certificate (an earlier
 * alarm clears itself), "changed" with the new one as candidate if another is pinned (audited,
 * and the sync stays blocked), or the candidate an admin confirms on first contact.
 */
export async function applyObservedCertificate(cluster: ClusterRow, seen: CertificateInfo): Promise<void> {
  const c = schema.proxmoxCluster;
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
  const noCandidate = {
    candidateFingerprint: null,
    candidateSubject: null,
    candidateIssuer: null,
    candidateValidFrom: null,
    candidateValidTo: null,
    candidateCaTrusted: null,
    candidateSeenAt: null,
  };
  if (cluster.certFingerprint && cluster.certFingerprint === seen.fingerprint) {
    if (cluster.certStatus === "changed" || cluster.candidateFingerprint) {
      await db
        .update(c)
        .set({
          certStatus: "confirmed",
          ...noCandidate,
          lastError: cluster.certStatus === "changed" ? null : cluster.lastError,
          updatedAt: now,
        })
        .where(eq(c.id, cluster.id));
    }
    return;
  }
  if (cluster.certFingerprint) {
    await db.transaction(async (tx) => {
      await tx
        .update(c)
        .set({
          certStatus: "changed",
          ...candidate,
          lastError: proxmoxErrorMessage("certificateChanged"),
          updatedAt: now,
        })
        .where(eq(c.id, cluster.id));
      if (cluster.certStatus !== "changed" || cluster.candidateFingerprint !== seen.fingerprint) {
        await tx.insert(schema.auditLog).values({
          organizationId: cluster.organizationId,
          action: "proxmox.certificate_changed",
          targetType: "proxmox_cluster",
          targetId: cluster.id,
          data: { name: cluster.name, pinned: cluster.certFingerprint, seen: seen.fingerprint },
        });
      }
    });
    return;
  }
  await db
    .update(c)
    .set({ ...candidate, lastError: null, updatedAt: now })
    .where(eq(c.id, cluster.id));
}

/**
 * Reads the certificate the server presents, without sending the token, and stores it as the
 * candidate an admin confirms (or flags a change). Never pins by itself.
 */
export async function readCertificate(clusterId: string, deps: ProxmoxDeps = {}): Promise<void> {
  const [cluster] = await db
    .select()
    .from(schema.proxmoxCluster)
    .where(eq(schema.proxmoxCluster.id, clusterId))
    .limit(1);
  if (!cluster) return;
  try {
    const address = await (deps.resolve ?? resolveProxmoxAddress)(cluster.host);
    const seen = await fetchLeafCertificate({ host: cluster.host, port: cluster.port, address }, deps.test);
    await applyObservedCertificate(cluster, seen);
  } catch (error) {
    const code = errorCodeOf(error, "unreachable");
    await db
      .update(schema.proxmoxCluster)
      .set({ lastError: proxmoxErrorMessage(code), updatedAt: new Date() })
      .where(eq(schema.proxmoxCluster.id, clusterId));
    if (!(error instanceof ProxmoxError)) {
      console.error(`proxmox ${clusterId} certificate:`, (error as Error).message);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Sync                                                                        */
/* -------------------------------------------------------------------------- */

/** A running sync older than this lost its worker (matches the job expiry). */
const STALE_RUNNING = sql`now() - interval '15 minutes'`;

async function failRun(run: RunRow, error: ProxmoxError, requests: number | null) {
  const message = error.message;
  await db.transaction(async (tx) => {
    await tx
      .update(schema.proxmoxSyncRun)
      .set({ state: "failed", error: message, requestCount: requests, finishedAt: sql`now()` })
      .where(eq(schema.proxmoxSyncRun.id, run.id));
    await tx
      .update(schema.proxmoxCluster)
      .set({ lastError: message, updatedAt: new Date() })
      .where(eq(schema.proxmoxCluster.id, run.clusterId));
  });
}

/** Runs one queued sync. Never throws for a problem of the Proxmox server; those become the run's error. */
export async function runProxmoxSync(runId: string, deps: ProxmoxDeps = {}): Promise<void> {
  const r = schema.proxmoxSyncRun;
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
    await syncCluster(run, deps, progress);
  } catch (error) {
    if (error instanceof ProxmoxError) {
      await failRun(run, error, progress.requests);
    } else {
      console.error(`proxmox sync ${runId}:`, (error as Error).message);
      await failRun(run, new ProxmoxError("unexpected"), progress.requests);
    }
  }
}

interface Collected {
  version: string;
  clusterName: string | null;
  quorate: boolean | null;
  nodes: ReturnType<typeof parseResources>["nodes"];
  nodeStatus: Map<string, PxNodeStatus | null>;
  nodeUpdates: Map<string, number | null>;
  guests: PxGuest[];
  storages: ReturnType<typeof parseResources>["storages"];
  details: Map<number, GuestDetails>;
  ha: Map<number, string>;
  jobs: BackupJob[] | null;
  backups: Map<number, Date>;
  backupsReadable: boolean;
  warnings: Set<ProxmoxWarning>;
}

interface GuestDetails {
  config?: PxGuestConfig;
  snapshots?: SnapshotInfo;
  ips?: string[];
}

async function syncCluster(run: RunRow, deps: ProxmoxDeps, progress: { requests: number }): Promise<void> {
  const [cluster] = await db
    .select()
    .from(schema.proxmoxCluster)
    .where(eq(schema.proxmoxCluster.id, run.clusterId))
    .limit(1);
  if (!cluster) throw new ProxmoxError("clusterRemoved");
  if (cluster.certStatus === "changed") throw new ProxmoxError("certificateChanged");
  if (cluster.certStatus !== "confirmed" || !cluster.certFingerprint) {
    throw new ProxmoxError("certificateNotConfirmed");
  }
  const secret = await openToken(cluster);
  const address = await (deps.resolve ?? resolveProxmoxAddress)(cluster.host);
  const client = new ProxmoxClient({
    endpoint: { host: cluster.host, port: cluster.port, address },
    pinned: cluster.certFingerprint,
    tokenId: cluster.tokenId,
    tokenSecret: secret,
    ...(deps.gapMs !== undefined ? { gapMs: deps.gapMs } : {}),
    ...(deps.maxBytes !== undefined ? { maxBytes: deps.maxBytes } : {}),
    ...(deps.timeoutMs !== undefined ? { timeoutMs: deps.timeoutMs } : {}),
    ...(deps.test ? { test: deps.test } : {}),
  });
  const deadline = Date.now() + (deps.budgetMs ?? SYNC_BUDGET_MINUTES * 60_000);
  const maxRequests = deps.maxRequests ?? MAX_REQUESTS_PER_SYNC;
  let consecutiveTimeouts = 0;

  const call = async (path: string, query?: Record<string, string>, timeoutMs?: number) => {
    if (client.requests >= maxRequests) throw new ProxmoxError("tooManyRequests");
    if (Date.now() > deadline) throw new ProxmoxError("syncTimeout", { minutes: SYNC_BUDGET_MINUTES });
    try {
      const result = await client.get(path, query, timeoutMs ? { timeoutMs } : undefined);
      consecutiveTimeouts = 0;
      return result;
    } catch (error) {
      consecutiveTimeouts = errorCodeOf(error, "unexpected") === "timeout" ? consecutiveTimeouts + 1 : 0;
      throw error;
    } finally {
      progress.requests = client.requests;
    }
  };
  /** An optional read: a refusal or a malformed answer is tolerated (null), a lost connection is not. */
  const optional = async (path: string, query?: Record<string, string>, timeoutMs?: number) => {
    try {
      return { ok: true as const, data: await call(path, query, timeoutMs) };
    } catch (error) {
      if (error instanceof CertificateMismatch) throw error;
      if (error instanceof ProxmoxError && !FATAL.includes(error.code) && consecutiveTimeouts < 5) {
        return { ok: false as const, status: error.status ?? null };
      }
      throw error;
    }
  };

  try {
    const collected = await collect(cluster, call, optional);
    await store(run, cluster, collected, client.requests);
  } catch (error) {
    // A certificate other than the pin: record what was seen, so an admin can decide (the token was never sent).
    const seen = error instanceof CertificateMismatch ? error.seen : client.mismatch;
    if (seen) await applyObservedCertificate(cluster, seen);
    throw error;
  } finally {
    client.close();
  }
}

type Call = (path: string, query?: Record<string, string>, timeoutMs?: number) => Promise<unknown>;
type Optional = (
  path: string,
  query?: Record<string, string>,
  timeoutMs?: number,
) => Promise<{ ok: true; data: unknown } | { ok: false; status: number | null }>;

async function collect(cluster: ClusterRow, call: Call, optional: Optional): Promise<Collected> {
  const warnings = new Set<ProxmoxWarning>();

  // 1. Is this Proxmox VE, and what can the token do?
  const version = parseVersion(await call("/version"));
  if (!version) throw new ProxmoxError("notProxmox");
  let permissions: unknown;
  try {
    permissions = await call("/access/permissions");
  } catch (error) {
    if (error instanceof ProxmoxError && FATAL.includes(error.code)) throw error;
    throw new ProxmoxError("permissionsUnreadable");
  }
  const extra = extraPrivileges(permissions);
  const c = schema.proxmoxCluster;
  await db.transaction(async (tx) => {
    await tx
      .update(c)
      .set({ extraPrivileges: extra, permissionsCheckedAt: new Date() })
      .where(eq(c.id, cluster.id));
    if (extra.length > 0 && extra.join("\n") !== cluster.extraPrivileges.join("\n")) {
      await tx.insert(schema.auditLog).values({
        organizationId: cluster.organizationId,
        action: "proxmox.privileges_detected",
        targetType: "proxmox_cluster",
        targetId: cluster.id,
        data: { name: cluster.name, privileges: extra.slice(0, 50) },
      });
    }
  });
  if (extra.length > 0 && !privilegesAcknowledged(extra, cluster.acknowledgedPrivileges)) {
    throw new ProxmoxError("privilegesNotAcknowledged");
  }

  // 2. The cluster and everything in it.
  const statusRead = await optional("/cluster/status");
  const status = statusRead.ok ? parseClusterStatus(statusRead.data) : null;
  const rawResources = await call("/cluster/resources");
  const resources = parseResources(rawResources);
  // An answer that is not a list, or lists no node at all, is not a cluster: never let it empty the inventory.
  if (!Array.isArray(rawResources) || resources.nodes.length === 0) throw new ProxmoxError("invalidResponse");
  if (resources.dropped > 0) warnings.add("entriesDropped");
  if (resources.guestsTruncated) warnings.add("guestsTruncated");
  const nodes = resources.nodes.map((n) => ({ ...n, online: status?.nodes.get(n.name) ?? n.online }));

  const haRead = await optional("/cluster/ha/resources");
  if (!haRead.ok) warnings.add("haUnreadable");
  const ha = haRead.ok ? parseHaResources(haRead.data) : new Map<number, string>();
  const jobsRead = await optional("/cluster/backup");
  if (!jobsRead.ok) warnings.add("backupJobsUnreadable");
  const jobs = jobsRead.ok ? parseBackupJobs(jobsRead.data) : null;

  // 3. Per node: its status and the updates its own cache knows (GET only, nothing is refreshed).
  const online = new Set(nodes.filter((n) => n.online).map((n) => n.name));
  if (online.size < nodes.length) warnings.add("nodeOffline");
  const nodeStatus = new Map<string, PxNodeStatus | null>();
  const nodeUpdates = new Map<string, number | null>();
  for (const node of nodes) {
    if (!online.has(node.name)) continue;
    const s = await optional(`/nodes/${node.name}/status`);
    nodeStatus.set(node.name, s.ok ? parseNodeStatus(s.data) : null);
    const u = await optional(`/nodes/${node.name}/apt/update`);
    if (!u.ok) warnings.add("updatesUnreadable");
    nodeUpdates.set(node.name, u.ok ? parseAptUpdates(u.data) : null);
  }

  // 4. Backups: the newest per guest, from every storage that can hold them.
  const backups = new Map<number, Date>();
  let failedListings = 0;
  const listed = new Set<string>();
  const targets: { node: string; storage: string }[] = [];
  for (const s of resources.storages) {
    if (!s.content.includes("backup") || s.status !== "available" || !online.has(s.node)) continue;
    if (s.shared && listed.has(s.name)) continue; // a shared storage shows the same backups on every node
    if (s.shared) listed.add(s.name);
    targets.push({ node: s.node, storage: s.name });
  }
  for (const t of targets.slice(0, 60)) {
    const r = await optional(`/nodes/${t.node}/storage/${t.storage}/content`, { content: "backup" });
    if (!r.ok) {
      failedListings++;
      continue;
    }
    for (const [vmid, at] of parseBackupContent(r.data)) {
      const prior = backups.get(vmid);
      if (!prior || prior < at) backups.set(vmid, at);
    }
  }
  if (targets.length > 60) failedListings++;
  if (failedListings > 0) warnings.add("backupsUnreadable");
  const backupsReadable = failedListings === 0;

  // 5. Per guest: configuration (a few fields), snapshots, addresses.
  const details = new Map<number, GuestDetails>();
  let agentFailures = 0;
  for (const guest of resources.guests) {
    if (!online.has(guest.node)) continue;
    const base = `/nodes/${guest.node}/${guest.type}/${guest.vmid}`;
    const d: GuestDetails = {};
    const cfg = await optional(`${base}/config`);
    if (cfg.ok) {
      const parsed = parseGuestConfig(cfg.data);
      if (parsed) d.config = parsed;
    } else warnings.add("detailsUnreadable");
    if (!guest.template) {
      const snap = await optional(`${base}/snapshot`);
      if (snap.ok) {
        const parsed = parseSnapshots(snap.data);
        if (parsed) d.snapshots = parsed;
      } else warnings.add("detailsUnreadable");
    }
    if (guest.status === "running" && !guest.template) {
      if (guest.type === "lxc") {
        const r = await optional(`${base}/interfaces`, undefined, 8000);
        if (r.ok) d.ips = parseLxcInterfaces(r.data);
        else if (r.status === 403) warnings.add("addressesUnreadable");
      } else if (d.config?.agent && agentFailures < 3) {
        // The guest agent may be switched on but not running: a short timeout, and give up after three misses.
        const r = await optional(`${base}/agent/network-get-interfaces`, undefined, 8000);
        if (r.ok) {
          d.ips = parseAgentInterfaces(r.data);
          agentFailures = 0;
        } else {
          agentFailures++;
          if (r.status === 403) warnings.add("addressesUnreadable");
        }
      }
    }
    details.set(guest.vmid, d);
  }

  return {
    version,
    clusterName: status?.name ?? null,
    quorate: status?.quorate ?? null,
    nodes,
    nodeStatus,
    nodeUpdates,
    guests: resources.guests,
    storages: resources.storages,
    details,
    ha,
    jobs,
    backups,
    backupsReadable,
    warnings,
  };
}

const toInt = (n: number | null | undefined) => (n === null || n === undefined ? null : Math.round(n));

/** Replaces what is stored about the cluster with what was read, in one transaction. */
async function store(run: RunRow, cluster: ClusterRow, d: Collected, requests: number): Promise<void> {
  const now = new Date();
  const g = schema.proxmoxGuest;
  const n = schema.proxmoxNode;
  await db.transaction(async (tx) => {
    // --- nodes
    const oldNodes = new Map(
      (await tx.select().from(n).where(eq(n.clusterId, cluster.id))).map((x) => [x.name, x]),
    );
    const nodeRows = d.nodes.map((node) => {
      const status = d.nodeStatus.get(node.name);
      const prior = oldNodes.get(node.name);
      const updates = d.nodeUpdates.get(node.name);
      return {
        id: prior?.id ?? newId("pxn"),
        organizationId: cluster.organizationId,
        clusterId: cluster.id,
        name: node.name,
        online: node.online,
        cpu: status?.cpu ?? node.cpu ?? prior?.cpu ?? null,
        cpus: toInt(status?.cpus ?? node.cpus) ?? prior?.cpus ?? null,
        mem: toInt(status?.mem ?? node.mem) ?? prior?.mem ?? null,
        maxMem: toInt(status?.maxMem ?? node.maxMem) ?? prior?.maxMem ?? null,
        disk: toInt(status?.rootUsed ?? node.disk) ?? prior?.disk ?? null,
        maxDisk: toInt(status?.rootTotal ?? node.maxDisk) ?? prior?.maxDisk ?? null,
        uptime: node.online ? (toInt(status?.uptime ?? node.uptime) ?? null) : null,
        pveVersion: status?.pveVersion ?? prior?.pveVersion ?? null,
        kernel: status?.kernel ?? prior?.kernel ?? null,
        // An offline node keeps its last known count; an online node whose cache could not be read shows none.
        pendingUpdates: updates !== undefined ? updates : (prior?.pendingUpdates ?? null),
        lastSeenAt: now,
      };
    });
    if (nodeRows.length > 0) {
      await tx
        .insert(n)
        .values(nodeRows)
        .onConflictDoUpdate({
          target: [n.clusterId, n.name],
          set: {
            online: sql`excluded.online`,
            cpu: sql`excluded.cpu`,
            cpus: sql`excluded.cpus`,
            mem: sql`excluded.mem`,
            maxMem: sql`excluded.max_mem`,
            disk: sql`excluded.disk`,
            maxDisk: sql`excluded.max_disk`,
            uptime: sql`excluded.uptime`,
            pveVersion: sql`excluded.pve_version`,
            kernel: sql`excluded.kernel`,
            pendingUpdates: sql`excluded.pending_updates`,
            lastSeenAt: sql`excluded.last_seen_at`,
          },
        });
    }
    await tx.delete(n).where(
      nodeRows.length > 0
        ? and(
            eq(n.clusterId, cluster.id),
            notInArray(
              n.name,
              nodeRows.map((x) => x.name),
            ),
          )
        : eq(n.clusterId, cluster.id),
    );

    // --- guests
    const oldGuests = new Map(
      (await tx.select().from(g).where(eq(g.clusterId, cluster.id))).map((x) => [x.vmid, x]),
    );
    const guestRows = d.guests.map((guest) => {
      const prior = oldGuests.get(guest.vmid);
      const detail = d.details.get(guest.vmid);
      const covered = d.jobs ? coveredByBackupJob(d.jobs, guest) : null;
      const backup = d.backups.get(guest.vmid);
      const snapshots = detail?.snapshots;
      return {
        id: prior?.id ?? newId("pxg"),
        organizationId: cluster.organizationId,
        clusterId: cluster.id,
        vmid: guest.vmid,
        type: guest.type,
        name: guest.name,
        node: guest.node,
        status: guest.status,
        // Proxmox does not say since when a guest is stopped: we count from when we first saw it so.
        statusSince: prior && prior.status === guest.status ? prior.statusSince : now,
        cpu: guest.cpu,
        cpus: toInt(guest.cpus),
        mem: toInt(guest.mem),
        maxMem: toInt(guest.maxMem),
        disk: toInt(guest.disk),
        maxDisk: toInt(guest.maxDisk),
        uptime: toInt(guest.uptime),
        ostype: detail?.config ? detail.config.ostype : (prior?.ostype ?? null),
        tags: guest.tags,
        template: guest.template || detail?.config?.template === true,
        haState: d.ha.get(guest.vmid) ?? guest.haState,
        inBackupJob: covered ?? null,
        lastBackupAt: backup ?? (d.backupsReadable ? null : (prior?.lastBackupAt ?? null)),
        snapshotCount: snapshots ? snapshots.count : (prior?.snapshotCount ?? null),
        newestSnapshotAt: snapshots ? snapshots.newest : (prior?.newestSnapshotAt ?? null),
        oldestSnapshotAt: snapshots ? snapshots.oldest : (prior?.oldestSnapshotAt ?? null),
        ips: detail?.ips ?? detail?.config?.ips ?? prior?.ips ?? [],
        firstSeenAt: prior?.firstSeenAt ?? now,
        lastSeenAt: now,
      };
    });
    for (let i = 0; i < guestRows.length; i += 400) {
      await tx
        .insert(g)
        .values(guestRows.slice(i, i + 400))
        .onConflictDoUpdate({
          target: [g.clusterId, g.vmid],
          set: {
            type: sql`excluded.type`,
            name: sql`excluded.name`,
            node: sql`excluded.node`,
            status: sql`excluded.status`,
            statusSince: sql`excluded.status_since`,
            cpu: sql`excluded.cpu`,
            cpus: sql`excluded.cpus`,
            mem: sql`excluded.mem`,
            maxMem: sql`excluded.max_mem`,
            disk: sql`excluded.disk`,
            maxDisk: sql`excluded.max_disk`,
            uptime: sql`excluded.uptime`,
            ostype: sql`excluded.ostype`,
            tags: sql`excluded.tags`,
            template: sql`excluded.template`,
            haState: sql`excluded.ha_state`,
            inBackupJob: sql`excluded.in_backup_job`,
            lastBackupAt: sql`excluded.last_backup_at`,
            snapshotCount: sql`excluded.snapshot_count`,
            newestSnapshotAt: sql`excluded.newest_snapshot_at`,
            oldestSnapshotAt: sql`excluded.oldest_snapshot_at`,
            ips: sql`excluded.ips`,
            lastSeenAt: sql`excluded.last_seen_at`,
          },
        });
    }
    // Guests that were not in this answer are gone (migrated away, deleted): every kept row has lastSeenAt = now.
    await tx.delete(g).where(and(eq(g.clusterId, cluster.id), lt(g.lastSeenAt, now)));

    // --- storage
    const s = schema.proxmoxStorage;
    await tx.delete(s).where(eq(s.clusterId, cluster.id));
    if (d.storages.length > 0) {
      await tx.insert(s).values(
        d.storages.map((x) => ({
          id: newId("pxs"),
          organizationId: cluster.organizationId,
          clusterId: cluster.id,
          node: x.node,
          name: x.name,
          type: x.type,
          content: x.content,
          shared: x.shared,
          status: x.status,
          used: toInt(x.used),
          total: toInt(x.total),
        })),
      );
    }

    // --- the cluster and the run
    await tx
      .update(schema.proxmoxCluster)
      .set({
        version: d.version,
        clusterName: d.clusterName,
        quorate: d.quorate,
        backupsReadable: d.backupsReadable,
        lastSyncAt: now,
        lastError: null,
        updatedAt: now,
      })
      .where(eq(schema.proxmoxCluster.id, cluster.id));
    await tx
      .update(schema.proxmoxSyncRun)
      .set({
        state: "succeeded",
        finishedAt: now,
        nodeCount: nodeRows.length,
        guestCount: guestRows.length,
        requestCount: requests,
        warnings: [...d.warnings],
        error: null,
      })
      .where(eq(schema.proxmoxSyncRun.id, run.id));
  });
}

/* -------------------------------------------------------------------------- */
/* Schedule                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * One tick of the Proxmox schedule: queues a sync for every enabled connection whose
 * certificate is confirmed and whose token is acknowledged, unless one is waiting, running or
 * was queued in the last ten minutes. Also sends again syncs that may have been lost between
 * queueing and sending (a worker claims a sync only if it is still queued), and looks again at
 * the certificate of connections that are blocked by a changed one.
 */
export async function proxmoxTick(boss: PgBoss): Promise<void> {
  const c = schema.proxmoxCluster;
  const r = schema.proxmoxSyncRun;
  const due = await db
    .select()
    .from(c)
    .where(
      and(
        eq(c.enabled, true),
        eq(c.certStatus, "confirmed"),
        sql`not exists (select 1 from ${r} where ${r.clusterId} = ${c.id}
              and (${r.state} in ('queued', 'running') or ${r.createdAt} > now() - interval '10 minutes'))`,
      ),
    );
  for (const cluster of due) {
    if (
      cluster.extraPrivileges.length > 0 &&
      !privilegesAcknowledged(cluster.extraPrivileges, cluster.acknowledgedPrivileges)
    ) {
      continue;
    }
    const runId = newId("pxr");
    await db.insert(r).values({
      id: runId,
      organizationId: cluster.organizationId,
      clusterId: cluster.id,
      state: "queued",
      trigger: "schedule",
      createdAt: new Date(),
    });
    await boss.send(PROXMOX_SYNC_QUEUE, { runId }, { ...PROXMOX_SYNC_JOB, singletonKey: cluster.id });
  }
  // A connection whose certificate changed is not synced, but looked at again now and then (no token is
  // sent): if the pinned certificate is back, the alarm clears itself; otherwise the candidate stays current.
  const changed = await db
    .select({ id: c.id })
    .from(c)
    .where(and(eq(c.enabled, true), eq(c.certStatus, "changed")));
  for (const cluster of changed) {
    await boss.send(
      PROXMOX_CERT_QUEUE,
      { clusterId: cluster.id },
      { retryLimit: 0, singletonKey: cluster.id },
    );
  }
  const stranded = await db
    .select({ id: r.id, clusterId: r.clusterId })
    .from(r)
    .where(and(eq(r.state, "queued"), sql`${r.createdAt} < now() - interval '2 minutes'`))
    .limit(100);
  for (const run of stranded) {
    await boss.send(
      PROXMOX_SYNC_QUEUE,
      { runId: run.id },
      { ...PROXMOX_SYNC_JOB, singletonKey: run.clusterId },
    );
  }
}

/** Registers the tick: every 15 minutes, cron evaluated in UTC. */
export async function startProxmoxScheduler(boss: PgBoss): Promise<void> {
  await boss.createQueue(PROXMOX_TICK_QUEUE);
  await boss.schedule(PROXMOX_TICK_QUEUE, `*/${PROXMOX_SYNC_INTERVAL_MINUTES} * * * *`, null, { tz: "UTC" });
  await boss.work(PROXMOX_TICK_QUEUE, { batchSize: 1 }, async () => {
    await proxmoxTick(boss);
  });
}
