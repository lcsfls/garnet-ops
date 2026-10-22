/**
 * Wazuh (ADR 0015): reading the certificate an endpoint presents, and the read-only sync.
 *
 * A sync opens the two sealed passwords, connects to the checked addresses with the pinned
 * certificates (or the admin's certificate authority), logs in to the manager, finds the version
 * and with it the adapter, checks what the two service users may do, and only then reads: the
 * agent list from the manager API, and from the indexer aggregations of alerts, a small sample
 * of file integrity events and vulnerability counts per agent. Whatever Wazuh sends is data:
 * parsed by packages/core/src/wazuh.ts, bounded, stored as text, never executed and never echoed
 * into an error message. Nothing streams raw logs into our database.
 */
import {
  newId,
  type WazuhEndpointKind,
  WazuhError,
  type WazuhErrorCode,
  type WazuhWarning,
  wazuhErrorMessage,
} from "@garnetops/core";
import { open } from "@garnetops/core/vault";
import {
  AGENTS_PAGE_SIZE,
  type AttackStats,
  adapterFor,
  agentsQuery,
  extraIndexerPrivileges,
  extraManagerPrivileges,
  type FimEvent,
  MAX_AGENTS,
  MAX_REQUESTS_PER_SYNC,
  type PreviousAttackStats,
  parseAgents,
  parseAlertStats,
  parseApiInfo,
  parseFimEvents,
  parseIndexerInfo,
  parsePreviousStats,
  parseVulnerabilityStats,
  privilegesAcknowledged,
  readSnapshot,
  type SeverityCounts,
  type Snapshot,
  type SourceIp,
  SYNC_BUDGET_MINUTES,
  suggestHost,
  sumVulnerabilities,
  WAZUH_SYNC_INTERVAL_MINUTES,
  type WazuhAdapter,
  type WazuhAgentInfo,
  WINDOWS,
  type Window,
  type WindowSnapshot,
} from "@garnetops/core/wazuh";
import { schema } from "@garnetops/db";
import { and, eq, inArray, isNotNull, isNull, lt, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { enrichOsint } from "./attacks.ts";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import {
  type CertificateInfo,
  CertificateMismatch,
  fetchLeafCertificate,
  IndexerClient,
  ManagerClient,
  resolveWazuhAddress,
  type TlsTestOptions,
  type Trust,
} from "./wazuh-http.ts";

export const WAZUH_CERT_QUEUE = "xdr.certificate";
export const WAZUH_SYNC_QUEUE = "xdr.sync";
export const WAZUH_TICK_QUEUE = "xdr.sync-tick";

/** Same job options as syncs queued by the API (apps/api/src/routes/xdr.ts). One try: the next tick is the retry. */
export const WAZUH_SYNC_JOB = { retryLimit: 0, expireInSeconds: (SYNC_BUDGET_MINUTES + 5) * 60 };

type ConnectionRow = typeof schema.wazuhConnection.$inferSelect;
type EndpointRow = typeof schema.wazuhEndpoint.$inferSelect;
type RunRow = typeof schema.wazuhSyncRun.$inferSelect;

/** What a test can replace: name resolution (so a local test server can be used), its CA, limits and the pause between requests. */
export interface WazuhDeps {
  resolve?: (host: string) => Promise<string>;
  test?: TlsTestOptions;
  gapMs?: number;
  maxBytes?: number;
  timeoutMs?: number;
  maxRequests?: number;
  budgetMs?: number;
}

/** Errors that end a sync even when the call that raised them was optional. */
const FATAL: WazuhErrorCode[] = [
  "loginRejected",
  "tlsFailed",
  "caRejected",
  "unreachable",
  "tooManyRequests",
  "syncTimeout",
  "certificateChanged",
  "addressRefused",
  "addressUnresolvable",
  "rateLimited",
  "redirected",
];

const errorCodeOf = (error: unknown, fallback: WazuhErrorCode = "unexpected"): WazuhErrorCode =>
  error instanceof WazuhError ? error.code : fallback;

/* -------------------------------------------------------------------------- */
/* Secrets                                                                     */
/* -------------------------------------------------------------------------- */

const PURPOSE = { manager: "wazuh-api-password", indexer: "wazuh-indexer-password" } as const;

/** Opens a sealed password. Only the worker holds the vault private key (ADR 0004). */
async function openPassword(endpoint: EndpointRow): Promise<string> {
  if (!endpoint.secretId) throw new WazuhError("credentialsMissing", { endpoint: endpoint.kind });
  const purpose = PURPOSE[endpoint.kind];
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, endpoint.secretId),
        eq(schema.secret.organizationId, endpoint.organizationId),
        eq(schema.secret.purpose, purpose),
      ),
    )
    .limit(1);
  if (!secret) throw new WazuhError("credentialsMissing", { endpoint: endpoint.kind });
  const plain = open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose },
    vaultPrivateKey,
  );
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

function trustOf(endpoint: EndpointRow): Trust | null {
  if (endpoint.trustMode === "ca") return endpoint.caPem ? { mode: "ca", ca: endpoint.caPem } : null;
  return endpoint.certFingerprint ? { mode: "pin", fingerprint: endpoint.certFingerprint } : null;
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
} as const;

/**
 * Records what the endpoint presented: nothing to do if it is the pinned certificate (an earlier
 * alarm clears itself), "changed" with the new one as candidate if another is pinned (audited,
 * and the sync stays blocked), or the candidate an admin confirms on first contact.
 */
export async function applyObservedCertificate(
  connection: ConnectionRow,
  endpoint: EndpointRow,
  seen: CertificateInfo,
): Promise<void> {
  const e = schema.wazuhEndpoint;
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
  if (endpoint.certFingerprint && endpoint.certFingerprint === seen.fingerprint) {
    if (endpoint.certStatus === "changed" || endpoint.candidateFingerprint) {
      await db
        .update(e)
        .set({
          certStatus: "confirmed",
          ...NO_CANDIDATE,
          lastError: endpoint.certStatus === "changed" ? null : endpoint.lastError,
          updatedAt: now,
        })
        .where(eq(e.id, endpoint.id));
    }
    return;
  }
  if (endpoint.certFingerprint) {
    await db.transaction(async (tx) => {
      await tx
        .update(e)
        .set({
          certStatus: "changed",
          ...candidate,
          lastError: wazuhErrorMessage("certificateChanged", {
            endpoint: endpoint.kind === "manager" ? "manager API" : "indexer",
          }),
          updatedAt: now,
        })
        .where(eq(e.id, endpoint.id));
      if (endpoint.certStatus !== "changed" || endpoint.candidateFingerprint !== seen.fingerprint) {
        await tx.insert(schema.auditLog).values({
          organizationId: connection.organizationId,
          action: "xdr.certificate_changed",
          targetType: "wazuh_connection",
          targetId: connection.id,
          data: {
            name: connection.name,
            endpoint: endpoint.kind,
            pinned: endpoint.certFingerprint,
            seen: seen.fingerprint,
          },
        });
      }
    });
    return;
  }
  await db
    .update(e)
    .set({ ...candidate, lastError: null, updatedAt: now })
    .where(eq(e.id, endpoint.id));
}

/**
 * Reads the certificate an endpoint presents, without sending the password, and stores it as the
 * candidate an admin confirms (or flags a change). Never pins by itself. With an uploaded
 * certificate authority the handshake verifies the certificate; the endpoint is then trusted
 * without a confirmation, and an endpoint that does not chain to the authority is an error.
 */
export async function readCertificate(endpointId: string, deps: WazuhDeps = {}): Promise<void> {
  const e = schema.wazuhEndpoint;
  const [endpoint] = await db.select().from(e).where(eq(e.id, endpointId)).limit(1);
  if (!endpoint) return;
  const [connection] = await db
    .select()
    .from(schema.wazuhConnection)
    .where(eq(schema.wazuhConnection.id, endpoint.connectionId))
    .limit(1);
  if (!connection) return;
  try {
    const address = await (deps.resolve ?? resolveWazuhAddress)(endpoint.host);
    const ca = endpoint.trustMode === "ca" ? trustOf(endpoint) : null;
    if (endpoint.trustMode === "ca" && !ca) throw new WazuhError("caRejected");
    const seen = await fetchLeafCertificate(
      { host: endpoint.host, port: endpoint.port, address },
      ca,
      deps.test,
    );
    if (endpoint.trustMode === "ca") {
      // The authority vouches for it; the fingerprint is recorded for the admin's information only.
      await db
        .update(e)
        .set({
          certStatus: "confirmed",
          certFingerprint: seen.fingerprint,
          certSubject: seen.subject,
          certIssuer: seen.issuer,
          certValidFrom: seen.validFrom,
          certValidTo: seen.validTo,
          certConfirmedAt: new Date(),
          ...NO_CANDIDATE,
          lastError: null,
          updatedAt: new Date(),
        })
        .where(eq(e.id, endpoint.id));
      return;
    }
    await applyObservedCertificate(connection, endpoint, seen);
  } catch (error) {
    const code = errorCodeOf(error, "unreachable");
    await db
      .update(e)
      .set({
        lastError: wazuhErrorMessage(code, {
          endpoint: endpoint.kind === "manager" ? "manager API" : "indexer",
          limit: 8,
        }),
        updatedAt: new Date(),
      })
      .where(eq(e.id, endpointId));
    if (!(error instanceof WazuhError)) {
      console.error(`wazuh endpoint ${endpointId} certificate:`, (error as Error).message);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Sync                                                                        */
/* -------------------------------------------------------------------------- */

/** A running sync older than this lost its worker (matches the job expiry). */
const STALE_RUNNING = sql`now() - interval '15 minutes'`;

async function failRun(run: RunRow, error: WazuhError, requests: number | null) {
  const message = error.message;
  await db.transaction(async (tx) => {
    await tx
      .update(schema.wazuhSyncRun)
      .set({ state: "failed", error: message, requestCount: requests, finishedAt: sql`now()` })
      .where(eq(schema.wazuhSyncRun.id, run.id));
    await tx
      .update(schema.wazuhConnection)
      .set({ lastError: message, updatedAt: new Date() })
      .where(eq(schema.wazuhConnection.id, run.connectionId));
  });
}

/** Runs one queued sync. Never throws for a problem of the Wazuh installation; those become the run's error. */
export async function runWazuhSync(runId: string, deps: WazuhDeps = {}): Promise<void> {
  const r = schema.wazuhSyncRun;
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
    // Optional OSINT lookups of the busiest public addresses (ADR 0016). Off unless an admin switched it on;
    // never part of the sync's result.
    await enrichOsint(run.organizationId).catch((error: Error) =>
      console.error(`osint after sync ${runId}: ${error?.name ?? "error"}`),
    );
  } catch (error) {
    if (error instanceof WazuhError) {
      await failRun(run, error, progress.requests);
    } else {
      // Never log the message of an unknown error: it could quote what Wazuh sent.
      console.error(`xdr sync ${runId}: ${(error as Error)?.name ?? "error"}`);
      await failRun(run, new WazuhError("unexpected"), progress.requests);
    }
  }
}

interface Collected {
  adapter: WazuhAdapter;
  managerVersion: string;
  indexerVersion: string;
  agents: WazuhAgentInfo[];
  /** Windows that were read now; windows missing here keep their earlier values. */
  windows: Partial<Record<Window, WindowSnapshot>>;
  sources: Partial<Record<Window, SourceIp[]>>;
  /** Attack numbers per window read now (ADR 0016). */
  attacks: Partial<
    Record<Window, { readAt: Date; current: AttackStats; previous: PreviousAttackStats | null }>
  >;
  /** null: not read now (the stored sample stays). */
  fim: FimEvent[] | null;
  vulnerabilities: Map<string, SeverityCounts> | null;
  warnings: Set<WazuhWarning>;
}

async function syncConnection(run: RunRow, deps: WazuhDeps, progress: { requests: number }): Promise<void> {
  const [connection] = await db
    .select()
    .from(schema.wazuhConnection)
    .where(eq(schema.wazuhConnection.id, run.connectionId))
    .limit(1);
  if (!connection) throw new WazuhError("connectionRemoved");
  const endpoints = await db
    .select()
    .from(schema.wazuhEndpoint)
    .where(eq(schema.wazuhEndpoint.connectionId, connection.id));
  const manager = endpoints.find((x) => x.kind === "manager");
  const indexer = endpoints.find((x) => x.kind === "indexer");
  if (!manager || !indexer) throw new WazuhError("connectionRemoved");
  for (const endpoint of [manager, indexer]) {
    if (endpoint.certStatus === "changed")
      throw new WazuhError("certificateChanged", { endpoint: endpoint.kind });
    const trust = trustOf(endpoint);
    if (endpoint.certStatus !== "confirmed" || !trust) {
      throw new WazuhError("certificateNotConfirmed", { endpoint: endpoint.kind });
    }
  }
  const resolve = deps.resolve ?? resolveWazuhAddress;
  const attributed = async <T>(kind: WazuhEndpointKind, work: () => Promise<T>): Promise<T> => {
    try {
      return await work();
    } catch (error) {
      throw error instanceof WazuhError && !error.endpoint ? error.forEndpoint(kind) : error;
    }
  };
  const managerPassword = await openPassword(manager);
  const indexerPassword = await openPassword(indexer);
  const managerAddress = await attributed("manager", () => resolve(manager.host));
  const indexerAddress = await attributed("indexer", () => resolve(indexer.host));
  const common = {
    ...(deps.gapMs !== undefined ? { gapMs: deps.gapMs } : {}),
    ...(deps.maxBytes !== undefined ? { maxBytes: deps.maxBytes } : {}),
    ...(deps.timeoutMs !== undefined ? { timeoutMs: deps.timeoutMs } : {}),
    ...(deps.test ? { test: deps.test } : {}),
  };
  const managerClient = new ManagerClient({
    endpoint: { host: manager.host, port: manager.port, address: managerAddress },
    trust: trustOf(manager) as Trust,
    username: manager.username,
    password: managerPassword,
    ...common,
  });
  const indexerClient = new IndexerClient({
    endpoint: { host: indexer.host, port: indexer.port, address: indexerAddress },
    trust: trustOf(indexer) as Trust,
    username: indexer.username,
    password: indexerPassword,
    ...common,
  });
  const deadline = Date.now() + (deps.budgetMs ?? SYNC_BUDGET_MINUTES * 60_000);
  const maxRequests = deps.maxRequests ?? MAX_REQUESTS_PER_SYNC;
  const total = () => managerClient.requests + indexerClient.requests;
  let consecutiveTimeouts = 0;

  /** Budget, deadline and timeout bookkeeping around every request. */
  const call = async <T>(work: () => Promise<T>): Promise<T> => {
    if (total() >= maxRequests) throw new WazuhError("tooManyRequests");
    if (Date.now() > deadline) throw new WazuhError("syncTimeout", { minutes: SYNC_BUDGET_MINUTES });
    try {
      const result = await work();
      consecutiveTimeouts = 0;
      return result;
    } catch (error) {
      consecutiveTimeouts = errorCodeOf(error) === "timeout" ? consecutiveTimeouts + 1 : 0;
      throw error;
    } finally {
      progress.requests = total();
    }
  };
  /** An optional read: a refusal or a malformed answer is tolerated (null), a lost connection is not. */
  const optional = async <T>(work: () => Promise<T>): Promise<{ ok: true; data: T } | { ok: false }> => {
    try {
      return { ok: true, data: await call(work) };
    } catch (error) {
      if (error instanceof CertificateMismatch) throw error;
      if (error instanceof WazuhError && !FATAL.includes(error.code) && consecutiveTimeouts < 5) {
        return { ok: false };
      }
      throw error;
    }
  };

  try {
    const collected = await collect(connection, managerClient, indexerClient, call, optional);
    await store(run, connection, collected, total());
  } catch (error) {
    // A certificate other than the pin: record what was seen, so an admin can decide (the password was never sent).
    for (const [kind, endpoint, client] of [
      ["manager", manager, managerClient],
      ["indexer", indexer, indexerClient],
    ] as const) {
      const seen =
        error instanceof CertificateMismatch && error.endpoint === kind ? error.seen : client.mismatch;
      if (seen) await applyObservedCertificate(connection, endpoint, seen);
    }
    throw error;
  } finally {
    managerClient.close();
    indexerClient.close();
  }
}

type Call = <T>(work: () => Promise<T>) => Promise<T>;
type Optional = <T>(work: () => Promise<T>) => Promise<{ ok: true; data: T } | { ok: false }>;

async function collect(
  connection: ConnectionRow,
  manager: ManagerClient,
  indexer: IndexerClient,
  call: Call,
  optional: Optional,
): Promise<Collected> {
  const warnings = new Set<WazuhWarning>();

  // 1. Is this Wazuh, which version, and which adapter reads it?
  await call(() => manager.login());
  const version = parseApiInfo(await call(() => manager.get("/")));
  if (!version) throw new WazuhError("notWazuh", { endpoint: "manager" });
  const adapter = adapterFor(version);
  if (!adapter) throw new WazuhError("unsupportedVersion", { version: version.version });
  const indexerVersion = parseIndexerInfo(await call(() => indexer.get("/")));
  if (!indexerVersion) throw new WazuhError("notWazuh", { endpoint: "indexer" });

  // 2. What can the two service users do? Nothing is read before an admin has seen any extra privilege.
  const policies = extraManagerPrivileges(await call(() => manager.get("/security/users/me/policies")));
  if (policies === null) throw new WazuhError("policiesUnreadable");
  let indexerExtra: string[] = [];
  const authinfo = await optional(() => indexer.get("/_plugins/_security/authinfo"));
  if (authinfo.ok) {
    const permissions = await optional(() => indexer.get("/_plugins/_security/api/permissionsinfo"));
    const found = extraIndexerPrivileges(authinfo.data, permissions.ok ? permissions.data : null);
    if (found === null) warnings.add("rolesUnreadable");
    else indexerExtra = found;
  } else {
    warnings.add("rolesUnreadable");
  }
  const extra = [...new Set([...policies, ...indexerExtra])].sort();
  const c = schema.wazuhConnection;
  await db.transaction(async (tx) => {
    await tx
      .update(c)
      .set({
        adapter: adapter.id,
        managerVersion: version.version,
        indexerVersion,
        extraPrivileges: extra,
        permissionsCheckedAt: new Date(),
      })
      .where(eq(c.id, connection.id));
    if (extra.length > 0 && extra.join("\n") !== connection.extraPrivileges.join("\n")) {
      await tx.insert(schema.auditLog).values({
        organizationId: connection.organizationId,
        action: "xdr.privileges_detected",
        targetType: "wazuh_connection",
        targetId: connection.id,
        data: { name: connection.name, privileges: extra.slice(0, 50) },
      });
    }
  });
  if (extra.length > 0 && !privilegesAcknowledged(extra, connection.acknowledgedPrivileges)) {
    throw new WazuhError("privilegesNotAcknowledged");
  }

  // 3. Agents, from the manager API, page by page.
  const agents: WazuhAgentInfo[] = [];
  let total = 0;
  let offset = 0;
  while (agents.length < MAX_AGENTS) {
    const body = await call(() => manager.get("/agents", agentsQuery(offset)));
    const page = parseAgents(body);
    if (offset === 0 && page.items.length === 0)
      throw new WazuhError("invalidResponse", { endpoint: "manager" });
    if (page.dropped > 0) warnings.add("entriesDropped");
    if (offset === 0) total = page.total;
    for (const a of page.items) if (agents.length < MAX_AGENTS) agents.push(a);
    offset += AGENTS_PAGE_SIZE;
    if (page.items.length === 0 || offset >= Math.max(total, 0)) break;
  }
  if (total > MAX_AGENTS) warnings.add("agentsTruncated");

  // 4. Aggregations from the indexer. Each is optional: a role that lacks one index must not stop the others.
  const windows: Collected["windows"] = {};
  const sources: Collected["sources"] = {};
  const attacks: Collected["attacks"] = {};
  const readable = await optional(() => indexer.run(adapter, { kind: "alertsReadable" }));
  if (!readable.ok) warnings.add("alertsUnreadable");
  else {
    for (const window of WINDOWS) {
      const stats = await optional(() => indexer.run(adapter, { kind: "alertStats", window }));
      const parsed = stats.ok ? parseAlertStats(stats.data) : null;
      if (!parsed) {
        warnings.add("alertsUnreadable");
        continue;
      }
      const prev = await optional(() => indexer.run(adapter, { kind: "alertStatsPrevious", window }));
      const previous = prev.ok ? parsePreviousStats(prev.data) : null;
      const readAt = new Date();
      windows[window] = {
        readAt: readAt.toISOString(),
        total: parsed.total,
        bySeverity: parsed.bySeverity,
        // Numbers only: the snapshot never holds an address. The previous period's addresses go to the attack table.
        previous: previous ? { total: previous.total, bySeverity: previous.bySeverity } : null,
        tactics: parsed.tactics,
        agents: parsed.agents,
        fim: parsed.fim,
      };
      sources[window] = parsed.sources;
      if (parsed.attack)
        attacks[window] = { readAt, current: parsed.attack, previous: previous?.attack ?? null };
    }
  }
  let fim: FimEvent[] | null = null;
  if (readable.ok) {
    const sample = await optional(() => indexer.run(adapter, { kind: "fimLatest" }));
    if (sample.ok) fim = parseFimEvents(sample.data, adapter);
    else warnings.add("fimUnreadable");
  }
  let vulnerabilities: Map<string, SeverityCounts> | null = null;
  const vulns = await optional(() => indexer.run(adapter, { kind: "vulnerabilityStats" }));
  if (vulns.ok) vulnerabilities = parseVulnerabilityStats(vulns.data);
  if (!vulnerabilities) warnings.add("vulnerabilitiesUnreadable");

  return {
    adapter,
    managerVersion: version.version,
    indexerVersion,
    agents,
    windows,
    sources,
    attacks,
    fim,
    vulnerabilities,
    warnings,
  };
}

/** Replaces what is stored about the connection with what was read, in one transaction. */
async function store(run: RunRow, connection: ConnectionRow, d: Collected, requests: number): Promise<void> {
  const now = new Date();
  const a = schema.wazuhAgent;
  await db.transaction(async (tx) => {
    // --- agents
    const prior = new Map(
      (await tx.select().from(a).where(eq(a.connectionId, connection.id))).map((x) => [x.agentId, x]),
    );
    const rows = d.agents.map((agent) => {
      const old = prior.get(agent.agentId);
      const vuln = d.vulnerabilities?.get(agent.agentId);
      const keep = (n: number | null | undefined) => n ?? null;
      return {
        id: old?.id ?? newId("wza"),
        organizationId: connection.organizationId,
        connectionId: connection.id,
        agentId: agent.agentId,
        name: agent.name,
        ip: agent.ip,
        osName: agent.osName,
        osVersion: agent.osVersion,
        osPlatform: agent.osPlatform,
        arch: agent.arch,
        version: agent.version,
        status: agent.status,
        lastKeepAliveAt: agent.lastKeepAliveAt,
        groups: agent.groups,
        registeredAt: agent.registeredAt,
        isManager: agent.isManager,
        // Counts from this answer; an agent the indexer does not list has none reported (null); an unreadable
        // indexer keeps what was known.
        vulnCritical: d.vulnerabilities ? (vuln?.critical ?? null) : keep(old?.vulnCritical),
        vulnHigh: d.vulnerabilities ? (vuln?.high ?? null) : keep(old?.vulnHigh),
        vulnMedium: d.vulnerabilities ? (vuln?.medium ?? null) : keep(old?.vulnMedium),
        vulnLow: d.vulnerabilities ? (vuln?.low ?? null) : keep(old?.vulnLow),
        firstSeenAt: old?.firstSeenAt ?? now,
        lastSeenAt: now,
      };
    });
    for (let i = 0; i < rows.length; i += 400) {
      await tx
        .insert(a)
        .values(rows.slice(i, i + 400))
        .onConflictDoUpdate({
          target: [a.connectionId, a.agentId],
          set: {
            name: sql`excluded.name`,
            ip: sql`excluded.ip`,
            osName: sql`excluded.os_name`,
            osVersion: sql`excluded.os_version`,
            osPlatform: sql`excluded.os_platform`,
            arch: sql`excluded.arch`,
            version: sql`excluded.version`,
            status: sql`excluded.status`,
            lastKeepAliveAt: sql`excluded.last_keep_alive_at`,
            groups: sql`excluded.groups`,
            registeredAt: sql`excluded.registered_at`,
            isManager: sql`excluded.is_manager`,
            vulnCritical: sql`excluded.vuln_critical`,
            vulnHigh: sql`excluded.vuln_high`,
            vulnMedium: sql`excluded.vuln_medium`,
            vulnLow: sql`excluded.vuln_low`,
            lastSeenAt: sql`excluded.last_seen_at`,
          },
        });
    }
    // Agents that were not in this answer are gone (removed from Wazuh): every kept row has lastSeenAt = now.
    await tx.delete(a).where(and(eq(a.connectionId, connection.id), lt(a.lastSeenAt, now)));

    // --- suggestions: which existing server is probably the machine behind an unlinked agent
    const linkedHosts = new Set(
      (
        await tx
          .select({ hostId: a.hostId })
          .from(a)
          .where(and(eq(a.organizationId, connection.organizationId), isNotNull(a.hostId)))
      ).map((x) => x.hostId as string),
    );
    const h = schema.host;
    const hosts = (
      await tx
        .select({ id: h.id, name: h.name, address: h.address })
        .from(h)
        .where(eq(h.organizationId, connection.organizationId))
    ).filter((x) => !linkedHosts.has(x.id));
    const unlinked = await tx
      .select({ id: a.id, name: a.name, ip: a.ip, isManager: a.isManager })
      .from(a)
      .where(and(eq(a.connectionId, connection.id), isNull(a.hostId)));
    const suggestions = new Map<string, { hostId: string; reason: "address" | "name" | "hostname" }>();
    const perHost = new Map<string, number>();
    for (const agent of unlinked) {
      const found = suggestHost(agent, hosts);
      if (found) {
        suggestions.set(agent.id, found);
        perHost.set(found.hostId, (perHost.get(found.hostId) ?? 0) + 1);
      }
    }
    for (const agent of unlinked) {
      const found = suggestions.get(agent.id);
      // Two agents that suggest the same server are ambiguous: suggest it for neither.
      const ok = found && perHost.get(found.hostId) === 1 ? found : null;
      await tx
        .update(a)
        .set({ suggestedHostId: ok?.hostId ?? null, suggestionReason: ok?.reason ?? null })
        .where(eq(a.id, agent.id));
    }
    await tx
      .update(a)
      .set({ suggestedHostId: null, suggestionReason: null })
      .where(and(eq(a.connectionId, connection.id), isNotNull(a.hostId)));

    // --- the aggregates: windows read now replace their old values, the others stay
    const [priorSnapshot] = await tx
      .select()
      .from(schema.wazuhSnapshot)
      .where(eq(schema.wazuhSnapshot.connectionId, connection.id))
      .limit(1);
    const before: Snapshot = readSnapshot(priorSnapshot?.data);
    const snapshot: Snapshot = {
      windows: { ...before.windows, ...d.windows },
      vulnerabilities: d.vulnerabilities
        ? sumVulnerabilities(d.vulnerabilities, now.toISOString())
        : before.vulnerabilities,
    };
    await tx
      .insert(schema.wazuhSnapshot)
      .values({
        connectionId: connection.id,
        organizationId: connection.organizationId,
        data: snapshot,
        syncedAt: now,
      })
      .onConflictDoUpdate({
        target: schema.wazuhSnapshot.connectionId,
        set: { data: snapshot, syncedAt: now },
      });

    // --- source addresses for the attack overview (windows read now)
    const s = schema.wazuhSourceIp;
    const readWindows = Object.keys(d.sources) as Window[];
    if (readWindows.length > 0) {
      await tx.delete(s).where(and(eq(s.connectionId, connection.id), inArray(s.window, readWindows)));
      const sourceRows = readWindows.flatMap((window) =>
        (d.sources[window] ?? []).map((x) => ({
          id: newId("wzs"),
          organizationId: connection.organizationId,
          connectionId: connection.id,
          window,
          ip: x.ip,
          count: x.count,
          groups: x.groups,
          seenAt: now,
          firstSeenAt: x.firstSeen,
          lastSeenAt: x.lastSeen,
          agents: x.agents,
        })),
      );
      for (let i = 0; i < sourceRows.length; i += 400) {
        await tx
          .insert(s)
          .values(sourceRows.slice(i, i + 400))
          .onConflictDoNothing();
      }
    }

    // --- attack numbers per window (windows read now)
    const attackWindows = Object.keys(d.attacks) as Window[];
    if (attackWindows.length > 0) {
      const w = schema.wazuhAttackWindow;
      await tx.delete(w).where(and(eq(w.connectionId, connection.id), inArray(w.window, attackWindows)));
      await tx.insert(w).values(
        attackWindows.map((window) => {
          const x = d.attacks[window] as NonNullable<Collected["attacks"][Window]>;
          return {
            organizationId: connection.organizationId,
            connectionId: connection.id,
            window,
            attackAlerts: x.current.alerts,
            distinctSources: x.current.distinctSources,
            agents: x.current.agents,
            previousAttackAlerts: x.previous?.alerts ?? null,
            previousDistinctSources: x.previous?.distinctSources ?? null,
            previousSources: x.previous?.sources ?? [],
            readAt: x.readAt,
          };
        }),
      );
    }

    // --- the sample of file integrity events
    if (d.fim) {
      const f = schema.wazuhFimEvent;
      await tx.delete(f).where(eq(f.connectionId, connection.id));
      if (d.fim.length > 0) {
        await tx.insert(f).values(
          d.fim.map((event) => ({
            id: newId("wzf"),
            organizationId: connection.organizationId,
            connectionId: connection.id,
            at: event.at,
            agentId: event.agentId,
            agentName: event.agentName,
            path: event.path,
            event: event.event,
            ruleLevel: event.level,
          })),
        );
      }
    }

    // --- the connection and the run
    await tx
      .update(schema.wazuhConnection)
      .set({
        adapter: d.adapter.id,
        managerVersion: d.managerVersion,
        indexerVersion: d.indexerVersion,
        lastSyncAt: now,
        lastError: null,
        updatedAt: now,
      })
      .where(eq(schema.wazuhConnection.id, connection.id));
    await tx
      .update(schema.wazuhSyncRun)
      .set({
        state: "succeeded",
        finishedAt: now,
        agentCount: rows.length,
        requestCount: requests,
        warnings: [...d.warnings],
        error: null,
      })
      .where(eq(schema.wazuhSyncRun.id, run.id));
  });
}

/* -------------------------------------------------------------------------- */
/* Schedule                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * One tick of the Wazuh schedule: queues a sync for every enabled connection whose two
 * certificates are confirmed and whose service users are acknowledged, unless one is waiting,
 * running or was queued in the last ten minutes. Also sends again syncs that may have been lost
 * between queueing and sending, and looks again at the certificates of endpoints that are
 * blocked by a changed one.
 */
export async function wazuhTick(boss: PgBoss): Promise<void> {
  const c = schema.wazuhConnection;
  const e = schema.wazuhEndpoint;
  const r = schema.wazuhSyncRun;
  const due = await db
    .select()
    .from(c)
    .where(
      and(
        eq(c.enabled, true),
        sql`not exists (select 1 from ${e} where ${e.connectionId} = ${c.id} and ${e.certStatus} <> 'confirmed')`,
        sql`(select count(*) from ${e} where ${e.connectionId} = ${c.id}) = 2`,
        sql`not exists (select 1 from ${r} where ${r.connectionId} = ${c.id}
              and (${r.state} in ('queued', 'running') or ${r.createdAt} > now() - interval '10 minutes'))`,
      ),
    );
  for (const connection of due) {
    if (
      connection.extraPrivileges.length > 0 &&
      !privilegesAcknowledged(connection.extraPrivileges, connection.acknowledgedPrivileges)
    ) {
      continue;
    }
    const runId = newId("wzr");
    await db.insert(r).values({
      id: runId,
      organizationId: connection.organizationId,
      connectionId: connection.id,
      state: "queued",
      trigger: "schedule",
      createdAt: new Date(),
    });
    await boss.send(WAZUH_SYNC_QUEUE, { runId }, { ...WAZUH_SYNC_JOB, singletonKey: connection.id });
  }
  // An endpoint whose certificate changed blocks its connection, but is looked at again now and then (no password is
  // sent): if the pinned certificate is back, the alarm clears itself; otherwise the candidate stays current.
  const changed = await db
    .select({ id: e.id })
    .from(e)
    .innerJoin(c, eq(c.id, e.connectionId))
    .where(and(eq(c.enabled, true), eq(e.certStatus, "changed")));
  for (const endpoint of changed) {
    await boss.send(
      WAZUH_CERT_QUEUE,
      { endpointId: endpoint.id },
      { retryLimit: 0, singletonKey: endpoint.id },
    );
  }
  const stranded = await db
    .select({ id: r.id, connectionId: r.connectionId })
    .from(r)
    .where(and(eq(r.state, "queued"), sql`${r.createdAt} < now() - interval '2 minutes'`))
    .limit(100);
  for (const run of stranded) {
    await boss.send(
      WAZUH_SYNC_QUEUE,
      { runId: run.id },
      { ...WAZUH_SYNC_JOB, singletonKey: run.connectionId },
    );
  }
}

/** Registers the tick: every 15 minutes, cron evaluated in UTC. */
export async function startWazuhScheduler(boss: PgBoss): Promise<void> {
  await boss.createQueue(WAZUH_TICK_QUEUE);
  await boss.schedule(WAZUH_TICK_QUEUE, `*/${WAZUH_SYNC_INTERVAL_MINUTES} * * * *`, null, { tz: "UTC" });
  await boss.work(WAZUH_TICK_QUEUE, { batchSize: 1 }, async () => {
    await wazuhTick(boss);
  });
}
