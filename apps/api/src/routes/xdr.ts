/**
 * Wazuh / XDR (ADR 0015): a read-only view of a customer-run Wazuh. Everyone in the
 * organisation reads; owners and admins configure. Creating, re-pointing and removing the
 * connection, changing a password, a certificate authority or the addresses shown to people,
 * confirming a certificate and acknowledging users with more than read privileges also need a
 * recent sign-in (step-up). The API only seals the two passwords; the worker opens them and is the
 * only component that talks to Wazuh or to the model. Responses never contain a password, a
 * certificate authority's private data or anything Wazuh sent beyond the fields stored by the sync.
 */
import { X509Certificate } from "node:crypto";
import { newId } from "@garnetops/core";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { normalizeFingerprint } from "@garnetops/core/proxmox";
import { seal } from "@garnetops/core/vault";
import {
  ADAPTERS,
  type AdapterId,
  AGENT_STATUSES,
  checkCaPem,
  checkConnectionName,
  checkDashboardUrl,
  checkEnrollmentHost,
  checkWazuhUrl,
  checkWazuhUsername,
  MAX_WAZUH_CONNECTIONS,
  privilegesAcknowledged,
  readSnapshot,
  WAZUH_INDEXER_PORT,
  WAZUH_MANAGER_PORT,
  WAZUH_PASSWORD_PATTERN,
  WAZUH_SYNC_INTERVAL_MINUTES,
  type WazuhVersion,
} from "@garnetops/core/wazuh";
import { buildEnrollment, ENROLL_ARCH, ENROLL_OS } from "@garnetops/core/wazuh-enroll";
import { schema } from "@garnetops/db";
import {
  and,
  count,
  desc,
  eq,
  getTableColumns,
  ilike,
  inArray,
  isNotNull,
  isNull,
  or,
  sql,
} from "drizzle-orm";
import { type AnyPgColumn, alias } from "drizzle-orm/pg-core";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { unifiActive } from "../lib/attack-live.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, isAdmin, requireRole } from "../lib/context.ts";
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

const c = schema.wazuhConnection;
const e = schema.wazuhEndpoint;
const a = schema.wazuhAgent;
const h = schema.host;
type EndpointRow = typeof e.$inferSelect;
type Kind = "manager" | "indexer";

/** Same job options as the worker uses when its schedule queues a sync (apps/worker/src/wazuh.ts). */
const SYNC_JOB = { retryLimit: 0, expireInSeconds: 10 * 60 };
const CERT_JOB = { retryLimit: 1, expireInSeconds: 5 * 60 };
const SUMMARY_JOB = { retryLimit: 0, expireInSeconds: 15 * 60 };
/** AI requests share the budgets of AI triage (ADR 0013). */
const AI_USER_PER_MINUTE = 12;
const AI_ORG_PER_MINUTE = 40;
/** A summary that is still pending after this long no longer blocks a new one. */
const SUMMARY_GRACE_MINUTES = 15;

const PURPOSE = { manager: "wazuh-api-password", indexer: "wazuh-indexer-password" } as const;
const kindParam = z.enum(["manager", "indexer"]);

const escapeLike = (text: string) => `%${text.replace(/[%_\\]/g, "\\$&")}%`;
const iso = (d: Date | null) => d?.toISOString() ?? null;

type FieldError = { field: string; code: string };
function invalid(errors: FieldError[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((x) => ({ path: x.field, message: x.code })),
  });
}

/* -------------------------------------------------------------------------- */
/* Loading                                                                     */
/* -------------------------------------------------------------------------- */

async function loadConnection(organizationId: string) {
  const [connection] = await db.select().from(c).where(eq(c.organizationId, organizationId)).limit(1);
  if (!connection) return null;
  const endpoints = await db.select().from(e).where(eq(e.connectionId, connection.id));
  const manager = endpoints.find((x) => x.kind === "manager");
  const indexer = endpoints.find((x) => x.kind === "indexer");
  if (!manager || !indexer) return null;
  return { connection, manager, indexer };
}
type Loaded = NonNullable<Awaited<ReturnType<typeof loadConnection>>>;

async function ownConnection(organizationId: string): Promise<Loaded> {
  const loaded = await loadConnection(organizationId);
  if (!loaded) throw notFound("Wazuh connection");
  return loaded;
}

const queueCertificate = (endpointId: string) =>
  boss.send(QUEUES.xdrCertificate, { endpointId }, { ...CERT_JOB, singletonKey: endpointId });

/** Queues a sync unless one is already waiting or running. */
async function queueSync(
  organizationId: string,
  connectionId: string,
  requestedBy: string | null,
  trigger: "manual" | "setup",
): Promise<{ runId: string; alreadyQueued: boolean }> {
  const r = schema.wazuhSyncRun;
  const [active] = await db
    .select({ id: r.id })
    .from(r)
    .where(and(eq(r.connectionId, connectionId), inArray(r.state, ["queued", "running"])))
    .limit(1);
  if (active) return { runId: active.id, alreadyQueued: true };
  const runId = newId("wzr");
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
  await boss.send(QUEUES.xdrSync, { runId }, { ...SYNC_JOB, singletonKey: connectionId });
  return { runId, alreadyQueued: false };
}

async function latestRun(connectionId: string) {
  const r = schema.wazuhSyncRun;
  const [run] = await db
    .select({
      id: r.id,
      state: r.state,
      trigger: r.trigger,
      error: r.error,
      warnings: r.warnings,
      agentCount: r.agentCount,
      requestCount: r.requestCount,
      createdAt: r.createdAt,
      finishedAt: r.finishedAt,
    })
    .from(r)
    .where(eq(r.connectionId, connectionId))
    .orderBy(desc(r.createdAt), desc(r.id))
    .limit(1);
  return run ?? null;
}

/* -------------------------------------------------------------------------- */
/* Presentation                                                                */
/* -------------------------------------------------------------------------- */

/** The subjects of an uploaded certificate authority, for the admin to recognise it. */
function caSummary(pem: string | null) {
  if (!pem) return null;
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\n]+?-----END CERTIFICATE-----/g) ?? [];
  const subjects: string[] = [];
  let validTo: Date | null = null;
  for (const block of blocks) {
    try {
      const x = new X509Certificate(block);
      subjects.push(x.subject.replace(/\n/g, ", ").slice(0, 200));
      const to = new Date(x.validTo);
      if (!validTo || to < validTo) validTo = to;
    } catch {
      // A damaged stored value is shown as one certificate less.
    }
  }
  return { count: blocks.length, subjects, validTo: iso(validTo) };
}

function presentEndpoint(row: EndpointRow, admin: boolean) {
  const certificate = {
    status: row.certStatus,
    ...(admin
      ? {
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
        }
      : {}),
  };
  return {
    kind: row.kind,
    trust: row.trustMode,
    certificate,
    lastError: row.lastError,
    ...(admin
      ? {
          apiUrl: row.apiUrl,
          host: row.host,
          port: row.port,
          username: row.username,
          ca: caSummary(row.caPem),
        }
      : {}),
  };
}

function adapterView(id: AdapterId | null) {
  if (!id) return null;
  const adapter = ADAPTERS[id];
  return { id: adapter.id, preview: adapter.preview };
}

function presentConnection(loaded: Loaded, admin: boolean, run: Awaited<ReturnType<typeof latestRun>>) {
  const { connection: row, manager, indexer } = loaded;
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    dashboardUrl: row.dashboardUrl,
    ...(admin ? { enrollmentHost: row.enrollmentHost } : {}),
    adapter: adapterView(row.adapter),
    managerVersion: row.managerVersion,
    indexerVersion: row.indexerVersion,
    endpoints: [presentEndpoint(manager, admin), presentEndpoint(indexer, admin)],
    privileges: {
      /** Actions and roles of the two service users beyond reading; empty means they can only read. */
      extra: row.extraPrivileges,
      acknowledged: privilegesAcknowledged(row.extraPrivileges, row.acknowledgedPrivileges),
      acknowledgedAt: iso(row.privilegesAcknowledgedAt),
      checkedAt: iso(row.permissionsCheckedAt),
    },
    lastSyncAt: iso(row.lastSyncAt),
    lastError: row.lastError,
    run,
    createdAt: row.createdAt,
  };
}

/* -------------------------------------------------------------------------- */
/* Agents                                                                      */
/* -------------------------------------------------------------------------- */

const linkedHost = alias(h, "linked_host");
const suggestedHost = alias(h, "suggested_host");

const msKey = (col: AnyPgColumn) => sql`coalesce(date_trunc('milliseconds', ${col}), 'epoch'::timestamptz)`;
const SORTS = {
  name: { keys: [sql`lower(${a.name})`], parse: [parseText], dir: "asc" },
  status: { keys: [a.status], parse: [parseText], dir: "asc" },
  os: { keys: [sql`lower(coalesce(${a.osName}, ''))`], parse: [parseText], dir: "asc" },
  version: { keys: [sql`coalesce(${a.version}, '')`], parse: [parseText], dir: "desc" },
  keepAlive: { keys: [msKey(a.lastKeepAliveAt)], parse: [parseDate], dir: "desc" },
  vulnerabilities: {
    keys: [
      sql`coalesce(${a.vulnCritical}, -1)`,
      sql`coalesce(${a.vulnHigh}, -1)`,
      sql`coalesce(${a.vulnMedium}, -1)`,
    ],
    parse: [parseNumber, parseNumber, parseNumber],
    dir: "desc",
  },
} satisfies Record<string, SortOption>;
type SortName = keyof typeof SORTS;
const sortNames = Object.keys(SORTS) as [SortName, ...SortName[]];

type AgentListRow = typeof a.$inferSelect & {
  linkedName: string | null;
  suggestedName: string | null;
  sortKeys?: (string | number | Date)[];
};
const defaultSpec: KeysetSpec<AgentListRow> = {
  keys: [sql`lower(${a.name})`, a.id],
  direction: "asc",
  keyOf: (row) => [row.name.toLowerCase(), row.id],
  parse: [parseText, parseText],
};

const agentFilters = {
  q: z.string().trim().max(100).optional(),
  status: z.enum(AGENT_STATUSES).optional(),
  group: z
    .string()
    .regex(/^[A-Za-z0-9._-]{1,128}$/)
    .optional(),
  /** "linked": a confirmed server. "unlinked": none. "suggested": none yet, but GarnetOps has an idea. */
  link: z.enum(["all", "linked", "unlinked", "suggested"]).default("all"),
};
const agentListQuery = z.object({
  ...agentFilters,
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  sort: z.enum(sortNames).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

function agentWhere(organizationId: string, input: z.infer<z.ZodObject<typeof agentFilters>>) {
  const like = input.q ? escapeLike(input.q) : null;
  return and(
    eq(a.organizationId, organizationId),
    input.status ? eq(a.status, input.status) : undefined,
    input.group ? sql`${a.groups} @> ${JSON.stringify([input.group])}::jsonb` : undefined,
    input.link === "linked" ? isNotNull(a.hostId) : undefined,
    input.link === "unlinked" ? isNull(a.hostId) : undefined,
    input.link === "suggested" ? and(isNull(a.hostId), isNotNull(a.suggestedHostId)) : undefined,
    like
      ? or(
          ilike(a.name, like),
          ilike(sql<string>`coalesce(${a.ip}, '')`, like),
          ilike(sql<string>`coalesce(${a.osName}, '')`, like),
          ilike(sql<string>`coalesce(${a.version}, '')`, like),
          sql`${a.groups}::text ilike ${like}`,
          sql`${a.agentId} like ${like}`,
        )
      : undefined,
  );
}

function presentAgent(row: AgentListRow) {
  const vulnerabilities =
    row.vulnCritical === null && row.vulnHigh === null && row.vulnMedium === null && row.vulnLow === null
      ? null
      : {
          critical: row.vulnCritical ?? 0,
          high: row.vulnHigh ?? 0,
          medium: row.vulnMedium ?? 0,
          low: row.vulnLow ?? 0,
        };
  return {
    id: row.id,
    connectionId: row.connectionId,
    agentId: row.agentId,
    name: row.name,
    ip: row.ip,
    os: { name: row.osName, version: row.osVersion, platform: row.osPlatform },
    arch: row.arch,
    version: row.version,
    status: row.status,
    lastKeepAliveAt: iso(row.lastKeepAliveAt),
    groups: row.groups,
    registeredAt: iso(row.registeredAt),
    isManager: row.isManager,
    vulnerabilities,
    server: row.hostId ? { id: row.hostId, name: row.linkedName ?? "" } : null,
    suggestion:
      !row.hostId && row.suggestedHostId
        ? { hostId: row.suggestedHostId, hostName: row.suggestedName ?? "", reason: row.suggestionReason }
        : null,
  };
}

/* -------------------------------------------------------------------------- */
/* Writes                                                                      */
/* -------------------------------------------------------------------------- */

const endpointFields = {
  apiUrl: z.string().max(400),
  username: z.string().max(200),
  password: z.string().max(400),
  caPem: z.string().max(30_000).optional(),
};
const createBody = z.object({
  name: z.string().max(300),
  dashboardUrl: z.string().max(500).optional(),
  enrollmentHost: z.string().max(300).optional(),
  managerApiUrl: endpointFields.apiUrl,
  managerUsername: endpointFields.username,
  managerPassword: endpointFields.password,
  managerCaPem: endpointFields.caPem,
  indexerApiUrl: endpointFields.apiUrl,
  indexerUsername: endpointFields.username,
  indexerPassword: endpointFields.password,
  indexerCaPem: endpointFields.caPem,
});
const patchBody = z.object({
  name: z.string().max(300).optional(),
  enabled: z.boolean().optional(),
  dashboardUrl: z.string().max(500).nullable().optional(),
  enrollmentHost: z.string().max(300).nullable().optional(),
  managerApiUrl: endpointFields.apiUrl.optional(),
  managerUsername: endpointFields.username.optional(),
  managerPassword: endpointFields.password.optional(),
  managerCaPem: endpointFields.caPem.nullable().optional(),
  indexerApiUrl: endpointFields.apiUrl.optional(),
  indexerUsername: endpointFields.username.optional(),
  indexerPassword: endpointFields.password.optional(),
  indexerCaPem: endpointFields.caPem.nullable().optional(),
});

const isCertificate = (pem: string) => {
  try {
    new X509Certificate(pem);
    return true;
  } catch {
    return false;
  }
};

function checkUrl(kind: Kind, value: string, errors: FieldError[]) {
  const field = `${kind}ApiUrl`;
  const url = checkWazuhUrl(value, kind === "manager" ? WAZUH_MANAGER_PORT : WAZUH_INDEXER_PORT);
  if (!url.ok) errors.push({ field, code: `url_${url.problem}` });
  return url.ok ? url : null;
}
function checkUser(kind: Kind, value: string, errors: FieldError[]) {
  const user = checkWazuhUsername(value);
  if (!user.ok) errors.push({ field: `${kind}Username`, code: `user_${user.problem}` });
  return user.ok ? user.value : null;
}
function checkPassword(kind: Kind, value: string, errors: FieldError[]) {
  if (!WAZUH_PASSWORD_PATTERN.test(value))
    errors.push({ field: `${kind}Password`, code: "password_invalid" });
  return WAZUH_PASSWORD_PATTERN.test(value);
}
function checkCa(kind: Kind, value: string, errors: FieldError[]) {
  const ca = checkCaPem(value, isCertificate);
  if (!ca.ok) errors.push({ field: `${kind}CaPem`, code: "ca_invalid" });
  return ca.ok ? ca.pem : null;
}

async function storeSecret(organizationId: string, userId: string, kind: Kind, plain: string) {
  const id = newId("sec");
  await db.insert(schema.secret).values({
    id,
    organizationId,
    purpose: PURPOSE[kind],
    sealed: seal(plain, { organizationId, recordId: id, purpose: PURPOSE[kind] }, vaultPublicKey),
    vaultKeyId: vaultPublicKey.id,
    createdBy: userId,
  });
  return id;
}

/** What is cleared when the server behind an endpoint, or the way it is trusted, changes. */
const FORGET_CERTIFICATE = {
  certStatus: "pending" as const,
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
};
const FORGET_PRIVILEGES = {
  extraPrivileges: [] as string[],
  acknowledgedPrivileges: [] as string[],
  privilegesAcknowledgedAt: null,
  privilegesAcknowledgedBy: null,
  permissionsCheckedAt: null,
};

const confirmBody = z.object({ fingerprint: z.string().max(100) });
const acknowledgeBody = z.object({ privileges: z.array(z.string().max(120)).max(200) });
const linkBody = z.object({ hostId: z.string().max(80) });
const summaryBody = z.object({ language: z.enum(["en", "de"]).default("en") });
const enrollmentQuery = z.object({
  os: z.enum(ENROLL_OS),
  arch: z.enum(ENROLL_ARCH).default("amd64"),
  group: z.string().max(200).optional(),
  name: z.string().max(200).optional(),
  password: z.enum(["0", "1", "true", "false"]).optional(),
});

/* -------------------------------------------------------------------------- */
/* AI availability                                                             */
/* -------------------------------------------------------------------------- */

async function aiAvailability(organizationId: string) {
  const [row] = await db
    .select({ enabled: schema.aiSettings.enabled, model: schema.aiSettings.model })
    .from(schema.aiSettings)
    .where(eq(schema.aiSettings.organizationId, organizationId))
    .limit(1);
  if (!row) return { state: "not-configured" as const };
  if (!row.enabled) return { state: "disabled" as const };
  return { state: "ready" as const, model: row.model };
}

/* -------------------------------------------------------------------------- */
/* Routes                                                                      */
/* -------------------------------------------------------------------------- */

export const xdrRoutes = new Hono<AppEnv>()
  /**
   * Whether the XDR entry shows in the navigation: a connection exists. `attacks` is whether the Attacks entry does: a
   * Wazuh connection exists or UniFi threat events are on (ADR 0022). Reveals nothing else.
   */
  .get("/status", async (c2) => {
    const actor = c2.get("actor");
    const [row] = await db.select({ n: count() }).from(c).where(eq(c.organizationId, actor.organizationId));
    const connected = (row?.n ?? 0) > 0;
    return c2.json({ connected, attacks: connected || (await unifiActive(actor.organizationId)) });
  })

  /* ------------------------------ connection ------------------------------ */
  .get("/connection", async (c2) => {
    const actor = c2.get("actor");
    const loaded = await loadConnection(actor.organizationId);
    if (!loaded) return c2.json({ syncIntervalMinutes: WAZUH_SYNC_INTERVAL_MINUTES, connection: null });
    return c2.json({
      syncIntervalMinutes: WAZUH_SYNC_INTERVAL_MINUTES,
      connection: presentConnection(loaded, isAdmin(actor), await latestRun(loaded.connection.id)),
    });
  })
  .post("/connection", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = createBody.parse(await c2.req.json());
    const errors: FieldError[] = [];
    const name = checkConnectionName(body.name);
    if (name === null) errors.push({ field: "name", code: "name_invalid" });
    let dashboardUrl: string | null = null;
    if (body.dashboardUrl?.trim()) {
      const d = checkDashboardUrl(body.dashboardUrl);
      if (!d.ok) errors.push({ field: "dashboardUrl", code: "dashboard_invalid" });
      else dashboardUrl = d.url;
    }
    let enrollmentHost: string | null = null;
    if (body.enrollmentHost?.trim()) {
      const eh = checkEnrollmentHost(body.enrollmentHost);
      if (!eh.ok) errors.push({ field: "enrollmentHost", code: "enrollment_invalid" });
      else enrollmentHost = eh.value;
    }
    const managerUrl = checkUrl("manager", body.managerApiUrl, errors);
    const indexerUrl = checkUrl("indexer", body.indexerApiUrl, errors);
    const managerUser = checkUser("manager", body.managerUsername, errors);
    const indexerUser = checkUser("indexer", body.indexerUsername, errors);
    const managerPasswordOk = checkPassword("manager", body.managerPassword, errors);
    const indexerPasswordOk = checkPassword("indexer", body.indexerPassword, errors);
    const managerCa = body.managerCaPem?.trim() ? checkCa("manager", body.managerCaPem, errors) : null;
    const indexerCa = body.indexerCaPem?.trim() ? checkCa("indexer", body.indexerCaPem, errors) : null;
    if (
      managerUrl &&
      indexerUrl &&
      managerUrl.host === indexerUrl.host &&
      managerUrl.port === indexerUrl.port
    ) {
      errors.push({ field: "indexerApiUrl", code: "url_same_as_manager" });
    }
    if (
      errors.length > 0 ||
      name === null ||
      !managerUrl ||
      !indexerUrl ||
      !managerUser ||
      !indexerUser ||
      !managerPasswordOk ||
      !indexerPasswordOk
    ) {
      throw invalid(errors);
    }
    requireRecentSignIn(actor);

    const [existing] = await db
      .select({ n: count() })
      .from(c)
      .where(eq(c.organizationId, actor.organizationId));
    if ((existing?.n ?? 0) >= MAX_WAZUH_CONNECTIONS) {
      throw new ProblemError(409, "limit-reached", "The organisation is connected to Wazuh already");
    }
    const id = newId("wzc");
    const managerSecret = await storeSecret(
      actor.organizationId,
      actor.userId,
      "manager",
      body.managerPassword,
    );
    const indexerSecret = await storeSecret(
      actor.organizationId,
      actor.userId,
      "indexer",
      body.indexerPassword,
    );
    const managerId = newId("wze");
    const indexerId = newId("wze");
    await db.transaction(async (tx) => {
      await tx.insert(c).values({
        id,
        organizationId: actor.organizationId,
        name,
        dashboardUrl,
        enrollmentHost,
        createdBy: actor.userId,
      });
      await tx.insert(e).values([
        {
          id: managerId,
          organizationId: actor.organizationId,
          connectionId: id,
          kind: "manager",
          apiUrl: managerUrl.url,
          host: managerUrl.host,
          port: managerUrl.port,
          username: managerUser,
          secretId: managerSecret,
          trustMode: managerCa ? "ca" : "pin",
          caPem: managerCa,
        },
        {
          id: indexerId,
          organizationId: actor.organizationId,
          connectionId: id,
          kind: "indexer",
          apiUrl: indexerUrl.url,
          host: indexerUrl.host,
          port: indexerUrl.port,
          username: indexerUser,
          secretId: indexerSecret,
          trustMode: indexerCa ? "ca" : "pin",
          caPem: indexerCa,
        },
      ]);
    });
    await audit(
      actor,
      "xdr.connection_created",
      { type: "wazuh_connection", id },
      {
        name,
        managerUrl: managerUrl.url,
        managerUser,
        managerTrust: managerCa ? "ca" : "pin",
        indexerUrl: indexerUrl.url,
        indexerUser,
        indexerTrust: indexerCa ? "ca" : "pin",
        ...(dashboardUrl ? { dashboardUrl } : {}),
        ...(enrollmentHost ? { enrollmentHost } : {}),
      },
    );
    await queueCertificate(managerId);
    await queueCertificate(indexerId);
    return c2.json({ id }, 201);
  })
  .patch("/connection", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = patchBody.parse(await c2.req.json());
    const loaded = await ownConnection(actor.organizationId);
    const { connection: row } = loaded;
    const errors: FieldError[] = [];
    const changes: Partial<typeof c.$inferInsert> = {};
    const changed: string[] = [];
    let sensitive = false;

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
    if (body.dashboardUrl !== undefined) {
      let next: string | null = null;
      if (body.dashboardUrl !== null && body.dashboardUrl.trim() !== "") {
        const d = checkDashboardUrl(body.dashboardUrl);
        if (!d.ok) errors.push({ field: "dashboardUrl", code: "dashboard_invalid" });
        else next = d.url;
      }
      if (!errors.some((x) => x.field === "dashboardUrl") && next !== row.dashboardUrl) {
        changes.dashboardUrl = next;
        changed.push("dashboardUrl");
        sensitive = true;
      }
    }
    if (body.enrollmentHost !== undefined) {
      let next: string | null = null;
      if (body.enrollmentHost !== null && body.enrollmentHost.trim() !== "") {
        const eh = checkEnrollmentHost(body.enrollmentHost);
        if (!eh.ok) errors.push({ field: "enrollmentHost", code: "enrollment_invalid" });
        else next = eh.value;
      }
      if (!errors.some((x) => x.field === "enrollmentHost") && next !== row.enrollmentHost) {
        changes.enrollmentHost = next;
        changed.push("enrollmentHost");
        // The address ends up in commands that people paste into their servers: a change needs a recent sign-in.
        sensitive = true;
      }
    }

    interface EndpointChange {
      endpoint: EndpointRow;
      set: Partial<typeof e.$inferInsert>;
      newPassword: string | null;
      repoint: boolean;
      trustChanged: boolean;
      url?: string;
    }
    const endpointChanges: EndpointChange[] = [];
    for (const kind of ["manager", "indexer"] as const) {
      const endpoint = kind === "manager" ? loaded.manager : loaded.indexer;
      const url = body[`${kind}ApiUrl`];
      const user = body[`${kind}Username`];
      const password = body[`${kind}Password`];
      const caPem = body[`${kind}CaPem`];
      const change: EndpointChange = {
        endpoint,
        set: {},
        newPassword: null,
        repoint: false,
        trustChanged: false,
      };
      if (url !== undefined) {
        const checked = checkUrl(kind, url, errors);
        if (checked && (checked.host !== endpoint.host || checked.port !== endpoint.port)) {
          Object.assign(change.set, { apiUrl: checked.url, host: checked.host, port: checked.port });
          change.repoint = true;
          change.url = checked.url;
          changed.push(`${kind}ApiUrl`);
        }
      }
      if (user !== undefined || password !== undefined) {
        const name = user === undefined ? endpoint.username : checkUser(kind, user, errors);
        const passwordOk = password === undefined ? true : checkPassword(kind, password, errors);
        if (name && passwordOk && (name !== endpoint.username || password !== undefined)) {
          // A password belongs to its user name: a new name needs the password again.
          if (password === undefined) errors.push({ field: `${kind}Password`, code: "password_invalid" });
          else {
            change.set.username = name;
            change.newPassword = password;
            changed.push(`${kind}Credentials`);
          }
        }
      }
      if (caPem !== undefined) {
        if (caPem === null || caPem.trim() === "") {
          if (endpoint.trustMode === "ca") {
            Object.assign(change.set, { trustMode: "pin", caPem: null });
            change.trustChanged = true;
            changed.push(`${kind}Trust`);
          }
        } else {
          const pem = checkCa(kind, caPem, errors);
          if (pem && (endpoint.trustMode !== "ca" || endpoint.caPem !== pem)) {
            Object.assign(change.set, { trustMode: "ca", caPem: pem });
            change.trustChanged = true;
            changed.push(`${kind}Trust`);
          }
        }
      }
      if (change.repoint || change.newPassword !== null || change.trustChanged) {
        sensitive = true;
        endpointChanges.push(change);
      }
    }
    if (errors.length > 0) throw invalid(errors);
    if (changed.length === 0) return c2.body(null, 204);
    if (sensitive) requireRecentSignIn(actor);

    // Two endpoints must stay two different servers.
    const finalFor = (kind: Kind) => {
      const change = endpointChanges.find((x) => x.endpoint.kind === kind);
      const endpoint = kind === "manager" ? loaded.manager : loaded.indexer;
      return {
        host: (change?.set.host as string | undefined) ?? endpoint.host,
        port: (change?.set.port as number | undefined) ?? endpoint.port,
      };
    };
    const m = finalFor("manager");
    const i = finalFor("indexer");
    if (m.host === i.host && m.port === i.port) {
      throw invalid([{ field: "indexerApiUrl", code: "url_same_as_manager" }]);
    }

    const oldSecrets: string[] = [];
    let credentialsChanged = false;
    for (const change of endpointChanges) {
      if (change.newPassword !== null) {
        change.set.secretId = await storeSecret(
          actor.organizationId,
          actor.userId,
          change.endpoint.kind,
          change.newPassword,
        );
        if (change.endpoint.secretId) oldSecrets.push(change.endpoint.secretId);
        credentialsChanged = true;
      }
    }
    const forgetCertificate = (change: EndpointChange) => change.repoint || change.trustChanged;
    const privilegesReset = credentialsChanged || endpointChanges.some((x) => x.repoint);
    await db.transaction(async (tx) => {
      await tx
        .update(c)
        .set({ ...changes, ...(privilegesReset ? FORGET_PRIVILEGES : {}), updatedAt: new Date() })
        .where(eq(c.id, row.id));
      for (const change of endpointChanges) {
        await tx
          .update(e)
          .set({
            ...change.set,
            ...(forgetCertificate(change) ? FORGET_CERTIFICATE : {}),
            updatedAt: new Date(),
          })
          .where(eq(e.id, change.endpoint.id));
      }
      if (oldSecrets.length > 0) await tx.delete(schema.secret).where(inArray(schema.secret.id, oldSecrets));
    });
    await audit(
      actor,
      "xdr.connection_changed",
      { type: "wazuh_connection", id: row.id },
      {
        name: changes.name ?? row.name,
        changed,
        ...Object.fromEntries(
          endpointChanges.filter((x) => x.url).map((x) => [`${x.endpoint.kind}Url`, x.url]),
        ),
        ...(changes.dashboardUrl !== undefined ? { dashboardUrl: changes.dashboardUrl } : {}),
        ...(changes.enrollmentHost !== undefined ? { enrollmentHost: changes.enrollmentHost } : {}),
      },
    );
    for (const change of endpointChanges) {
      if (forgetCertificate(change)) await queueCertificate(change.endpoint.id);
    }
    const stillConfirmed =
      !endpointChanges.some(forgetCertificate) &&
      loaded.manager.certStatus === "confirmed" &&
      loaded.indexer.certStatus === "confirmed";
    if (credentialsChanged && stillConfirmed)
      await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    return c2.body(null, 204);
  })
  .delete("/connection", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const loaded = await ownConnection(actor.organizationId);
    await db.transaction(async (tx) => {
      await tx.delete(c).where(eq(c.id, loaded.connection.id));
      const secrets = [loaded.manager.secretId, loaded.indexer.secretId].filter(
        (x): x is string => x !== null,
      );
      if (secrets.length > 0) await tx.delete(schema.secret).where(inArray(schema.secret.id, secrets));
    });
    await audit(
      actor,
      "xdr.connection_deleted",
      { type: "wazuh_connection", id: loaded.connection.id },
      { name: loaded.connection.name, managerUrl: loaded.manager.apiUrl, indexerUrl: loaded.indexer.apiUrl },
    );
    return c2.body(null, 204);
  })

  /* ------------------------------ certificates ------------------------------ */
  .post("/endpoints/:kind/certificate/scan", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const kind = kindParam.parse(c2.req.param("kind"));
    const loaded = await ownConnection(actor.organizationId);
    const endpoint = kind === "manager" ? loaded.manager : loaded.indexer;
    await rateLimit(`xdr-cert:${actor.organizationId}`, 30, 60 * 60_000);
    await queueCertificate(endpoint.id);
    await audit(
      actor,
      "xdr.certificate_scan_requested",
      { type: "wazuh_connection", id: loaded.connection.id },
      { name: loaded.connection.name, endpoint: kind },
    );
    return c2.body(null, 202);
  })
  .post("/endpoints/:kind/certificate/confirm", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const kind = kindParam.parse(c2.req.param("kind"));
    const input = confirmBody.parse(await c2.req.json());
    const fingerprint = normalizeFingerprint(input.fingerprint);
    if (!fingerprint) throw invalid([{ field: "fingerprint", code: "fingerprint_invalid" }]);
    requireRecentSignIn(actor);
    const loaded = await ownConnection(actor.organizationId);
    const row = kind === "manager" ? loaded.manager : loaded.indexer;
    if (row.trustMode === "ca") {
      throw new ProblemError(409, "trust-mode", "This endpoint is verified with your certificate authority");
    }
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
      .update(e)
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
      .where(and(eq(e.id, row.id), eq(e.candidateFingerprint, fingerprint)))
      .returning({ id: e.id });
    if (updated.length === 0) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The certificate has changed since it was shown; compare the new fingerprint",
      );
    }
    await audit(
      actor,
      "xdr.certificate_confirmed",
      { type: "wazuh_connection", id: loaded.connection.id },
      {
        name: loaded.connection.name,
        endpoint: kind,
        fingerprint,
        subject: row.candidateSubject,
        issuer: row.candidateIssuer,
        caTrusted: row.candidateCaTrusted,
        previous: row.certFingerprint,
      },
    );
    const other = kind === "manager" ? loaded.indexer : loaded.manager;
    // The sync needs both: it starts when the second one is confirmed (or the pinned one is replaced).
    if (other.certStatus === "confirmed") {
      const run = await queueSync(
        actor.organizationId,
        loaded.connection.id,
        actor.userId,
        row.certFingerprint ? "manual" : "setup",
      );
      return c2.json({ runId: run.runId });
    }
    return c2.json({ runId: null });
  })
  .post("/privileges/acknowledge", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const input = acknowledgeBody.parse(await c2.req.json());
    requireRecentSignIn(actor);
    const { connection: row, manager, indexer } = await ownConnection(actor.organizationId);
    if (row.extraPrivileges.length === 0) {
      throw new ProblemError(409, "no-extra-privileges", "The users have no privileges beyond reading");
    }
    // The admin acknowledges the list they were shown, not "whatever the users can do now".
    const shown = [...new Set(input.privileges)].sort();
    if (shown.join("\n") !== [...row.extraPrivileges].sort().join("\n")) {
      throw new ProblemError(
        409,
        "privileges-changed",
        "The privileges of the users have changed since they were shown",
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
      "xdr.privileges_acknowledged",
      { type: "wazuh_connection", id: row.id },
      { name: row.name, privileges: row.extraPrivileges.slice(0, 50) },
    );
    if (manager.certStatus === "confirmed" && indexer.certStatus === "confirmed") {
      await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    }
    return c2.body(null, 204);
  })
  .post("/sync", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const { connection: row, manager, indexer } = await ownConnection(actor.organizationId);
    if (manager.certStatus !== "confirmed" || indexer.certStatus !== "confirmed") {
      throw new ProblemError(
        409,
        "certificate-unconfirmed",
        "Confirm the certificates of the Wazuh endpoints first",
      );
    }
    await rateLimit(`xdr-sync:${actor.organizationId}`, 60, 60 * 60_000);
    const result = await queueSync(actor.organizationId, row.id, actor.userId, "manual");
    if (!result.alreadyQueued) {
      await audit(
        actor,
        "xdr.sync_requested",
        { type: "wazuh_connection", id: row.id },
        { runId: result.runId, name: row.name },
      );
    }
    return c2.json(result, result.alreadyQueued ? 200 : 202);
  })
  .get("/runs", async (c2) => {
    const actor = c2.get("actor");
    const { connection: row } = await ownConnection(actor.organizationId);
    const r = schema.wazuhSyncRun;
    const runs = await db
      .select({
        id: r.id,
        state: r.state,
        trigger: r.trigger,
        agentCount: r.agentCount,
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

  /* ------------------------------ the XDR page ------------------------------ */
  .get("/overview", async (c2) => {
    const actor = c2.get("actor");
    const loaded = await loadConnection(actor.organizationId);
    if (!loaded) return c2.json({ connection: null });
    const { connection: row } = loaded;
    const [snapshotRow] = await db
      .select()
      .from(schema.wazuhSnapshot)
      .where(eq(schema.wazuhSnapshot.connectionId, row.id))
      .limit(1);
    const snapshot = readSnapshot(snapshotRow?.data);
    const states = await db
      .select({ status: a.status, n: count() })
      .from(a)
      .where(and(eq(a.connectionId, row.id), eq(a.isManager, false)))
      .groupBy(a.status);
    const n = (status: string) => states.find((s) => s.status === status)?.n ?? 0;
    const [linked] = await db
      .select({ n: count() })
      .from(a)
      .where(and(eq(a.connectionId, row.id), isNotNull(a.hostId)));
    const [suggested] = await db
      .select({ n: count() })
      .from(a)
      .where(and(eq(a.connectionId, row.id), isNull(a.hostId), isNotNull(a.suggestedHostId)));
    const f = schema.wazuhFimEvent;
    const fim = await db
      .select()
      .from(f)
      .where(eq(f.connectionId, row.id))
      .orderBy(desc(f.at), desc(f.id))
      .limit(25);
    return c2.json({
      syncIntervalMinutes: WAZUH_SYNC_INTERVAL_MINUTES,
      connection: presentConnection(loaded, isAdmin(actor), await latestRun(row.id)),
      syncedAt: iso(snapshotRow?.syncedAt ?? null),
      windows: snapshot.windows,
      vulnerabilities: snapshot.vulnerabilities,
      agents: {
        total: states.reduce((sum, s) => sum + s.n, 0),
        active: n("active"),
        disconnected: n("disconnected"),
        neverConnected: n("never_connected"),
        pending: n("pending"),
        linked: linked?.n ?? 0,
        suggested: suggested?.n ?? 0,
      },
      fim: fim.map((x) => ({
        id: x.id,
        at: x.at.toISOString(),
        agentId: x.agentId,
        agentName: x.agentName,
        path: x.path,
        event: x.event,
        level: x.ruleLevel,
      })),
      ai: await aiAvailability(actor.organizationId),
    });
  })
  .get("/agents", async (c2) => {
    const actor = c2.get("actor");
    const input = agentListQuery.parse(c2.req.query());
    const where = agentWhere(actor.organizationId, input);
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, a.id) : null;
    const activeSpec = (sorted?.spec ?? defaultSpec) as KeysetSpec<AgentListRow>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          ...getTableColumns(a),
          linkedName: linkedHost.name,
          suggestedName: suggestedHost.name,
          sortKeys: sorted ? sorted.select : sql<null>`null`,
        })
        .from(a)
        .leftJoin(linkedHost, eq(linkedHost.id, a.hostId))
        .leftJoin(suggestedHost, eq(suggestedHost.id, a.suggestedHostId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(a).where(where),
    ]);
    const page = toPage(
      activeSpec,
      q,
      rows as AgentListRow[],
      totalRow[0]?.n ?? 0,
      input.pageSize,
      Boolean(input.cursor),
      (row) => row,
    );
    return c2.json({ ...page, items: page.items.map(presentAgent) });
  })
  .get("/agents/counts", async (c2) => {
    const actor = c2.get("actor");
    const input = z.object(agentFilters).omit({ status: true }).parse(c2.req.query());
    const base = agentWhere(actor.organizationId, { ...input, link: input.link });
    const rows = await db.select({ status: a.status, n: count() }).from(a).where(base).groupBy(a.status);
    const total = rows.reduce((sum, r) => sum + r.n, 0);
    const result: Record<string, number> = { all: total };
    for (const status of AGENT_STATUSES) result[status] = rows.find((r) => r.status === status)?.n ?? 0;
    return c2.json(result);
  })

  /* ------------------------------ linking agents and servers ------------------------------ */
  .post("/agents/:id/link", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const body = linkBody.parse(await c2.req.json());
    const [agent] = await db
      .select()
      .from(a)
      .where(and(eq(a.id, c2.req.param("id")), eq(a.organizationId, actor.organizationId)))
      .limit(1);
    if (!agent) throw notFound("Agent");
    if (agent.isManager)
      throw new ProblemError(409, "manager-agent", "The manager itself cannot be linked to a server");
    const [host] = await db
      .select({ id: h.id, name: h.name })
      .from(h)
      .where(and(eq(h.id, body.hostId), eq(h.organizationId, actor.organizationId)))
      .limit(1);
    if (!host) throw invalid([{ field: "hostId", code: "host_unknown" }]);
    const [taken] = await db
      .select({ id: a.id })
      .from(a)
      .where(and(eq(a.hostId, host.id), sql`${a.id} <> ${agent.id}`))
      .limit(1);
    if (taken) throw new ProblemError(409, "already-linked", "This server is linked to another agent");
    await db
      .update(a)
      .set({
        hostId: host.id,
        linkedAt: new Date(),
        linkedBy: actor.userId,
        suggestedHostId: null,
        suggestionReason: null,
      })
      .where(eq(a.id, agent.id));
    await audit(
      actor,
      "xdr.agent_linked",
      { type: "wazuh_agent", id: agent.id },
      { agentId: agent.agentId, agentName: agent.name, hostId: host.id, hostName: host.name },
    );
    return c2.body(null, 204);
  })
  .delete("/agents/:id/link", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "admin");
    const [agent] = await db
      .select()
      .from(a)
      .where(and(eq(a.id, c2.req.param("id")), eq(a.organizationId, actor.organizationId)))
      .limit(1);
    if (!agent) throw notFound("Agent");
    if (!agent.hostId) return c2.body(null, 204);
    await db.update(a).set({ hostId: null, linkedAt: null, linkedBy: null }).where(eq(a.id, agent.id));
    await audit(
      actor,
      "xdr.agent_unlinked",
      { type: "wazuh_agent", id: agent.id },
      { agentId: agent.agentId, agentName: agent.name, hostId: agent.hostId },
    );
    return c2.body(null, 204);
  })

  /* ------------------------------ AI summary ------------------------------ */
  .get("/summary", async (c2) => {
    const actor = c2.get("actor");
    const loaded = await loadConnection(actor.organizationId);
    if (!loaded) return c2.json({ summary: null });
    const w = schema.wazuhSummary;
    const [row] = await db
      .select({ summary: w, author: schema.user.name })
      .from(w)
      .leftJoin(schema.user, eq(schema.user.id, w.requestedBy))
      .where(eq(w.connectionId, loaded.connection.id))
      .orderBy(desc(w.createdAt))
      .limit(1);
    if (!row) return c2.json({ summary: null });
    const s = row.summary;
    return c2.json({
      summary: {
        id: s.id,
        status: s.status,
        content: s.status === "complete" ? s.content : "",
        error: s.error,
        model: s.model,
        language: s.language,
        author: row.author,
        createdAt: s.createdAt.toISOString(),
        finishedAt: iso(s.finishedAt),
      },
    });
  })
  .post("/summary", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "member");
    const body = summaryBody.parse(await c2.req.json().catch(() => ({})));
    const loaded = await ownConnection(actor.organizationId);
    const ai = await aiAvailability(actor.organizationId);
    if (ai.state !== "ready") {
      throw new ProblemError(409, "ai-not-ready", "AI is not available", undefined, { state: ai.state });
    }
    const [snapshot] = await db
      .select({ connectionId: schema.wazuhSnapshot.connectionId })
      .from(schema.wazuhSnapshot)
      .where(eq(schema.wazuhSnapshot.connectionId, loaded.connection.id))
      .limit(1);
    if (!snapshot) throw new ProblemError(409, "no-data", "There is nothing to summarise yet");
    await rateLimit(`ai:user:${actor.userId}`, AI_USER_PER_MINUTE);
    await rateLimit(`ai:org:${actor.organizationId}`, AI_ORG_PER_MINUTE);
    const w = schema.wazuhSummary;
    const [busy] = await db
      .select({ id: w.id })
      .from(w)
      .where(
        and(
          eq(w.connectionId, loaded.connection.id),
          inArray(w.status, ["pending", "running"]),
          sql`${w.createdAt} > now() - make_interval(mins => ${SUMMARY_GRACE_MINUTES})`,
        ),
      )
      .limit(1);
    if (busy) throw new ProblemError(429, "summary-busy", "A summary is being written already");
    const id = newId("wzm");
    await db.insert(w).values({
      id,
      organizationId: actor.organizationId,
      connectionId: loaded.connection.id,
      status: "pending",
      language: body.language,
      requestedBy: actor.userId,
      createdAt: new Date(),
    });
    try {
      await boss.send(QUEUES.xdrSummary, { summaryId: id }, SUMMARY_JOB);
    } catch (error) {
      await db
        .update(w)
        .set({ status: "failed", error: "internal", finishedAt: new Date() })
        .where(eq(w.id, id));
      throw error;
    }
    // The prompt is never part of the log, only what was asked about and which model answers.
    await audit(
      actor,
      "ai.request",
      { type: "wazuh_connection", id: loaded.connection.id },
      { kind: "xdr-summary", model: ai.model, summaryId: id },
    );
    return c2.json({ id }, 202);
  })

  /* ------------------------------ agent enrollment helper ------------------------------ */
  .get("/enrollment", async (c2) => {
    const actor = c2.get("actor");
    requireRole(actor, "member");
    const input = enrollmentQuery.parse(c2.req.query());
    const loaded = await ownConnection(actor.organizationId);
    const { connection: row, manager } = loaded;
    if (!row.managerVersion) {
      throw new ProblemError(409, "not-synced", "The version of the manager is not known yet");
    }
    const m = /^(\d+)\.(\d+)/.exec(row.managerVersion);
    const version: WazuhVersion = {
      version: row.managerVersion,
      major: Number(m?.[1] ?? 0),
      minor: Number(m?.[2] ?? 0),
    };
    const address = row.enrollmentHost ?? manager.host;
    const result = buildEnrollment({
      os: input.os,
      arch: input.arch,
      manager: address,
      version,
      group: input.group?.trim() || undefined,
      name: input.name?.trim() || undefined,
      password: input.password === "1" || input.password === "true",
    });
    if (!result.ok) throw invalid([{ field: result.problem, code: `enroll_${result.problem}` }]);
    return c2.json({
      ...result,
      manager: address,
      /** The agents were told to use the API address because no enrollment address was set. */
      addressFromApi: row.enrollmentHost === null,
      managerVersion: row.managerVersion,
    });
  });
