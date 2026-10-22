/**
 * Directory sign-in in the worker (ADR 0020). Only the worker opens the service account's
 * password, so only the worker talks to the directory: the API queues a request, the worker
 * answers it in the same table, the API reads the answer and deletes the row.
 *
 * What this module does with the directory, and nothing else:
 *   1. bind as the read-only service account and search for the person (filter values escaped),
 *   2. bind as that person on a second connection to check the password (never empty),
 *   3. read the groups the person is in, from the groups named in the configuration only.
 * It never writes to the directory, follows no referrals, and never returns or logs a password.
 */
import { randomBytes } from "node:crypto";
import {
  AD_CHAIN_RULE,
  type CertificateFacts,
  checkPassword,
  checkUsername,
  type DirectoryProblem,
  type DirectoryUser,
  escapeFilterValue,
  isUnderDn,
  matchedGroups,
  normalizeDn,
  readEmail,
  readText,
  readUniqueId,
  renderFilter,
  roleForGroups,
  type SignInResult,
  sameDn,
  type TestResult,
} from "@garnetops/core/directory";
import { open } from "@garnetops/core/vault";
import { applyDirectoryRole, schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { InvalidCredentialsError, NoSuchObjectError, SizeLimitExceededError } from "ldapts";
import { db } from "./db.ts";
import {
  connectDirectory,
  type DirectoryConnection,
  DirectoryError,
  type DirectoryNetHooks,
  openSecureSocket,
  type TrustPolicy,
  targetOf,
} from "./directory-net.ts";
import { vaultPrivateKey } from "./env.ts";
import { tellUsers } from "./user-notify.ts";

export const DIRECTORY_QUEUE = "directory.request";

/** How long the service account is left alone after the directory refused its password (so it cannot be locked out). */
export const BIND_BLOCK_MINUTES = 10;
/** The whole request, from taking it to answering it. The API waits a little longer. */
export const REQUEST_DEADLINE_MS = 25_000;

type ConfigRow = typeof schema.ldapConfig.$inferSelect;
type DirectoryServerRow = schema.DirectoryServerRow;

export interface DirectoryDeps {
  net?: DirectoryNetHooks;
  /** Overrides the 25 s deadline (tests). */
  deadlineMs?: number;
}

/* -------------------------------------------------------------------------- */
/* Secrets                                                                     */
/* -------------------------------------------------------------------------- */

async function openSecret(
  secretId: string,
  organizationId: string,
  purpose: "ldap-bind-password" | "ldap-user-password",
): Promise<string | null> {
  const [row] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, secretId),
        eq(schema.secret.organizationId, organizationId),
        eq(schema.secret.purpose, purpose),
      ),
    )
    .limit(1);
  if (!row) return null;
  const plain = open(row.sealed, { organizationId, recordId: row.id, purpose }, vaultPrivateKey);
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

/* -------------------------------------------------------------------------- */
/* One request's connections                                                   */
/* -------------------------------------------------------------------------- */

const trustFor = (config: ConfigRow, server: DirectoryServerRow): TrustPolicy =>
  config.tlsTrust === "ca"
    ? { kind: "ca", ca: config.caCertificate }
    : config.tlsTrust === "pin"
      ? { kind: "pin", pin: server.pin?.fingerprint ?? null }
      : { kind: "system" };

/** Everything one request opens, so a deadline or an error closes it all. */
class Session {
  private readonly open = new Set<DirectoryConnection>();
  readonly config: ConfigRow;
  readonly deps: DirectoryDeps;
  readonly deadline: number;
  constructor(config: ConfigRow, deps: DirectoryDeps) {
    this.config = config;
    this.deps = deps;
    this.deadline = Date.now() + (deps.deadlineMs ?? REQUEST_DEADLINE_MS);
  }

  /** Throws when the request has used its time; called between directory operations. */
  checkTime(): void {
    if (Date.now() > this.deadline) throw new DirectoryError("timeout");
  }

  async connect(server: DirectoryServerRow): Promise<DirectoryConnection> {
    this.checkTime();
    const connection = await connectDirectory(server.url, trustFor(this.config, server), {
      connectTimeoutMs: this.config.connectTimeoutSeconds * 1000,
      operationTimeoutMs: this.config.operationTimeoutSeconds * 1000,
      ...(this.deps.net ? { hooks: this.deps.net } : {}),
    });
    this.open.add(connection);
    // The pinned certificate is back after an alarm: the alarm clears itself.
    if (this.config.tlsTrust === "pin" && server.certStatus !== "confirmed") {
      await recordCertificate(this.config, server.url, connection.certificate);
    }
    return connection;
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.open].map((c) => c.close().catch(() => {})));
    this.open.clear();
  }
}

/** Remembers what a server presented (changed or not yet confirmed) so an admin can decide. Audited once per change. */
async function recordCertificate(config: ConfigRow, url: string, seen: CertificateFacts): Promise<void> {
  let news = false;
  await db.transaction(async (tx) => {
    const [row] = await tx
      .select({ servers: schema.ldapConfig.servers })
      .from(schema.ldapConfig)
      .where(eq(schema.ldapConfig.organizationId, config.organizationId))
      .for("update");
    if (!row) return;
    const now = new Date().toISOString();
    const servers = row.servers.map((server): DirectoryServerRow => {
      if (server.url !== url) return server;
      const pinned = server.pin?.fingerprint ?? null;
      if (pinned !== null && pinned === seen.fingerprint) {
        return { ...server, certStatus: "confirmed", candidate: null };
      }
      const candidate = { ...seen, seenAt: now };
      if (pinned !== null) {
        if (server.certStatus !== "changed" || server.candidate?.fingerprint !== seen.fingerprint)
          news = true;
        return { ...server, certStatus: "changed", candidate };
      }
      return { ...server, certStatus: "pending", candidate };
    });
    // The version moves too: an owner who is about to confirm a certificate is told it changed under them.
    await tx
      .update(schema.ldapConfig)
      .set({ servers, updatedAt: new Date() })
      .where(eq(schema.ldapConfig.organizationId, config.organizationId));
    if (news) {
      await tx.insert(schema.auditLog).values({
        organizationId: config.organizationId,
        action: "directory.certificate_changed",
        targetType: "ldap_config",
        targetId: config.organizationId,
        data: {
          server: url,
          pinned: config.servers.find((s) => s.url === url)?.pin?.fingerprint ?? null,
          seen: seen.fingerprint,
        },
      });
    }
  });
  if (news) {
    await tellUsers({
      organizationId: config.organizationId,
      titleKey: "certificateChangedDirectory",
      params: { name: url },
      link: "/settings?section=signin",
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Talking LDAP                                                                */
/* -------------------------------------------------------------------------- */

/** ldapts reports a timed-out operation as a plain error ("Operation timed out", "Connection timeout"). */
const isTimeout = (error: unknown) => /time(?:d)? ?out/i.test((error as Error)?.message ?? "");

/** An attribute of a search entry, matched case-insensitively; the server decides how it spells names. */
function attribute(entry: Record<string, unknown>, name: string): unknown {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(entry)) {
    if (key.toLowerCase() === wanted && !(Array.isArray(value) && value.length === 0)) return value;
  }
  return undefined;
}

const asList = (value: unknown): string[] =>
  (Array.isArray(value) ? value : value === undefined ? [] : [value]).filter(
    (v): v is string => typeof v === "string",
  );

/** Binds as the service account on the first server that answers; a refused password stops the walk (no lock-out). */
async function connectAsService(
  session: Session,
  password: string,
): Promise<{ connection: DirectoryConnection; server: DirectoryServerRow }> {
  const { config } = session;
  let last: DirectoryError = new DirectoryError("unreachable");
  for (const server of config.servers) {
    let connection: DirectoryConnection | undefined;
    try {
      connection = await session.connect(server);
      await connection.client.bind(config.bindDn, password);
      return { connection, server };
    } catch (error) {
      if (connection) await connection.close().catch(() => {});
      if (error instanceof DirectoryError) {
        last = error;
        if (
          error.seen &&
          (error.problem === "certificate-changed" || error.problem === "certificate-not-confirmed")
        ) {
          await recordCertificate(config, server.url, error.seen);
        }
      } else if (error instanceof InvalidCredentialsError) {
        // Stop here: another server would only count one more wrong password against the account.
        await blockServiceAccount(config);
        throw new DirectoryError("service-bind-failed");
      } else {
        last = new DirectoryError(isTimeout(error) ? "timeout" : "service-bind-failed");
      }
    }
  }
  throw last;
}

/** The directory refused the service account's password: leave it alone for a while so it cannot be locked out. */
async function blockServiceAccount(config: ConfigRow): Promise<void> {
  await db
    .update(schema.ldapConfig)
    .set({ bindBlockedUntil: sql`now() + ${`${BIND_BLOCK_MINUTES} minutes`}::interval` })
    .where(eq(schema.ldapConfig.organizationId, config.organizationId));
}

type Found =
  | {
      kind: "found";
      dn: string;
      uniqueId: string;
      email: string | null;
      name: string | null;
      memberOf: string[];
    }
  | { kind: "none" };

/**
 * Searches for the person. The name is escaped into the configured filter; exactly one entry below
 * the base counts. With `at`, only that entry is looked at (the periodic check of a known account).
 */
async function findUser(
  session: Session,
  service: DirectoryConnection,
  username: string,
  at?: string,
): Promise<Found> {
  const { config } = session;
  session.checkTime();
  const filter = renderFilter(config.userFilter, { username });
  const attributes = [
    config.emailAttribute,
    config.nameAttribute,
    config.uniqueIdAttribute,
    ...(config.groupMode === "member-of" ? ["memberOf"] : []),
  ];
  let entries: Record<string, unknown>[];
  try {
    const result = await service.client.search(at ?? config.userBaseDn, {
      scope: at ? "base" : "sub",
      filter,
      attributes,
      // Two are enough to know the filter is ambiguous.
      sizeLimit: 2,
      timeLimit: config.operationTimeoutSeconds,
      explicitBufferAttributes: [config.uniqueIdAttribute],
    });
    entries = result.searchEntries as Record<string, unknown>[];
  } catch (error) {
    if (error instanceof SizeLimitExceededError) throw new DirectoryError("user-ambiguous");
    // A known account whose entry is gone is a result; a search base that is gone is a misconfiguration.
    if (error instanceof NoSuchObjectError) {
      if (at) return { kind: "none" };
      throw new DirectoryError("base-not-found");
    }
    throw new DirectoryError(isTimeout(error) ? "timeout" : "search-failed");
  }
  if (entries.length === 0) return { kind: "none" };
  if (entries.length > 1) throw new DirectoryError("user-ambiguous");
  const entry = entries[0] as Record<string, unknown>;
  const dn = typeof entry.dn === "string" ? entry.dn : "";
  // A server that answers with an entry outside the base (or a DN we cannot read) is not believed.
  if (!isUnderDn(dn, config.userBaseDn)) throw new DirectoryError("user-outside-base");
  const uniqueId = readUniqueId(config.uniqueIdAttribute, attribute(entry, config.uniqueIdAttribute));
  if (!uniqueId) throw new DirectoryError("no-unique-id");
  return {
    kind: "found",
    dn,
    uniqueId,
    email: readEmail(attribute(entry, config.emailAttribute)),
    name: readText(attribute(entry, config.nameAttribute), 120),
    memberOf: asList(attribute(entry, "memberOf")),
  };
}

/** Which of the configured groups the person is in. Only the configured groups are asked about. */
async function groupsOf(
  session: Session,
  service: DirectoryConnection,
  found: Extract<Found, { kind: "found" }>,
  username: string,
): Promise<string[]> {
  const { config } = session;
  if (config.groupMode === "member-of") return matchedGroups(found.memberOf, config.groupRoles);
  const filter =
    config.groupMode === "nested"
      ? `(member:${AD_CHAIN_RULE}:=${escapeFilterValue(found.dn)})`
      : renderFilter(config.groupFilter, { dn: found.dn, username });
  const member: string[] = [];
  const seen = new Set<string>();
  for (const group of config.groupRoles) {
    const key = normalizeDn(group.dn);
    if (key === null || seen.has(key)) continue;
    seen.add(key);
    session.checkTime();
    try {
      const result = await service.client.search(group.dn, {
        scope: "base",
        filter,
        attributes: ["1.1"],
        sizeLimit: 1,
        timeLimit: config.operationTimeoutSeconds,
      });
      if (result.searchEntries.length > 0) member.push(group.dn);
    } catch (error) {
      // A group that does not exist has no members; any other failure must not turn into "not a member".
      if (error instanceof NoSuchObjectError) continue;
      if (error instanceof SizeLimitExceededError) {
        member.push(group.dn);
        continue;
      }
      throw new DirectoryError(isTimeout(error) ? "timeout" : "group-search-failed");
    }
  }
  return member;
}

function userOf(
  found: Extract<Found, { kind: "found" }>,
  groups: string[],
  config: ConfigRow,
): DirectoryUser {
  return {
    uniqueId: found.uniqueId,
    dn: found.dn,
    email: found.email,
    name: found.name,
    groups,
    role: roleForGroups(groups, config.groupRoles),
  };
}

/** Whether the service account may be tried now. */
const blocked = (config: ConfigRow) =>
  config.bindBlockedUntil !== null && config.bindBlockedUntil > new Date();

async function serviceSecret(config: ConfigRow): Promise<string> {
  if (!config.bindSecretId) throw new DirectoryError("not-configured");
  const password = await openSecret(config.bindSecretId, config.organizationId, "ldap-bind-password");
  if (!password) throw new DirectoryError("not-configured");
  return password;
}

/* -------------------------------------------------------------------------- */
/* Operations                                                                  */
/* -------------------------------------------------------------------------- */

function failure(error: unknown): { outcome: SignInResult["outcome"]; problem: DirectoryProblem } {
  if (error instanceof DirectoryError) {
    const problem = error.problem;
    const misconfigured: DirectoryProblem[] = [
      "not-configured",
      "service-bind-failed",
      "service-bind-blocked",
      "base-not-found",
      "search-failed",
      "user-ambiguous",
      "user-outside-base",
      "no-unique-id",
      "group-search-failed",
    ];
    return { outcome: misconfigured.includes(problem) ? "misconfigured" : "unavailable", problem };
  }
  console.error(`directory: ${(error as Error)?.name ?? "error"}`);
  return { outcome: "unavailable", problem: "internal" };
}

/**
 * A sign-in. The password is checked by the directory itself; this function never sees whether
 * it is right any other way. Anything that is not a clear "yes" is a refusal.
 */
export async function signIn(
  config: ConfigRow,
  username: string,
  password: string,
  deps: DirectoryDeps = {},
): Promise<SignInResult> {
  const name = checkUsername(username);
  const secret = checkPassword(password);
  // Defence in depth: the API checks these too. An empty password must never reach a bind.
  if (!name || !secret) return { outcome: "invalid-credentials", problem: "wrong-password" };
  if (!config.enabled) return { outcome: "unavailable", problem: "disabled" };
  if (blocked(config)) return { outcome: "misconfigured", problem: "service-bind-blocked" };
  const session = new Session(config, deps);
  try {
    const service = await connectAsService(session, await serviceSecret(config));
    const found = await findUser(session, service.connection, name);
    // A second connection to the same server carries the person's password; the service connection stays untouched.
    const userConnection = await session.connect(service.server);
    if (found.kind === "none") {
      // Same number of round trips as a real attempt, so the answer does not take less time for unknown names.
      await userConnection.client
        .bind(
          `cn=${randomBytes(6).toString("hex")},${config.userBaseDn}`,
          randomBytes(18).toString("base64url"),
        )
        .catch(() => {});
      return { outcome: "invalid-credentials", problem: "user-not-found" };
    }
    try {
      await userConnection.client.bind(found.dn, secret);
    } catch (error) {
      if (error instanceof InvalidCredentialsError) {
        return {
          outcome: "invalid-credentials",
          problem: "wrong-password",
          subject: { dn: found.dn, uniqueId: found.uniqueId },
        };
      }
      throw new DirectoryError(isTimeout(error) ? "timeout" : "unreachable");
    }
    const groups = await groupsOf(session, service.connection, found, name);
    const user = userOf(found, groups, config);
    return user.role ? { outcome: "ok", user } : { outcome: "not-allowed", problem: "not-in-group", user };
  } catch (error) {
    return failure(error);
  } finally {
    await session.closeAll();
  }
}

/** Finds a person without a password (linking an existing account). Nothing is bound as the person. */
export async function lookup(
  config: ConfigRow,
  username: string,
  deps: DirectoryDeps = {},
): Promise<SignInResult> {
  const name = checkUsername(username);
  if (!name) return { outcome: "invalid-credentials", problem: "user-not-found" };
  if (blocked(config)) return { outcome: "misconfigured", problem: "service-bind-blocked" };
  const session = new Session(config, deps);
  try {
    const service = await connectAsService(session, await serviceSecret(config));
    const found = await findUser(session, service.connection, name);
    if (found.kind === "none") return { outcome: "invalid-credentials", problem: "user-not-found" };
    const groups = await groupsOf(session, service.connection, found, name);
    const user = userOf(found, groups, config);
    return user.role ? { outcome: "ok", user } : { outcome: "not-allowed", problem: "not-in-group", user };
  } catch (error) {
    return failure(error);
  } finally {
    await session.closeAll();
  }
}

/**
 * The connection test: every server (TLS, trust, service bind), the search base, and, when a
 * user name is given, what the directory says about that person. Never needs or shows a password.
 */
export async function test(
  config: ConfigRow,
  username: string | null,
  deps: DirectoryDeps = {},
): Promise<TestResult> {
  const started = performance.now();
  const servers: TestResult["servers"] = [];
  const result: TestResult = { ok: false, servers, latencyMs: 0 };
  const session = new Session(config, deps);
  try {
    if (blocked(config)) throw new DirectoryError("service-bind-blocked");
    const password = await serviceSecret(config);
    let working: { connection: DirectoryConnection; server: DirectoryServerRow } | null = null;
    // Report every server, not just the first that works: a second domain controller with a wrong certificate is worth knowing.
    for (const server of config.servers) {
      const transport = targetOf(server.url).scheme === "ldaps" ? "ldaps" : "starttls";
      let connection: DirectoryConnection | undefined;
      try {
        connection = await session.connect(server);
        await connection.client.bind(config.bindDn, password);
        servers.push({ url: server.url, ok: true, transport, certificate: connection.certificate });
        if (!working) working = { connection, server };
      } catch (error) {
        let problem: DirectoryProblem = "service-bind-failed";
        let detail: string | undefined;
        let seen: CertificateFacts | undefined;
        if (error instanceof DirectoryError) {
          problem = error.problem;
          detail = error.detail;
          seen = error.seen;
          if (seen && (problem === "certificate-changed" || problem === "certificate-not-confirmed")) {
            await recordCertificate(config, server.url, seen);
          }
        } else if (error instanceof InvalidCredentialsError) {
          await blockServiceAccount(config);
        }
        servers.push({
          url: server.url,
          ok: false,
          problem,
          transport,
          ...(seen ? { certificate: seen } : {}),
          ...(detail ? { detail } : {}),
        });
        if (connection && working?.connection !== connection) await connection.close().catch(() => {});
        // Another attempt with a refused password would only count against the account.
        if (error instanceof InvalidCredentialsError) break;
      }
    }
    if (!working) {
      const first = servers.find((s) => !s.ok);
      result.problem = first?.problem ?? "unreachable";
      return result;
    }
    // The search base must exist, whoever is looked up.
    try {
      await working.connection.client.search(config.userBaseDn, {
        scope: "base",
        filter: "(objectClass=*)",
        attributes: ["1.1"],
        sizeLimit: 1,
        timeLimit: config.operationTimeoutSeconds,
      });
    } catch (error) {
      result.problem = error instanceof NoSuchObjectError ? "base-not-found" : "search-failed";
      return result;
    }
    // Which configured groups exist. A typo in a group name would otherwise show up as "nobody can sign in".
    const groups: NonNullable<TestResult["groups"]> = [];
    for (const group of config.groupRoles) {
      session.checkTime();
      let exists = true;
      try {
        await working.connection.client.search(group.dn, {
          scope: "base",
          filter: "(objectClass=*)",
          attributes: ["1.1"],
          sizeLimit: 1,
          timeLimit: config.operationTimeoutSeconds,
        });
      } catch (error) {
        if (error instanceof NoSuchObjectError) exists = false;
        else throw new DirectoryError("group-search-failed");
      }
      groups.push({ dn: group.dn, exists, member: false });
    }
    result.groups = groups;
    if (username === null) {
      result.ok = true;
      return result;
    }
    const name = checkUsername(username);
    if (!name) {
      result.problem = "user-not-found";
      return result;
    }
    const found = await findUser(session, working.connection, name);
    if (found.kind === "none") {
      result.problem = "user-not-found";
      return result;
    }
    const memberOf = await groupsOf(session, working.connection, found, name);
    for (const g of groups) g.member = memberOf.some((m) => sameDn(m, g.dn));
    result.user = userOf(found, memberOf, config);
    result.ok = true;
    return result;
  } catch (error) {
    result.problem = error instanceof DirectoryError ? error.problem : failure(error).problem;
    return result;
  } finally {
    result.latencyMs = Math.round(performance.now() - started);
    await session.closeAll();
  }
}

/**
 * Reads the certificate each server presents (or one server's), without sending anything, and
 * stores it as the candidate an admin confirms, or flags a change. Never pins by itself.
 */
export async function readCertificates(
  config: ConfigRow,
  url: string | null,
  deps: DirectoryDeps = {},
): Promise<{ servers: { url: string; certificate?: CertificateFacts; problem?: DirectoryProblem }[] }> {
  const out: { url: string; certificate?: CertificateFacts; problem?: DirectoryProblem }[] = [];
  for (const server of config.servers) {
    if (url !== null && server.url !== url) continue;
    try {
      const { socket, certificate } = await openSecureSocket(targetOf(server.url), trustFor(config, server), {
        connectTimeoutMs: config.connectTimeoutSeconds * 1000,
        inspect: true,
        ...(deps.net ? { hooks: deps.net } : {}),
      });
      socket.destroy();
      await recordCertificate(config, server.url, certificate);
      out.push({ url: server.url, certificate });
    } catch (error) {
      out.push({ url: server.url, problem: error instanceof DirectoryError ? error.problem : "internal" });
    }
  }
  return { servers: out };
}

/* -------------------------------------------------------------------------- */
/* The periodic check                                                          */
/* -------------------------------------------------------------------------- */

/** How often the groups of every directory account are read again. Sign-in checks them too; this ends a session that outlives a change. */
export const RECONCILE_INTERVAL_MINUTES = 15;
/** Accounts checked per run; more would take too long for one pass. */
const RECONCILE_MAX_ACCOUNTS = 1000;
const RECONCILE_DEADLINE_MS = 10 * 60_000;

export interface ReconcileSummary {
  checked: number;
  changed: number;
  removed: number;
  /** The directory could not be asked (or answered wrongly): nothing was changed. */
  skipped: boolean;
}

/**
 * Asks the directory about every account that came from it and makes membership say the same
 * (ADR 0020): a person removed from the allowed groups, deleted, or no longer matching the user
 * filter (for example because the account is disabled) loses their membership and sessions; a
 * changed group changes the role. Without this, a session that is kept busy would outlive the
 * person's access in the directory, because sessions renew while they are used.
 *
 * Fails safe in the other direction on purpose: if the directory cannot be asked, or answers with
 * something unexpected, nobody is changed. An outage must not sign everyone out.
 */
export async function reconcileDirectory(
  config: ConfigRow,
  deps: DirectoryDeps = {},
): Promise<ReconcileSummary> {
  const summary: ReconcileSummary = { checked: 0, changed: 0, removed: 0, skipped: false };
  if (!config.enabled || blocked(config) || !config.bindSecretId) return { ...summary, skipped: true };
  const people = await db
    .select({
      userId: schema.directoryIdentity.userId,
      uniqueId: schema.directoryIdentity.uniqueId,
      dn: schema.directoryIdentity.dn,
      loginName: schema.directoryIdentity.loginName,
      email: schema.user.email,
      role: schema.membership.role,
    })
    .from(schema.directoryIdentity)
    .innerJoin(
      schema.membership,
      and(
        eq(schema.membership.userId, schema.directoryIdentity.userId),
        eq(schema.membership.organizationId, config.organizationId),
      ),
    )
    .innerJoin(schema.user, eq(schema.user.id, schema.directoryIdentity.userId))
    .where(eq(schema.directoryIdentity.organizationId, config.organizationId))
    .limit(RECONCILE_MAX_ACCOUNTS);
  if (people.length === 0) return summary;

  const session = new Session(config, { ...deps, deadlineMs: deps.deadlineMs ?? RECONCILE_DEADLINE_MS });
  // First ask about everybody; change things only when the directory answered for all of them.
  const decisions: { person: (typeof people)[number]; role: ReturnType<typeof roleForGroups> }[] = [];
  try {
    const service = await connectAsService(session, await serviceSecret(config));
    for (const person of people) {
      const found = await findUser(session, service.connection, person.loginName, person.dn);
      // A different person at this name, or no one, means the account's directory entry is gone.
      if (found.kind === "none" || found.uniqueId !== person.uniqueId) {
        decisions.push({ person, role: null });
      } else {
        const groups = await groupsOf(session, service.connection, found, person.loginName);
        decisions.push({ person, role: roleForGroups(groups, config.groupRoles) });
      }
      summary.checked++;
    }
  } catch (error) {
    console.error(
      `directory reconcile: ${error instanceof DirectoryError ? error.problem : ((error as Error)?.name ?? "error")}`,
    );
    return { ...summary, skipped: true };
  } finally {
    await session.closeAll();
  }
  for (const { person, role } of decisions) {
    const change = await db.transaction((tx) =>
      applyDirectoryRole(tx, { organizationId: config.organizationId, userId: person.userId, role }),
    );
    if (change.kind === "unchanged" || change.kind === "owner") continue;
    await db.insert(schema.auditLog).values({
      organizationId: config.organizationId,
      action: change.kind === "removed" ? "directory.access_removed" : "directory.role_changed",
      targetType: "user",
      targetId: person.userId,
      data: { email: person.email, before: change.before, after: change.after, via: "check" },
    });
    if (change.kind === "removed") summary.removed++;
    else {
      summary.changed++;
      await tellUsers({
        organizationId: config.organizationId,
        titleKey: "roleChanged",
        params: { role: change.after ?? "" },
        link: "/account",
        context: { targetUserId: person.userId },
      });
    }
  }
  return summary;
}

let reconciling = false;

/** Runs the check for every organisation with an enabled directory. One run at a time. */
export async function reconcileAll(deps: DirectoryDeps = {}): Promise<void> {
  if (reconciling) return;
  reconciling = true;
  try {
    const configs = await db.select().from(schema.ldapConfig).where(eq(schema.ldapConfig.enabled, true));
    for (const config of configs) {
      const summary = await reconcileDirectory(config, deps);
      if (summary.changed + summary.removed > 0) {
        console.log(
          `directory: checked ${summary.checked}, changed ${summary.changed}, removed ${summary.removed}`,
        );
      }
    }
  } finally {
    reconciling = false;
  }
}

/** Starts the periodic check. Returns a function that stops it. */
export function startDirectoryReconcile(): () => void {
  const run = () => reconcileAll().catch((error: Error) => console.error("directory check:", error.name));
  const first = setTimeout(run, 60_000);
  const timer = setInterval(run, RECONCILE_INTERVAL_MINUTES * 60_000);
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}

/* -------------------------------------------------------------------------- */
/* The queue                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Takes one queued request, answers it and stores the answer. A password sealed for it is
 * deleted the moment the request is taken, whatever happens next; the answer never contains it.
 */
export async function runDirectoryRequest(requestId: string, deps: DirectoryDeps = {}): Promise<void> {
  const r = schema.directoryRequest;
  const [request] = await db
    .update(r)
    .set({ status: "running" })
    .where(and(eq(r.id, requestId), eq(r.status, "pending")))
    .returning();
  if (!request) return;

  let password: string | null = null;
  if (request.passwordSecretId) {
    try {
      password = await openSecret(request.passwordSecretId, request.organizationId, "ldap-user-password");
    } catch {
      password = null;
    }
    await db.delete(schema.secret).where(eq(schema.secret.id, request.passwordSecretId));
  }

  let result: Record<string, unknown>;
  try {
    const [config] = await db
      .select()
      .from(schema.ldapConfig)
      .where(eq(schema.ldapConfig.organizationId, request.organizationId))
      .limit(1);
    if (!config) {
      result = { outcome: "unavailable", problem: "not-configured", ok: false };
    } else if (request.kind === "sign-in") {
      result = (await signIn(
        config,
        request.params.username ?? "",
        password ?? "",
        deps,
      )) as unknown as Record<string, unknown>;
    } else if (request.kind === "lookup") {
      result = (await lookup(config, request.params.username ?? "", deps)) as unknown as Record<
        string,
        unknown
      >;
    } else if (request.kind === "test") {
      const tested = await test(config, request.params.username ?? null, deps);
      // A test that found a person marks exactly these settings as tested; a change since then wins.
      if (tested.ok && tested.user) {
        await db
          .update(schema.ldapConfig)
          .set({ testedAt: new Date() })
          .where(
            and(
              eq(schema.ldapConfig.organizationId, config.organizationId),
              // JavaScript dates have milliseconds, the column has microseconds.
              sql`date_trunc('milliseconds', ${schema.ldapConfig.updatedAt}) = date_trunc('milliseconds', ${config.updatedAt}::timestamptz)`,
            ),
          );
      }
      result = tested as unknown as Record<string, unknown>;
    } else {
      result = (await readCertificates(config, request.params.url ?? null, deps)) as unknown as Record<
        string,
        unknown
      >;
    }
  } catch (error) {
    result = { ...failure(error), ok: false };
  }
  await db.update(r).set({ status: "done", result }).where(eq(r.id, request.id));
}

/** Removes answers nobody collected and passwords of requests that never ran. */
export async function sweepDirectory(): Promise<void> {
  const old = await db
    .delete(schema.directoryRequest)
    .where(sql`${schema.directoryRequest.createdAt} < now() - interval '10 minutes'`)
    .returning({ secretId: schema.directoryRequest.passwordSecretId });
  for (const row of old) {
    if (row.secretId) await db.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
  }
  // Defence in depth: a sealed password whose request is gone (the row cascades on delete of the secret only one way).
  await db.execute(sql`
    delete from secret
    where purpose = 'ldap-user-password' and created_at < now() - interval '10 minutes'`);
}
