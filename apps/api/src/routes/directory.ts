/**
 * Settings → Sign-in → LDAP and Active Directory (ADR 0020). Owners only. Every change needs a
 * recent sign-in (step-up) and is audit-logged. The API only seals the service account's
 * password; the worker opens it and is the only process that talks to the directory. Nothing
 * here returns the password, a certificate beyond its public facts, or anything the directory
 * sent beyond what the connection test shows an owner.
 */
import { newId } from "@garnetops/core";
import { normalizeFingerprint } from "@garnetops/core/certificates";
import {
  checkDirectorySettings,
  checkUsername,
  DIRECTORY_LIMITS,
  DIRECTORY_PRESETS,
  DIRECTORY_ROLES,
  type DirectorySettings,
  type DirectoryUser,
  GROUP_MODES,
  mayLinkRole,
  TLS_TRUSTS,
} from "@garnetops/core/directory";
import { directoryHostPolicy } from "@garnetops/core/directory-policy";
import { seal } from "@garnetops/core/vault";
import { applyDirectoryRole, schema } from "@garnetops/db";
import { and, count, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { askDirectory, type DirectoryConfigRow, directoryOf } from "../lib/directory.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

type ServerRow = schema.DirectoryServerRow;

const iso = (d: Date | null) => d?.toISOString() ?? null;

function invalid(errors: { field: string; code: string }[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((e) => ({ path: e.field, message: e.code })),
  });
}

const groupRole = z.object({
  dn: z.string().max(DIRECTORY_LIMITS.maxDnLength),
  role: z.enum(DIRECTORY_ROLES),
});
const settingsBody = z.object({
  enabled: z.boolean(),
  preset: z.enum(DIRECTORY_PRESETS),
  servers: z.array(z.string().max(300)).max(20),
  tlsTrust: z.enum(TLS_TRUSTS),
  caCertificate: z
    .string()
    .max(DIRECTORY_LIMITS.maxCaPemLength + 1)
    .default(""),
  bindDn: z.string().max(DIRECTORY_LIMITS.maxDnLength),
  /** Write-only. Missing keeps the stored password. */
  bindPassword: z.string().min(1).max(DIRECTORY_LIMITS.bindPasswordMax).optional(),
  userBaseDn: z.string().max(DIRECTORY_LIMITS.maxDnLength),
  userFilter: z.string().max(DIRECTORY_LIMITS.maxFilterLength + 100),
  emailAttribute: z.string().max(80),
  nameAttribute: z.string().max(80),
  uniqueIdAttribute: z.string().max(80),
  groupMode: z.enum(GROUP_MODES),
  groupFilter: z
    .string()
    .max(DIRECTORY_LIMITS.maxFilterLength + 100)
    .default(""),
  groupRoles: z.array(groupRole).max(DIRECTORY_LIMITS.maxGroupRoles + 10),
  emailVerified: z.boolean(),
  connectTimeoutSeconds: z.number(),
  operationTimeoutSeconds: z.number(),
  sizeLimit: z.number(),
});

/** What is stored apart from the password; compared to decide whether a save needs a new test. */
const CONNECTION_FIELDS = [
  "tlsTrust",
  "caCertificate",
  "bindDn",
  "userBaseDn",
  "userFilter",
  "emailAttribute",
  "nameAttribute",
  "uniqueIdAttribute",
  "groupMode",
  "groupFilter",
] as const;

const transportOf = (url: string) => (url.startsWith("ldaps://") ? "ldaps" : "starttls");

function presentServer(server: ServerRow, trust: DirectoryConfigRow["tlsTrust"]) {
  return {
    url: server.url,
    transport: transportOf(server.url),
    certificate:
      trust === "pin"
        ? {
            status: server.certStatus,
            pin: server.pin
              ? {
                  fingerprint: server.pin.fingerprint,
                  subject: server.pin.subject,
                  issuer: server.pin.issuer,
                  validFrom: server.pin.validFrom,
                  validTo: server.pin.validTo,
                  confirmedAt: server.pin.confirmedAt,
                }
              : null,
            candidate: server.candidate
              ? {
                  fingerprint: server.candidate.fingerprint,
                  subject: server.candidate.subject,
                  issuer: server.candidate.issuer,
                  validFrom: server.candidate.validFrom,
                  validTo: server.candidate.validTo,
                  trusted: server.candidate.trusted,
                  seenAt: server.candidate.seenAt,
                }
              : null,
          }
        : null,
  };
}

async function present(row: DirectoryConfigRow | null, organizationId: string) {
  const [accounts] = await db
    .select({ n: count() })
    .from(schema.directoryIdentity)
    .where(eq(schema.directoryIdentity.organizationId, organizationId));
  if (!row)
    return {
      configured: false,
      settings: null,
      servers: [],
      testedAt: null,
      bindBlockedUntil: null,
      accounts: accounts?.n ?? 0,
    };
  return {
    configured: true,
    settings: {
      enabled: row.enabled,
      preset: row.preset,
      servers: row.servers.map((s) => s.url),
      tlsTrust: row.tlsTrust,
      caCertificate: row.caCertificate,
      bindDn: row.bindDn,
      bindPasswordSet: row.bindSecretId !== null,
      userBaseDn: row.userBaseDn,
      userFilter: row.userFilter,
      emailAttribute: row.emailAttribute,
      nameAttribute: row.nameAttribute,
      uniqueIdAttribute: row.uniqueIdAttribute,
      groupMode: row.groupMode,
      groupFilter: row.groupFilter,
      groupRoles: row.groupRoles,
      emailVerified: row.emailVerified,
      connectTimeoutSeconds: row.connectTimeoutSeconds,
      operationTimeoutSeconds: row.operationTimeoutSeconds,
      sizeLimit: row.sizeLimit,
    },
    servers: row.servers.map((s) => presentServer(s, row.tlsTrust)),
    testedAt: iso(row.testedAt),
    bindBlockedUntil:
      row.bindBlockedUntil && row.bindBlockedUntil > new Date() ? iso(row.bindBlockedUntil) : null,
    accounts: accounts?.n ?? 0,
  };
}

/** Keeps the pin of every server that stays in the list and the trust that stays `pin`; everything else starts unconfirmed. */
function mergeServers(
  urls: string[],
  previous: DirectoryConfigRow | null,
  trust: DirectoryConfigRow["tlsTrust"],
): ServerRow[] {
  return urls.map((url) => {
    const old =
      trust === "pin" && previous?.tlsTrust === "pin"
        ? previous.servers.find((s) => s.url === url)
        : undefined;
    if (old) return old;
    return { url, pin: null, candidate: null, certStatus: trust === "pin" ? "pending" : "confirmed" };
  });
}

const testBody = z.object({ username: z.string().max(200).optional() });
const confirmBody = z.object({ url: z.string().max(300), fingerprint: z.string().max(100) });
const scanBody = z.object({ url: z.string().max(300).optional() });
const personBody = z.object({ userId: z.string().max(60), username: z.string().max(200) });

async function linkTarget(organizationId: string, userId: string) {
  const [member] = await db
    .select({
      role: schema.membership.role,
      email: schema.user.email,
      name: schema.user.name,
    })
    .from(schema.membership)
    .innerJoin(schema.user, eq(schema.user.id, schema.membership.userId))
    .where(and(eq(schema.membership.organizationId, organizationId), eq(schema.membership.userId, userId)))
    .limit(1);
  if (!member) throw notFound("Member");
  // Owners are local accounts and stay so: a directory outage or a changed group must never lock the installation out.
  if (!mayLinkRole(member.role)) {
    throw new ProblemError(409, "owner", "Owners are local accounts and cannot be linked to the directory");
  }
  const [linked] = await db
    .select({ id: schema.directoryIdentity.id })
    .from(schema.directoryIdentity)
    .where(eq(schema.directoryIdentity.userId, userId))
    .limit(1);
  if (linked) throw new ProblemError(409, "already-linked", "This account already comes from the directory");
  return member;
}

type LookupAnswer = { outcome: string; problem?: string; user?: DirectoryUser };

async function lookupPerson(
  organizationId: string,
  actorId: string,
  username: string,
): Promise<LookupAnswer> {
  const name = checkUsername(username);
  if (!name) throw invalid([{ field: "username", code: "username_invalid" }]);
  const config = await directoryOf(organizationId);
  if (!config || config.bindSecretId === null) {
    throw new ProblemError(409, "not-configured", "The directory is not configured");
  }
  await rateLimit(`directory-lookup:${organizationId}`, 20);
  return (await askDirectory({
    organizationId,
    kind: "lookup",
    params: { username: name },
    requestedBy: actorId,
  })) as unknown as LookupAnswer;
}

export const directoryRoutes = new Hono<AppEnv>()
  .use("*", async (c, next) => {
    requireRole(c.get("actor"), "owner");
    await next();
  })
  .get("/", async (c) => {
    const actor = c.get("actor");
    return c.json(await present(await directoryOf(actor.organizationId), actor.organizationId));
  })
  .put("/", async (c) => {
    const actor = c.get("actor");
    const input = settingsBody.parse(await c.req.json());
    const settings: DirectorySettings = {
      enabled: input.enabled,
      preset: input.preset,
      servers: input.servers.map((s) => s.trim()),
      tlsTrust: input.tlsTrust,
      caCertificate: input.caCertificate.trim(),
      bindDn: input.bindDn.trim(),
      userBaseDn: input.userBaseDn.trim(),
      userFilter: input.userFilter.trim(),
      emailAttribute: input.emailAttribute.trim(),
      nameAttribute: input.nameAttribute.trim(),
      uniqueIdAttribute: input.uniqueIdAttribute.trim(),
      groupMode: input.groupMode,
      groupFilter: input.groupFilter.trim(),
      groupRoles: input.groupRoles.map((g) => ({ dn: g.dn.trim(), role: g.role })),
      emailVerified: input.emailVerified,
      connectTimeoutSeconds: input.connectTimeoutSeconds,
      operationTimeoutSeconds: input.operationTimeoutSeconds,
      sizeLimit: input.sizeLimit,
    };
    const { problems, servers: urls } = checkDirectorySettings(settings, directoryHostPolicy);
    const previous = await directoryOf(actor.organizationId);
    if (!previous && !input.bindPassword) problems.push({ field: "bindPassword", code: "password_required" });
    if (problems.length > 0) throw invalid(problems);
    requireRecentSignIn(actor);

    const connectionChanged =
      !previous ||
      input.bindPassword !== undefined ||
      CONNECTION_FIELDS.some((field) => previous[field] !== settings[field]) ||
      previous.servers.map((s) => s.url).join("\n") !== urls.join("\n");

    // Settings that change how the directory is reached or read start untested; untested settings never go live.
    const testedAt = connectionChanged ? null : previous.testedAt;
    let enabled = settings.enabled;
    let switchedOff = false;
    if (enabled && testedAt === null) {
      if (connectionChanged && previous?.enabled) {
        enabled = false;
        switchedOff = true;
      } else if (!(previous?.enabled && !connectionChanged)) {
        // Staying on is fine (a newly pinned certificate clears the test but does not switch anything off);
        // switching on is not.
        throw new ProblemError(
          409,
          "not-tested",
          "Test the connection with a person before switching the sign-in on",
        );
      }
    }

    let secretId = previous?.bindSecretId ?? null;
    let oldSecretId: string | null = null;
    if (input.bindPassword !== undefined) {
      oldSecretId = secretId;
      secretId = newId("sec");
    }
    const servers = mergeServers(urls, previous, settings.tlsTrust);
    const values = {
      organizationId: actor.organizationId,
      enabled,
      preset: settings.preset,
      servers,
      tlsTrust: settings.tlsTrust,
      caCertificate: settings.tlsTrust === "ca" ? settings.caCertificate : "",
      bindDn: settings.bindDn,
      bindSecretId: secretId,
      userBaseDn: settings.userBaseDn,
      userFilter: settings.userFilter,
      emailAttribute: settings.emailAttribute,
      nameAttribute: settings.nameAttribute,
      uniqueIdAttribute: settings.uniqueIdAttribute,
      groupMode: settings.groupMode,
      groupFilter: settings.groupMode === "search" ? settings.groupFilter : "",
      groupRoles: settings.groupRoles,
      emailVerified: settings.emailVerified,
      connectTimeoutSeconds: settings.connectTimeoutSeconds,
      operationTimeoutSeconds: settings.operationTimeoutSeconds,
      sizeLimit: settings.sizeLimit,
      testedAt,
      // A new password may be right: let the worker try it.
      bindBlockedUntil: input.bindPassword !== undefined ? null : (previous?.bindBlockedUntil ?? null),
      updatedBy: actor.userId,
      updatedAt: new Date(),
    };
    await db.transaction(async (tx) => {
      if (input.bindPassword !== undefined && secretId) {
        await tx.insert(schema.secret).values({
          id: secretId,
          organizationId: actor.organizationId,
          purpose: "ldap-bind-password",
          sealed: seal(
            input.bindPassword,
            { organizationId: actor.organizationId, recordId: secretId, purpose: "ldap-bind-password" },
            vaultPublicKey,
          ),
          vaultKeyId: vaultPublicKey.id,
          createdBy: actor.userId,
        });
      }
      if (previous) {
        await tx
          .update(schema.ldapConfig)
          .set(values)
          .where(eq(schema.ldapConfig.organizationId, actor.organizationId));
      } else {
        await tx.insert(schema.ldapConfig).values(values);
      }
      if (oldSecretId) await tx.delete(schema.secret).where(eq(schema.secret.id, oldSecretId));
    });

    const changed = previous
      ? (
          [
            ...CONNECTION_FIELDS,
            "emailVerified",
            "connectTimeoutSeconds",
            "operationTimeoutSeconds",
            "sizeLimit",
            "preset",
          ] as const
        ).filter((field) => previous[field] !== values[field as keyof typeof values])
      : [];
    const extra: string[] = [];
    if (!previous || previous.servers.map((s) => s.url).join("\n") !== urls.join("\n")) extra.push("servers");
    if (!previous || JSON.stringify(previous.groupRoles) !== JSON.stringify(settings.groupRoles))
      extra.push("groupRoles");
    if (input.bindPassword !== undefined) extra.push("bindPassword");
    if (!previous || previous.enabled !== enabled) extra.push("enabled");
    await audit(
      actor,
      previous ? "directory.settings_changed" : "directory.settings_created",
      { type: "ldap_config", id: actor.organizationId },
      {
        changed: [...changed, ...extra],
        enabled,
        ...(switchedOff ? { switchedOff: true } : {}),
        tlsTrust: settings.tlsTrust,
        servers: urls,
        bindDn: settings.bindDn,
        groupRoles: settings.groupRoles,
      },
    );
    const row = await directoryOf(actor.organizationId);
    return c.json({ ...(await present(row, actor.organizationId)), switchedOff });
  })
  /** The connection test: every server, the search base, and (with a user name) what the directory says about that person. */
  .post("/test", async (c) => {
    const actor = c.get("actor");
    const input = testBody.parse(await c.req.json().catch(() => ({})));
    const username = input.username?.trim() ? checkUsername(input.username) : null;
    if (input.username?.trim() && !username) throw invalid([{ field: "username", code: "username_invalid" }]);
    const config = await directoryOf(actor.organizationId);
    if (!config || config.bindSecretId === null) {
      throw new ProblemError(409, "not-configured", "Save the settings first");
    }
    await rateLimit(`directory-test:${actor.organizationId}`, 10);
    const result = await askDirectory({
      organizationId: actor.organizationId,
      kind: "test",
      params: username ? { username } : {},
      requestedBy: actor.userId,
    });
    await audit(
      actor,
      "directory.test_run",
      { type: "ldap_config", id: actor.organizationId },
      { ok: result.ok === true, problem: result.problem ?? null, username },
    );
    const fresh = await directoryOf(actor.organizationId);
    return c.json({ result, testedAt: iso(fresh?.testedAt ?? null) });
  })
  /** Reads the certificate each server presents, for pinning. Nothing is sent to the directory. */
  .post("/certificates/scan", async (c) => {
    const actor = c.get("actor");
    const input = scanBody.parse(await c.req.json().catch(() => ({})));
    const config = await directoryOf(actor.organizationId);
    if (!config) throw new ProblemError(409, "not-configured", "Save the settings first");
    if (input.url !== undefined && !config.servers.some((s) => s.url === input.url)) throw notFound("Server");
    await rateLimit(`directory-cert:${actor.organizationId}`, 30, 60 * 60_000);
    await askDirectory({
      organizationId: actor.organizationId,
      kind: "certificate",
      params: input.url ? { url: input.url } : {},
      requestedBy: actor.userId,
    });
    await audit(
      actor,
      "directory.certificate_scan_requested",
      { type: "ldap_config", id: actor.organizationId },
      { url: input.url ?? null },
    );
    return c.json(await present(await directoryOf(actor.organizationId), actor.organizationId));
  })
  .post("/certificates/confirm", async (c) => {
    const actor = c.get("actor");
    const input = confirmBody.parse(await c.req.json());
    const fingerprint = normalizeFingerprint(input.fingerprint);
    if (!fingerprint) throw invalid([{ field: "fingerprint", code: "fingerprint_invalid" }]);
    requireRecentSignIn(actor);
    const config = await directoryOf(actor.organizationId);
    if (config?.tlsTrust !== "pin") {
      throw new ProblemError(409, "not-pinning", "Certificate pinning is not switched on");
    }
    const server = config.servers.find((s) => s.url === input.url);
    if (!server) throw notFound("Server");
    if (!server.candidate) {
      throw new ProblemError(409, "no-certificate", "There is no certificate waiting for confirmation");
    }
    // The owner confirms the fingerprint they compared, not "whatever is pending now".
    if (server.candidate.fingerprint !== fingerprint) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The certificate has changed since it was shown; compare the new fingerprint",
      );
    }
    const now = new Date().toISOString();
    const candidate = server.candidate;
    const servers = config.servers.map((s) =>
      s.url === server.url
        ? {
            url: s.url,
            certStatus: "confirmed" as const,
            candidate: null,
            pin: {
              fingerprint: candidate.fingerprint,
              subject: candidate.subject,
              issuer: candidate.issuer,
              validFrom: candidate.validFrom,
              validTo: candidate.validTo,
              confirmedAt: now,
              confirmedBy: actor.userId,
            },
          }
        : s,
    );
    // The worker may have seen yet another certificate meanwhile: only the one that was shown is pinned.
    const updated = await db
      .update(schema.ldapConfig)
      .set({ servers, testedAt: null, updatedAt: new Date() })
      .where(
        and(
          eq(schema.ldapConfig.organizationId, actor.organizationId),
          // JavaScript dates have milliseconds, the column may have microseconds.
          sql`date_trunc('milliseconds', ${schema.ldapConfig.updatedAt}) = date_trunc('milliseconds', ${config.updatedAt}::timestamptz)`,
        ),
      )
      .returning({ id: schema.ldapConfig.organizationId });
    if (updated.length === 0) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The settings changed while you were looking; compare the fingerprint again",
      );
    }
    await audit(
      actor,
      "directory.certificate_confirmed",
      { type: "ldap_config", id: actor.organizationId },
      {
        server: server.url,
        fingerprint,
        subject: candidate.subject,
        issuer: candidate.issuer,
        trusted: candidate.trusted,
        previous: server.pin?.fingerprint ?? null,
      },
    );
    return c.json(await present(await directoryOf(actor.organizationId), actor.organizationId));
  })
  /** What the directory says about a person, and whether an existing local account may be linked to them. */
  .post("/lookup", async (c) => {
    const actor = c.get("actor");
    const input = personBody.parse(await c.req.json());
    const member = await linkTarget(actor.organizationId, input.userId);
    const answer = await lookupPerson(actor.organizationId, actor.userId, input.username);
    const person = answer.user;
    const emailMatches = Boolean(person?.email && person.email === member.email.toLowerCase());
    let linkedTo: string | null = null;
    if (person) {
      const [taken] = await db
        .select({ userId: schema.directoryIdentity.userId })
        .from(schema.directoryIdentity)
        .where(
          and(
            eq(schema.directoryIdentity.organizationId, actor.organizationId),
            eq(schema.directoryIdentity.uniqueId, person.uniqueId),
          ),
        )
        .limit(1);
      linkedTo = taken?.userId ?? null;
    }
    return c.json({
      outcome: answer.outcome,
      problem: answer.problem ?? null,
      person: person
        ? { dn: person.dn, email: person.email, name: person.name, groups: person.groups, role: person.role }
        : null,
      emailMatches,
      alreadyLinked: linkedTo !== null,
      account: { email: member.email, name: member.name, role: member.role },
    });
  })
  /**
   * Links an existing local account to its directory entry (ADR 0020). The only way a local
   * account becomes a directory account: nothing links by mail address on its own. The account
   * loses its local password, ends all its sessions, and takes its role from its groups.
   */
  .post("/link", async (c) => {
    const actor = c.get("actor");
    const input = personBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    const member = await linkTarget(actor.organizationId, input.userId);
    const answer = await lookupPerson(actor.organizationId, actor.userId, input.username);
    const person = answer.user;
    if (answer.outcome !== "ok" || !person?.role) {
      throw new ProblemError(409, "not-allowed", "This person is not in a group that may sign in");
    }
    if (!person.email || person.email !== member.email.toLowerCase()) {
      throw new ProblemError(
        409,
        "email-mismatch",
        "The mail address in the directory is not the account's address",
      );
    }
    const identityId = newId("dri");
    try {
      await db.transaction(async (tx) => {
        await tx.insert(schema.directoryIdentity).values({
          id: identityId,
          organizationId: actor.organizationId,
          userId: input.userId,
          uniqueId: person.uniqueId,
          dn: person.dn,
          loginName: checkUsername(input.username) ?? input.username.trim(),
          linkedBy: actor.userId,
        });
        // No local password any more; the second factor stays.
        await tx
          .delete(schema.account)
          .where(
            and(eq(schema.account.userId, input.userId), inArray(schema.account.providerId, ["credential"])),
          );
        await applyDirectoryRole(tx, {
          organizationId: actor.organizationId,
          userId: input.userId,
          role: person.role,
        });
        // They sign in again, through the directory.
        await tx.delete(schema.session).where(eq(schema.session.userId, input.userId));
      });
    } catch (error) {
      const code =
        (error as { code?: string; cause?: { code?: string } }).cause?.code ??
        (error as { code?: string }).code;
      if (code === "23505") {
        throw new ProblemError(409, "already-linked", "This person is already linked to an account");
      }
      throw error;
    }
    await audit(
      actor,
      "directory.account_linked",
      { type: "user", id: input.userId },
      {
        email: member.email,
        before: member.role,
        after: person.role,
        uniqueId: person.uniqueId,
        dn: person.dn,
      },
    );
    return c.json({ ok: true, role: person.role });
  });
