import { createOTP } from "@better-auth/utils/otp";
import { newId } from "@garnetops/core";
import {
  describeUserAgent,
  isTimeZone,
  mayRemovePasskey,
  PREFERRED_LANGUAGES,
} from "@garnetops/core/account";
import { hashPassword, verifyPassword } from "@garnetops/core/password";
import { schema } from "@garnetops/db";
import { generateRandomString, symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { and, asc, desc, eq, gt, ne, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { auth } from "../auth.ts";
import { db } from "../db.ts";
import { env } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { newBackupCodes, openBackupCodes, sealBackupCodes } from "../lib/backup-codes.ts";
import type { Actor, AppEnv } from "../lib/context.ts";
import { isDirectoryAccount } from "../lib/directory-accounts.ts";
import { cleanPasskeyName, relyingParty } from "../lib/passkey-policy.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

/**
 * The account page's API (ADR 0017): every signed-in user manages their own profile, password,
 * authenticator app, backup codes, passkeys and sessions here. Nothing in this file touches
 * another user's account. Factor changes ask for a recent sign-in (ADR 0009), everything
 * security-relevant is audit-logged, and the second factor can be replaced but never removed.
 */

/** How long a new authenticator secret waits for its first code before it is dropped. */
export const TOTP_ENROLMENT_MINUTES = 10;
const MIN_PASSWORD = 12;
const MAX_PASSWORD = 256;

const u = schema.user;
const pk = schema.passkey;
const sess = schema.session;
const tf = schema.twoFactor;

/** better-auth's key material, for the secrets it stores (TOTP secrets and backup codes). */
async function secretConfig() {
  return (await auth.$context).secretConfig;
}

const pendingIdentifier = (userId: string) => `totp-reenrol:${userId}`;

const profileBody = z.object({ name: z.string().trim().min(1).max(100) });
const preferencesBody = z.object({
  locale: z.enum(PREFERRED_LANGUAGES).nullable(),
  timeZone: z
    .string()
    .nullable()
    .refine((zone) => zone === null || isTimeZone(zone), "Not a time zone"),
});
const passwordBody = z.object({
  currentPassword: z.string().min(1).max(MAX_PASSWORD),
  newPassword: z.string().min(MIN_PASSWORD).max(MAX_PASSWORD),
  revokeOtherSessions: z.boolean().default(true),
});
const passwordOnlyBody = z.object({ password: z.string().min(1).max(MAX_PASSWORD) });
const codeBody = z.object({
  code: z
    .string()
    .trim()
    .regex(/^\d{6}$/),
});
const renameBody = z.object({ name: z.string().max(200) });

/** Checks the signed-in user's own password. Wrong or missing is the same answer. */
async function checkPassword(actor: Actor, password: string): Promise<boolean> {
  const [account] = await db
    .select({ hash: schema.account.password })
    .from(schema.account)
    .where(and(eq(schema.account.userId, actor.userId), eq(schema.account.providerId, "credential")))
    .limit(1);
  return account?.hash ? verifyPassword(account.hash, password) : false;
}

async function totpRow(userId: string) {
  const [row] = await db.select().from(tf).where(eq(tf.userId, userId)).limit(1);
  return row ?? null;
}

export const accountRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const [user] = await db
      .select({
        name: u.name,
        email: u.email,
        locale: u.locale,
        timeZone: u.timeZone,
        createdAt: u.createdAt,
        twoFactorEnabled: u.twoFactorEnabled,
      })
      .from(u)
      .where(eq(u.id, actor.userId))
      .limit(1);
    if (!user) throw notFound("Account");
    const [totp, passkeys] = await Promise.all([
      totpRow(actor.userId),
      db
        .select({
          id: pk.id,
          name: pk.name,
          createdAt: pk.createdAt,
          lastUsedAt: pk.lastUsedAt,
          deviceType: pk.deviceType,
          backedUp: pk.backedUp,
        })
        .from(pk)
        .where(eq(pk.userId, actor.userId))
        .orderBy(asc(pk.createdAt), asc(pk.id)),
    ]);
    const [directory] = await db
      .select({ loginName: schema.directoryIdentity.loginName })
      .from(schema.directoryIdentity)
      .where(eq(schema.directoryIdentity.userId, actor.userId))
      .limit(1);
    const enrolled = Boolean(user.twoFactorEnabled && totp && totp.verified !== false);
    const codes = totp ? await openBackupCodes(totp.backupCodes, await secretConfig()) : null;
    const rp = relyingParty(env.PUBLIC_URL);
    return c.json({
      profile: {
        name: user.name,
        email: user.email,
        locale: user.locale,
        timeZone: user.timeZone,
        createdAt: user.createdAt,
        /** `directory`: signs in with the directory; no local password, and the role follows the groups (ADR 0020). */
        source: directory ? "directory" : "local",
        /** The name used at the last directory sign-in; the confirmation dialog offers it again. */
        loginName: directory?.loginName ?? null,
      },
      secondFactor: {
        totp: { enrolled, backupCodesRemaining: Array.isArray(codes) ? codes.length : 0 },
        passkeys,
        passkeysAvailable: rp.usable,
        relyingParty: rp.rpID,
      },
    });
  })
  /** The display name. The address is fixed: changing it is a different, later feature. */
  .patch("/profile", async (c) => {
    const actor = c.get("actor");
    const { name } = profileBody.parse(await c.req.json());
    // The directory is the source of the name of its accounts and writes it at every sign-in.
    if (await isDirectoryAccount(actor.userId)) {
      throw new ProblemError(
        409,
        "managed-by-directory",
        "The name of this account comes from your directory",
      );
    }
    if (name !== actor.name) {
      await db.update(u).set({ name, updatedAt: new Date() }).where(eq(u.id, actor.userId));
      await audit(
        actor,
        "account.profile_changed",
        { type: "user", id: actor.userId },
        { before: actor.name, after: name },
      );
    }
    return c.body(null, 204);
  })
  /** Language and time zone; null follows the browser. Not security-relevant, so not audited. */
  .put("/preferences", async (c) => {
    const actor = c.get("actor");
    const { locale, timeZone } = preferencesBody.parse(await c.req.json());
    await db.update(u).set({ locale, timeZone, updatedAt: new Date() }).where(eq(u.id, actor.userId));
    return c.body(null, 204);
  })
  /**
   * Changes the password. A recent sign-in and the current password are required (so a stolen session
   * alone is not enough),
   * the new one is hashed with Argon2id, and other sessions end unless the user opts out.
   * better-auth's own endpoint is closed: with "sign out everywhere" it would create a new
   * session without a second factor and so reset the step-up clock.
   */
  .post("/password", async (c) => {
    const actor = c.get("actor");
    requireRecentSignIn(actor);
    if (await isDirectoryAccount(actor.userId)) {
      throw new ProblemError(
        409,
        "managed-by-directory",
        "The password of this account is managed by your directory",
      );
    }
    const input = passwordBody.parse(await c.req.json());
    await rateLimit(`account:password:${actor.userId}`, 5);
    if (!(await checkPassword(actor, input.currentPassword))) {
      await audit(
        actor,
        "account.password_changed",
        { type: "user", id: actor.userId },
        { outcome: "failure" },
      );
      throw new ProblemError(400, "invalid-password", "The current password is not correct");
    }
    if (input.newPassword === input.currentPassword) {
      throw new ProblemError(422, "same-password", "The new password must differ from the current one");
    }
    const hash = await hashPassword(input.newPassword);
    let revoked = 0;
    await db.transaction(async (tx) => {
      await tx
        .update(schema.account)
        .set({ password: hash, updatedAt: new Date() })
        .where(and(eq(schema.account.userId, actor.userId), eq(schema.account.providerId, "credential")));
      if (input.revokeOtherSessions) {
        const gone = await tx
          .delete(sess)
          .where(and(eq(sess.userId, actor.userId), ne(sess.id, actor.sessionId)))
          .returning({ id: sess.id });
        revoked = gone.length;
      }
    });
    await audit(
      actor,
      "account.password_changed",
      { type: "user", id: actor.userId },
      { outcome: "success", revokedSessions: revoked },
    );
    return c.json({ revokedSessions: revoked });
  })
  /**
   * Starts replacing the authenticator app: a recent sign-in and the password are needed, and the
   * new secret waits in the verification table, encrypted. The old secret stays in force until
   * the first code of the new one is confirmed, so a failed or abandoned attempt locks nobody out.
   */
  .post("/totp/begin", async (c) => {
    const actor = c.get("actor");
    requireRecentSignIn(actor);
    // A directory account has no local password; the sign-in from the last ten minutes (directory password and code) is the proof.
    const managed = await isDirectoryAccount(actor.userId);
    const { password } = managed ? { password: undefined } : passwordOnlyBody.parse(await c.req.json());
    await rateLimit(`account:totp-begin:${actor.userId}`, 5);
    if (!managed && !(await checkPassword(actor, password ?? ""))) {
      await audit(
        actor,
        "account.totp_replace_started",
        { type: "user", id: actor.userId },
        { outcome: "failure" },
      );
      throw new ProblemError(400, "invalid-password", "The password is not correct");
    }
    if (!(await totpRow(actor.userId))) {
      throw new ProblemError(409, "no-authenticator", "There is no authenticator app to replace");
    }
    const secret = generateRandomString(32);
    const sealed = await symmetricEncrypt({ key: await secretConfig(), data: secret });
    await db.transaction(async (tx) => {
      await tx
        .delete(schema.verification)
        .where(eq(schema.verification.identifier, pendingIdentifier(actor.userId)));
      await tx.insert(schema.verification).values({
        id: newId("ver"),
        identifier: pendingIdentifier(actor.userId),
        value: sealed,
        expiresAt: new Date(Date.now() + TOTP_ENROLMENT_MINUTES * 60_000),
      });
    });
    await audit(
      actor,
      "account.totp_replace_started",
      { type: "user", id: actor.userId },
      { outcome: "success" },
    );
    const uri = createOTP(secret, { digits: 6, period: 30 }).url("GarnetOps", actor.email);
    c.header("cache-control", "no-store");
    return c.json({ uri, expiresInMinutes: TOTP_ENROLMENT_MINUTES });
  })
  /** Confirms the new authenticator with its first code; only now does the old secret go. */
  .post("/totp/confirm", async (c) => {
    const actor = c.get("actor");
    requireRecentSignIn(actor);
    const { code } = codeBody.parse(await c.req.json());
    await rateLimit(`account:totp-confirm:${actor.userId}`, 5);
    const [pending] = await db
      .select()
      .from(schema.verification)
      .where(
        and(
          eq(schema.verification.identifier, pendingIdentifier(actor.userId)),
          gt(schema.verification.expiresAt, new Date()),
        ),
      )
      .limit(1);
    if (!pending) throw new ProblemError(409, "no-pending-enrolment", "Start again to get a new QR code");
    const key = await secretConfig();
    const secret = await symmetricDecrypt({ key, data: pending.value });
    if (!(await createOTP(secret, { digits: 6, period: 30 }).verify(code))) {
      await audit(actor, "account.totp_replaced", { type: "user", id: actor.userId }, { outcome: "failure" });
      throw new ProblemError(400, "invalid-code", "The code is not correct");
    }
    const sealed = await symmetricEncrypt({ key, data: secret });
    await db.transaction(async (tx) => {
      await tx
        .update(tf)
        .set({ secret: sealed, verified: true, failedVerificationCount: 0, lockedUntil: null })
        .where(eq(tf.userId, actor.userId));
      await tx.delete(schema.verification).where(eq(schema.verification.id, pending.id));
    });
    await audit(actor, "account.totp_replaced", { type: "user", id: actor.userId }, { outcome: "success" });
    return c.body(null, 204);
  })
  /** New backup codes replace the old ones and are shown once, in this answer only. */
  .post("/backup-codes", async (c) => {
    const actor = c.get("actor");
    requireRecentSignIn(actor);
    await rateLimit(`account:backup-codes:${actor.userId}`, 5);
    if (!(await totpRow(actor.userId))) {
      throw new ProblemError(409, "no-authenticator", "Set up an authenticator app first");
    }
    const backupCodes = newBackupCodes();
    await db
      .update(tf)
      .set({ backupCodes: await sealBackupCodes(backupCodes, await secretConfig()) })
      .where(eq(tf.userId, actor.userId));
    await audit(
      actor,
      "account.backup_codes_regenerated",
      { type: "user", id: actor.userId },
      { codes: backupCodes.length },
    );
    c.header("cache-control", "no-store");
    return c.json({ codes: backupCodes });
  })
  .patch("/passkeys/:id", async (c) => {
    const actor = c.get("actor");
    const name = cleanPasskeyName(renameBody.parse(await c.req.json()).name);
    if (!name) throw new ProblemError(422, "invalid-name", "Give the passkey a name");
    const [before] = await db
      .select({ name: pk.name })
      .from(pk)
      .where(and(eq(pk.id, c.req.param("id")), eq(pk.userId, actor.userId)))
      .limit(1);
    if (!before) throw notFound("Passkey");
    await db
      .update(pk)
      .set({ name })
      .where(and(eq(pk.id, c.req.param("id")), eq(pk.userId, actor.userId)));
    await audit(
      actor,
      "account.passkey_renamed",
      { type: "passkey", id: c.req.param("id") },
      { before: before.name, after: name },
    );
    return c.body(null, 204);
  })
  /**
   * Removes a passkey. A recent sign-in is needed, and the last second factor can never go:
   * the account keeps its authenticator app or another passkey (AGENTS.md rule 1).
   */
  .delete("/passkeys/:id", async (c) => {
    const actor = c.get("actor");
    requireRecentSignIn(actor);
    const id = c.req.param("id");
    const removed = await db.transaction(async (tx) => {
      // One removal at a time per account, so two requests cannot each see a second factor that the other removes.
      await tx.execute(sql`select 1 from "user" where id = ${actor.userId} for update`);
      const passkeys = await tx
        .select({ id: pk.id, name: pk.name })
        .from(pk)
        .where(eq(pk.userId, actor.userId));
      const target = passkeys.find((p) => p.id === id);
      if (!target) return { kind: "missing" as const };
      const [user] = await tx
        .select({ twoFactorEnabled: u.twoFactorEnabled })
        .from(u)
        .where(eq(u.id, actor.userId))
        .limit(1);
      const [totp] = await tx
        .select({ verified: tf.verified })
        .from(tf)
        .where(eq(tf.userId, actor.userId))
        .limit(1);
      const totpEnrolled = Boolean(user?.twoFactorEnabled && totp && totp.verified !== false);
      if (!mayRemovePasskey({ totpEnrolled, passkeys: passkeys.length })) {
        return { kind: "last" as const, name: target.name };
      }
      await tx.delete(pk).where(and(eq(pk.id, id), eq(pk.userId, actor.userId)));
      return { kind: "removed" as const, name: target.name };
    });
    if (removed.kind === "missing") throw notFound("Passkey");
    if (removed.kind === "last") {
      await audit(
        actor,
        "account.passkey_removal_refused",
        { type: "passkey", id },
        { outcome: "failure", name: removed.name },
      );
      throw new ProblemError(409, "last-second-factor", "The last second factor cannot be removed");
    }
    await audit(actor, "account.passkey_removed", { type: "passkey", id }, { name: removed.name });
    return c.body(null, 204);
  })
  .get("/sessions", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select({
        id: sess.id,
        createdAt: sess.createdAt,
        lastActiveAt: sess.updatedAt,
        expiresAt: sess.expiresAt,
        ip: sess.ipAddress,
        userAgent: sess.userAgent,
      })
      .from(sess)
      .where(and(eq(sess.userId, actor.userId), gt(sess.expiresAt, new Date())))
      .orderBy(desc(sess.updatedAt), asc(sess.id));
    return c.json(
      rows.map(({ userAgent, ...row }) => ({
        ...row,
        current: row.id === actor.sessionId,
        device: describeUserAgent(userAgent),
      })),
    );
  })
  /** Ends the other sessions at once; the current one is ended by signing out. */
  .post("/sessions/revoke-others", async (c) => {
    const actor = c.get("actor");
    const gone = await db
      .delete(sess)
      .where(and(eq(sess.userId, actor.userId), ne(sess.id, actor.sessionId)))
      .returning({ id: sess.id });
    await audit(
      actor,
      "account.sessions_revoked",
      { type: "user", id: actor.userId },
      { sessions: gone.length },
    );
    return c.json({ revoked: gone.length });
  })
  .delete("/sessions/:id", async (c) => {
    const actor = c.get("actor");
    const id = c.req.param("id");
    if (id === actor.sessionId) {
      throw new ProblemError(400, "current-session", "Sign out to end this session");
    }
    const [gone] = await db
      .delete(sess)
      .where(and(eq(sess.id, id), eq(sess.userId, actor.userId)))
      .returning({ ip: sess.ipAddress, userAgent: sess.userAgent });
    if (!gone) throw notFound("Session");
    const device = describeUserAgent(gone.userAgent);
    await audit(
      actor,
      "account.session_revoked",
      { type: "session", id },
      { ip: gone.ip, browser: device.browser, os: device.os },
    );
    return c.body(null, 204);
  });
