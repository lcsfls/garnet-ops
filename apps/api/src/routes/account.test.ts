/**
 * The account API (ADR 0017) against a throw-away PostgreSQL database on the development server:
 * profile and preferences, password change, replacing the authenticator app, backup codes,
 * passkey list/rename/remove with the "never zero second factors" rule, sessions, and the
 * operator recovery. Sessions are replaced by a header-driven actor. Skipped without the
 * development PostgreSQL.
 */
import { createOTP } from "@better-auth/utils/otp";
import { hashPassword, verifyPassword } from "@garnetops/core/password";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { newBackupCodes, openBackupCodes, sealBackupCodes } from "../lib/backup-codes.ts";

const adminUrl = devDatabaseUrl();
const SECRET = "test-secret-with-at-least-32-characters-0000";

const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_account");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: {} };
});
vi.mock("../env.ts", () => ({
  env: { PUBLIC_URL: "https://garnetops.example.test/" },
  isProduction: false,
}));
// Only the key material of better-auth is needed; sessions are replaced by a header-driven actor below.
vi.mock("../auth.ts", () => ({ auth: { api: {}, $context: Promise.resolve({ secretConfig: SECRET }) } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_acc";
const PASSWORD = "old-password-long-enough";
const NEW_PASSWORD = "new-password-long-enough";

describe.skipIf(!adminUrl)("account API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  const code = (r: { json: Json | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();

  async function call(
    method: string,
    path: string,
    options: { user: string; session?: string; age?: number; body?: unknown },
  ) {
    const headers: Record<string, string> = {
      "x-user": options.user,
      "x-session": options.session ?? `${options.user}_s1`,
      "x-age": String(options.age ?? 0),
    };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(`/api/v1/account${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const text = await res.text();
    let json: Json | null = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // not JSON
    }
    return { status: res.status, json, text };
  }

  const STALE = 11 * 60;

  /** A member with a password, an authenticator app (when asked) and one session. */
  async function addUser(options: { totp?: boolean; passkeys?: number } = {}) {
    const id = `user_acc${++counter}`;
    await t.db.insert(schema.user).values({
      id,
      name: `Person ${counter}`,
      email: `person${counter}@example.test`,
      twoFactorEnabled: options.totp !== false,
    });
    await t.db.insert(schema.account).values({
      id: `acc_${id}`,
      accountId: id,
      providerId: "credential",
      userId: id,
      password: await hashPassword(PASSWORD),
    });
    await t.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role: "member" });
    await t.db.insert(schema.session).values({
      id: `${id}_s1`,
      token: `${id}_token1`,
      userId: id,
      expiresAt: new Date(Date.now() + 3600_000),
      userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
      ipAddress: "198.51.100.7",
    });
    let secret = "";
    let codes: string[] = [];
    if (options.totp !== false) {
      secret = `secret-of-${id}-0123456789abcdef`;
      codes = newBackupCodes();
      await t.db.insert(schema.twoFactor).values({
        id: `tf_${id}`,
        userId: id,
        secret: await symmetricEncrypt({ key: SECRET, data: secret }),
        backupCodes: await sealBackupCodes(codes, SECRET),
      });
    }
    const passkeyIds: string[] = [];
    for (let i = 0; i < (options.passkeys ?? 0); i++) {
      const pid = `pk_${id}_${i}`;
      passkeyIds.push(pid);
      await t.db.insert(schema.passkey).values({
        id: pid,
        name: `Key ${i}`,
        publicKey: "AAAA",
        userId: id,
        credentialID: `cred_${id}_${i}`,
        counter: 0,
        deviceType: "multiDevice",
        backedUp: true,
      });
    }
    return { id, secret, codes, passkeyIds };
  }

  const auditOf = async (action: string, userId?: string) =>
    (await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.action, action))).filter(
      (row) => !userId || row.actorUserId === userId || row.targetId === userId,
    );

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { accountRoutes } = await import("./account.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Org" });
    const v1 = new Hono().use("*", async (c, next) => {
      const userId = c.req.header("x-user") ?? "";
      const [user] = await t.db.select().from(schema.user).where(eq(schema.user.id, userId));
      c.set(
        "actor" as never,
        {
          userId,
          email: user?.email ?? "",
          name: user?.name ?? "",
          organizationId: ORG,
          role: "member",
          ip: "198.51.100.7",
          sessionId: c.req.header("x-session"),
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/account", accountRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  beforeEach(async () => {
    // The rate limits live in the database; start every test with a clean slate.
    await t.db.delete(schema.rateLimit);
  });

  describe("overview", () => {
    it("shows the profile and the second factors, never a secret", async () => {
      const u = await addUser({ passkeys: 2 });
      const r = await call("GET", "", { user: u.id });
      expect(r.status).toBe(200);
      expect(r.json?.profile).toMatchObject({
        email: expect.stringContaining("@example.test"),
        locale: null,
        timeZone: null,
      });
      expect(r.json?.secondFactor.totp).toEqual({ enrolled: true, backupCodesRemaining: 10 });
      expect(r.json?.secondFactor.passkeys.map((p: Json) => p.name)).toEqual(["Key 0", "Key 1"]);
      expect(r.json?.secondFactor.relyingParty).toBe("garnetops.example.test");
      expect(r.json?.secondFactor.passkeysAvailable).toBe(true);
      // Neither the secret, the backup codes, the public keys nor the credential ids leave the server.
      for (const secret of [u.secret, ...u.codes, "AAAA", `cred_${u.id}`])
        expect(r.text).not.toContain(secret);
    });

    it("lists only the passkeys of the signed-in user", async () => {
      const a = await addUser({ passkeys: 1 });
      const b = await addUser({ passkeys: 2 });
      const r = await call("GET", "", { user: a.id });
      expect(r.json?.secondFactor.passkeys).toHaveLength(1);
      expect((await call("GET", "", { user: b.id })).json?.secondFactor.passkeys).toHaveLength(2);
    });
  });

  describe("profile and preferences", () => {
    it("changes the display name, audits it, and refuses an empty one", async () => {
      const u = await addUser();
      expect((await call("PATCH", "/profile", { user: u.id, body: { name: "  New Name  " } })).status).toBe(
        204,
      );
      const [row] = await t.db.select().from(schema.user).where(eq(schema.user.id, u.id));
      expect(row?.name).toBe("New Name");
      const entries = await auditOf("account.profile_changed", u.id);
      expect(entries).toHaveLength(1);
      expect(entries[0]?.data).toMatchObject({ after: "New Name" });
      expect((await call("PATCH", "/profile", { user: u.id, body: { name: "   " } })).status).toBe(422);
    });

    it("keeps the email address fixed: there is no way to send one", async () => {
      const u = await addUser();
      const before = (await t.db.select().from(schema.user).where(eq(schema.user.id, u.id)))[0]?.email;
      await call("PATCH", "/profile", { user: u.id, body: { name: "Same", email: "other@example.test" } });
      expect((await t.db.select().from(schema.user).where(eq(schema.user.id, u.id)))[0]?.email).toBe(before);
    });

    it("stores language and time zone, and null follows the browser", async () => {
      const u = await addUser();
      expect(
        (await call("PUT", "/preferences", { user: u.id, body: { locale: "de", timeZone: "Europe/Berlin" } }))
          .status,
      ).toBe(204);
      expect((await call("GET", "", { user: u.id })).json?.profile).toMatchObject({
        locale: "de",
        timeZone: "Europe/Berlin",
      });
      expect(
        (await call("PUT", "/preferences", { user: u.id, body: { locale: null, timeZone: null } })).status,
      ).toBe(204);
      expect((await call("GET", "", { user: u.id })).json?.profile).toMatchObject({
        locale: null,
        timeZone: null,
      });
    });

    it("refuses an unknown language or time zone", async () => {
      const u = await addUser();
      for (const body of [
        { locale: "fr", timeZone: null },
        { locale: null, timeZone: "Mars/Olympus" },
        { locale: null, timeZone: "x; drop table user" },
      ]) {
        expect((await call("PUT", "/preferences", { user: u.id, body })).status, JSON.stringify(body)).toBe(
          422,
        );
      }
    });
  });

  describe("password", () => {
    it("changes the password (Argon2id), keeps this session and ends the others by default", async () => {
      const u = await addUser();
      await t.db.insert(schema.session).values({
        id: `${u.id}_s2`,
        token: `${u.id}_token2`,
        userId: u.id,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      const r = await call("POST", "/password", {
        user: u.id,
        body: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
      });
      expect(r.status).toBe(200);
      expect(r.json?.revokedSessions).toBe(1);
      const [account] = await t.db.select().from(schema.account).where(eq(schema.account.userId, u.id));
      expect(account?.password).toMatch(/^\$argon2id\$/);
      expect(await verifyPassword(account?.password ?? "", NEW_PASSWORD)).toBe(true);
      expect(await verifyPassword(account?.password ?? "", PASSWORD)).toBe(false);
      const sessions = await t.db.select().from(schema.session).where(eq(schema.session.userId, u.id));
      expect(sessions.map((s) => s.id)).toEqual([`${u.id}_s1`]);
      const [entry] = await auditOf("account.password_changed", u.id);
      expect(entry?.data).toMatchObject({ outcome: "success", revokedSessions: 1 });
      // No password, old or new, in the audit log.
      expect(JSON.stringify(await t.db.select().from(schema.auditLog))).not.toContain(NEW_PASSWORD);
    });

    it("needs a recent sign-in as well as the current password", async () => {
      const u = await addUser();
      const stale = await call("POST", "/password", {
        user: u.id,
        age: STALE,
        body: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
      });
      expect(stale.status).toBe(403);
      expect(code(stale)).toBe("step-up-required");
      const [account] = await t.db.select().from(schema.account).where(eq(schema.account.userId, u.id));
      expect(await verifyPassword(account?.password ?? "", PASSWORD)).toBe(true);
    });

    it("keeps the other sessions when asked to", async () => {
      const u = await addUser();
      await t.db.insert(schema.session).values({
        id: `${u.id}_s2`,
        token: `${u.id}_token2`,
        userId: u.id,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      const r = await call("POST", "/password", {
        user: u.id,
        body: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD, revokeOtherSessions: false },
      });
      expect(r.json?.revokedSessions).toBe(0);
      expect(await t.db.select().from(schema.session).where(eq(schema.session.userId, u.id))).toHaveLength(2);
    });

    it("refuses a wrong current password, a short new one and an unchanged one", async () => {
      const u = await addUser();
      const wrong = await call("POST", "/password", {
        user: u.id,
        body: { currentPassword: "not-the-password-123", newPassword: NEW_PASSWORD },
      });
      expect(wrong.status).toBe(400);
      expect(code(wrong)).toBe("invalid-password");
      expect((await auditOf("account.password_changed", u.id))[0]?.data).toMatchObject({
        outcome: "failure",
      });
      expect(
        (
          await call("POST", "/password", {
            user: u.id,
            body: { currentPassword: PASSWORD, newPassword: "short" },
          })
        ).status,
      ).toBe(422);
      const same = await call("POST", "/password", {
        user: u.id,
        body: { currentPassword: PASSWORD, newPassword: PASSWORD },
      });
      expect(code(same)).toBe("same-password");
      const [account] = await t.db.select().from(schema.account).where(eq(schema.account.userId, u.id));
      expect(await verifyPassword(account?.password ?? "", PASSWORD)).toBe(true);
    });

    it("is rate-limited", async () => {
      const u = await addUser();
      const attempt = () =>
        call("POST", "/password", {
          user: u.id,
          body: { currentPassword: "wrong-password-123", newPassword: NEW_PASSWORD },
        });
      for (let i = 0; i < 5; i++) expect((await attempt()).status).toBe(400);
      expect((await attempt()).status).toBe(429);
    });
  });

  describe("replacing the authenticator app", () => {
    const pending = async (userId: string) =>
      (
        await t.db
          .select()
          .from(schema.verification)
          .where(eq(schema.verification.identifier, `totp-reenrol:${userId}`))
      )[0];

    it("needs a recent sign-in and the password", async () => {
      const u = await addUser();
      const stale = await call("POST", "/totp/begin", {
        user: u.id,
        age: STALE,
        body: { password: PASSWORD },
      });
      expect(stale.status).toBe(403);
      expect(code(stale)).toBe("step-up-required");
      const wrong = await call("POST", "/totp/begin", {
        user: u.id,
        body: { password: "not-the-password-123" },
      });
      expect(code(wrong)).toBe("invalid-password");
      expect(await pending(u.id)).toBeUndefined();
      expect(
        code(await call("POST", "/totp/confirm", { user: u.id, age: STALE, body: { code: "123456" } })),
      ).toBe("step-up-required");
    });

    it("keeps the old secret until the new one is confirmed, then replaces it", async () => {
      const u = await addUser();
      const begin = await call("POST", "/totp/begin", { user: u.id, body: { password: PASSWORD } });
      expect(begin.status).toBe(200);
      expect(begin.json?.uri).toMatch(/^otpauth:\/\/totp\//);
      const row = await pending(u.id);
      const next = await symmetricDecrypt({ key: SECRET, data: row?.value ?? "" });
      // The pending secret is stored sealed and is not the stored authenticator secret.
      expect(row?.value).not.toContain(next);
      const stored = () => t.db.select().from(schema.twoFactor).where(eq(schema.twoFactor.userId, u.id));
      const oldSealed = (await stored())[0]?.secret;

      // A wrong code (and the old authenticator's code) changes nothing.
      const oldCode = await createOTP(u.secret, { digits: 6, period: 30 }).totp();
      const newCode = await createOTP(next, { digits: 6, period: 30 }).totp();
      const bad = oldCode === newCode ? "000000" : oldCode;
      expect(code(await call("POST", "/totp/confirm", { user: u.id, body: { code: bad } }))).toBe(
        "invalid-code",
      );
      expect((await stored())[0]?.secret).toBe(oldSealed);
      expect(await pending(u.id)).toBeDefined();

      expect((await call("POST", "/totp/confirm", { user: u.id, body: { code: newCode } })).status).toBe(204);
      const after = (await stored())[0];
      expect(await symmetricDecrypt({ key: SECRET, data: after?.secret ?? "" })).toBe(next);
      expect(after?.failedVerificationCount).toBe(0);
      expect(await pending(u.id)).toBeUndefined();
      const entries = await auditOf("account.totp_replaced", u.id);
      expect(entries.map((e) => (e.data as Json).outcome).sort()).toEqual(["failure", "success"]);
    });

    it("drops an enrolment that waited too long and refuses a confirmation without one", async () => {
      const u = await addUser();
      expect(code(await call("POST", "/totp/confirm", { user: u.id, body: { code: "123456" } }))).toBe(
        "no-pending-enrolment",
      );
      await call("POST", "/totp/begin", { user: u.id, body: { password: PASSWORD } });
      await t.db
        .update(schema.verification)
        .set({ expiresAt: new Date(Date.now() - 1000) })
        .where(eq(schema.verification.identifier, `totp-reenrol:${u.id}`));
      expect(code(await call("POST", "/totp/confirm", { user: u.id, body: { code: "123456" } }))).toBe(
        "no-pending-enrolment",
      );
    });

    it("keeps one pending secret per user, the newest", async () => {
      const u = await addUser();
      await call("POST", "/totp/begin", { user: u.id, body: { password: PASSWORD } });
      await call("POST", "/totp/begin", { user: u.id, body: { password: PASSWORD } });
      expect(
        await t.db
          .select()
          .from(schema.verification)
          .where(eq(schema.verification.identifier, `totp-reenrol:${u.id}`)),
      ).toHaveLength(1);
    });

    it("only touches the signed-in user's own authenticator", async () => {
      const a = await addUser();
      const b = await addUser();
      const before = (await t.db.select().from(schema.twoFactor).where(eq(schema.twoFactor.userId, b.id)))[0]
        ?.secret;
      await call("POST", "/totp/begin", { user: a.id, body: { password: PASSWORD } });
      const row = await pending(a.id);
      const next = await symmetricDecrypt({ key: SECRET, data: row?.value ?? "" });
      await call("POST", "/totp/confirm", {
        user: a.id,
        body: { code: await createOTP(next, { digits: 6, period: 30 }).totp() },
      });
      expect(
        (await t.db.select().from(schema.twoFactor).where(eq(schema.twoFactor.userId, b.id)))[0]?.secret,
      ).toBe(before);
    });
  });

  describe("backup codes", () => {
    it("needs a recent sign-in", async () => {
      const u = await addUser();
      expect(code(await call("POST", "/backup-codes", { user: u.id, age: STALE }))).toBe("step-up-required");
    });

    it("replaces the codes, shows them once and never audits them", async () => {
      const u = await addUser();
      const r = await call("POST", "/backup-codes", { user: u.id });
      expect(r.status).toBe(200);
      const codes: string[] = r.json?.codes ?? [];
      expect(codes).toHaveLength(10);
      expect(codes.some((c) => u.codes.includes(c))).toBe(false);
      const [row] = await t.db.select().from(schema.twoFactor).where(eq(schema.twoFactor.userId, u.id));
      expect(row?.backupCodes).not.toContain(codes[0]);
      expect(await openBackupCodes(row?.backupCodes ?? "", SECRET)).toEqual(codes);
      // The overview only counts them.
      expect((await call("GET", "", { user: u.id })).text).not.toContain(codes[0]);
      const dump = JSON.stringify(await t.db.select().from(schema.auditLog));
      for (const c of codes) expect(dump).not.toContain(c);
      expect((await auditOf("account.backup_codes_regenerated", u.id))[0]?.data).toEqual({ codes: 10 });
    });
  });

  describe("passkeys", () => {
    it("renames only the user's own passkeys", async () => {
      const a = await addUser({ passkeys: 1 });
      const b = await addUser({ passkeys: 1 });
      expect(
        (
          await call("PATCH", `/passkeys/${a.passkeyIds[0]}`, {
            user: a.id,
            body: { name: "  Work   laptop " },
          })
        ).status,
      ).toBe(204);
      const [row] = await t.db
        .select()
        .from(schema.passkey)
        .where(eq(schema.passkey.id, a.passkeyIds[0] ?? ""));
      expect(row?.name).toBe("Work laptop");
      expect((await auditOf("account.passkey_renamed", a.id))[0]?.data).toMatchObject({
        after: "Work laptop",
      });
      // Someone else's passkey looks like a missing one.
      expect(
        (await call("PATCH", `/passkeys/${b.passkeyIds[0]}`, { user: a.id, body: { name: "Mine now" } }))
          .status,
      ).toBe(404);
      const [other] = await t.db
        .select()
        .from(schema.passkey)
        .where(eq(schema.passkey.id, b.passkeyIds[0] ?? ""));
      expect(other?.name).toBe("Key 0");
      expect(
        (await call("PATCH", `/passkeys/${a.passkeyIds[0]}`, { user: a.id, body: { name: "  " } })).status,
      ).toBe(422);
    });

    it("removes a passkey after a recent sign-in while the authenticator app stays", async () => {
      const u = await addUser({ passkeys: 1 });
      const id = u.passkeyIds[0] ?? "";
      expect(code(await call("DELETE", `/passkeys/${id}`, { user: u.id, age: STALE }))).toBe(
        "step-up-required",
      );
      expect(await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, u.id))).toHaveLength(1);
      expect((await call("DELETE", `/passkeys/${id}`, { user: u.id })).status).toBe(204);
      expect(await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, u.id))).toHaveLength(0);
      expect((await auditOf("account.passkey_removed", u.id))[0]?.targetId).toBe(id);
    });

    it("never removes someone else's passkey", async () => {
      const a = await addUser({ passkeys: 1 });
      const b = await addUser({ passkeys: 1 });
      expect((await call("DELETE", `/passkeys/${b.passkeyIds[0]}`, { user: a.id })).status).toBe(404);
      expect(await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, b.id))).toHaveLength(1);
    });

    it("never leaves the account without a second factor", async () => {
      // No authenticator app: the passkeys are the second factor.
      const u = await addUser({ totp: false, passkeys: 2 });
      const [first, second] = u.passkeyIds;
      expect((await call("DELETE", `/passkeys/${first}`, { user: u.id })).status).toBe(204);
      const refused = await call("DELETE", `/passkeys/${second}`, { user: u.id });
      expect(refused.status).toBe(409);
      expect(code(refused)).toBe("last-second-factor");
      expect(await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, u.id))).toHaveLength(1);
      expect((await auditOf("account.passkey_removal_refused", u.id))[0]?.data).toMatchObject({
        outcome: "failure",
      });
    });

    it("cannot be raced into zero: two removals at once leave one", async () => {
      const u = await addUser({ totp: false, passkeys: 2 });
      const results = await Promise.all(
        u.passkeyIds.map((id) => call("DELETE", `/passkeys/${id}`, { user: u.id })),
      );
      expect(results.map((r) => r.status).sort()).toEqual([204, 409]);
      expect(await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, u.id))).toHaveLength(1);
    });

    it("an unverified authenticator app does not count as a factor", async () => {
      const u = await addUser({ passkeys: 1 });
      await t.db.update(schema.twoFactor).set({ verified: false }).where(eq(schema.twoFactor.userId, u.id));
      expect(code(await call("DELETE", `/passkeys/${u.passkeyIds[0]}`, { user: u.id }))).toBe(
        "last-second-factor",
      );
    });
  });

  describe("sessions", () => {
    it("lists the user's own active sessions with a device summary and no token", async () => {
      const a = await addUser();
      const b = await addUser();
      await t.db.insert(schema.session).values([
        {
          id: `${a.id}_s2`,
          token: `${a.id}_token2`,
          userId: a.id,
          expiresAt: new Date(Date.now() + 3600_000),
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
          ipAddress: "203.0.113.9",
        },
        // Expired: not active, not listed.
        { id: `${a.id}_s3`, token: `${a.id}_token3`, userId: a.id, expiresAt: new Date(Date.now() - 1000) },
      ]);
      const r = await call("GET", "/sessions", { user: a.id });
      expect(r.status).toBe(200);
      const list = r.json as unknown as Json[];
      expect(list.map((s) => s.id).sort()).toEqual([`${a.id}_s1`, `${a.id}_s2`]);
      expect(list.find((s) => s.current)?.id).toBe(`${a.id}_s1`);
      expect(list.find((s) => s.id === `${a.id}_s2`)?.device).toEqual({ browser: "Chrome", os: "Windows" });
      expect(r.text).not.toContain("token");
      expect(r.text).not.toContain(b.id);
    });

    it("ends one other session of the user, not the current one and not someone else's", async () => {
      const a = await addUser();
      const b = await addUser();
      await t.db.insert(schema.session).values({
        id: `${a.id}_s2`,
        token: `${a.id}_token2`,
        userId: a.id,
        expiresAt: new Date(Date.now() + 3600_000),
        ipAddress: "203.0.113.9",
      });
      expect(code(await call("DELETE", `/sessions/${a.id}_s1`, { user: a.id }))).toBe("current-session");
      expect((await call("DELETE", `/sessions/${b.id}_s1`, { user: a.id })).status).toBe(404);
      expect(
        await t.db
          .select()
          .from(schema.session)
          .where(eq(schema.session.id, `${b.id}_s1`)),
      ).toHaveLength(1);
      expect((await call("DELETE", `/sessions/${a.id}_s2`, { user: a.id })).status).toBe(204);
      expect(await t.db.select().from(schema.session).where(eq(schema.session.userId, a.id))).toHaveLength(1);
      expect((await auditOf("account.session_revoked", a.id))[0]?.data).toMatchObject({ ip: "203.0.113.9" });
    });

    it("ends every other session at once", async () => {
      const a = await addUser();
      const b = await addUser();
      await t.db.insert(schema.session).values(
        [2, 3].map((n) => ({
          id: `${a.id}_s${n}`,
          token: `${a.id}_token${n}`,
          userId: a.id,
          expiresAt: new Date(Date.now() + 3600_000),
        })),
      );
      const r = await call("POST", "/sessions/revoke-others", { user: a.id });
      expect(r.json).toEqual({ revoked: 2 });
      expect(
        (await t.db.select().from(schema.session).where(eq(schema.session.userId, a.id))).map((s) => s.id),
      ).toEqual([`${a.id}_s1`]);
      expect(await t.db.select().from(schema.session).where(eq(schema.session.userId, b.id))).toHaveLength(1);
      expect((await auditOf("account.sessions_revoked", a.id))[0]?.data).toEqual({ sessions: 2 });
    });
  });

  describe("recovery of a lost second factor (operator CLI)", () => {
    it("removes the authenticator app, the passkeys and the sessions, keeps the password, and audits it", async () => {
      const { inspectSecondFactor, resetSecondFactor } = await import("../lib/second-factor-reset.ts");
      const u = await addUser({ passkeys: 2 });
      const other = await addUser({ passkeys: 1 });
      await t.db.insert(schema.verification).values([
        {
          id: `ver_${u.id}_a`,
          identifier: `2fa-abc${u.id}`,
          value: u.id,
          expiresAt: new Date(Date.now() + 60_000),
        },
        {
          id: `ver_${u.id}_b`,
          identifier: `totp-reenrol:${u.id}`,
          value: "sealed",
          expiresAt: new Date(Date.now() + 60_000),
        },
        {
          id: `ver_${other.id}_a`,
          identifier: `2fa-abc${other.id}`,
          value: other.id,
          expiresAt: new Date(Date.now() + 60_000),
        },
      ]);
      const [user] = await t.db.select().from(schema.user).where(eq(schema.user.id, u.id));
      const summary = await inspectSecondFactor(`  ${(user?.email ?? "").toUpperCase()} `);
      expect(summary).toMatchObject({
        userId: u.id,
        totpEnrolled: true,
        passkeys: 2,
        sessions: 1,
        organizationId: ORG,
      });

      await resetSecondFactor(summary as NonNullable<typeof summary>);

      expect(
        (await t.db.select().from(schema.user).where(eq(schema.user.id, u.id)))[0]?.twoFactorEnabled,
      ).toBe(false);
      expect(
        await t.db.select().from(schema.twoFactor).where(eq(schema.twoFactor.userId, u.id)),
      ).toHaveLength(0);
      expect(await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, u.id))).toHaveLength(0);
      expect(await t.db.select().from(schema.session).where(eq(schema.session.userId, u.id))).toHaveLength(0);
      const left = await t.db.select().from(schema.verification);
      expect(left.map((v) => v.id)).not.toContain(`ver_${u.id}_a`);
      expect(left.map((v) => v.id)).not.toContain(`ver_${u.id}_b`);
      expect(left.map((v) => v.id)).toContain(`ver_${other.id}_a`);
      // The password stays: the next sign-in leads to the setup of a new second factor.
      const [account] = await t.db
        .select()
        .from(schema.account)
        .where(and(eq(schema.account.userId, u.id), eq(schema.account.providerId, "credential")));
      expect(await verifyPassword(account?.password ?? "", PASSWORD)).toBe(true);
      // Nobody else is touched.
      expect(
        await t.db.select().from(schema.passkey).where(eq(schema.passkey.userId, other.id)),
      ).toHaveLength(1);
      expect(
        await t.db.select().from(schema.twoFactor).where(eq(schema.twoFactor.userId, other.id)),
      ).toHaveLength(1);
      expect(
        await t.db.select().from(schema.session).where(eq(schema.session.userId, other.id)),
      ).toHaveLength(1);

      const [entry] = await auditOf("account.second_factor_reset", u.id);
      expect(entry).toMatchObject({ actorUserId: null, organizationId: ORG, targetId: u.id });
      expect(entry?.data).toMatchObject({
        via: "cli",
        passkeysRemoved: 2,
        authenticatorRemoved: true,
        sessionsEnded: 1,
      });
      expect(JSON.stringify(entry?.data)).not.toContain(u.secret);
    });

    it("knows nobody by an unknown address", async () => {
      const { inspectSecondFactor } = await import("../lib/second-factor-reset.ts");
      expect(await inspectSecondFactor("nobody@example.test")).toBeNull();
    });
  });
});
