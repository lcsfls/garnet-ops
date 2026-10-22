/**
 * The directory sign-in endpoint (ADR 0020) inside the real better-auth, against a throw-away
 * PostgreSQL database on the development server. The worker is replaced by canned answers, so
 * these tests are about what the API does with what the directory said: who gets an account, who
 * is refused and how it is recorded, the mandatory second factor, rate limits that stay below a
 * directory's lock-out, and that the password goes nowhere but to the worker. Skipped without the
 * development PostgreSQL.
 */

import type { DirectoryUser, SignInResult } from "@garnetops/core/directory";
import { hashPassword } from "@garnetops/core/password";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { symmetricEncrypt } from "better-auth/crypto";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const SECRET = "test-secret-with-at-least-32-characters-0000";
const BASE = "https://garnetops.example.test";
const ORG = "org_dirauth";
const PASSWORD = "test-only-directory-password";

const holder = vi.hoisted(() => ({ db: null as unknown }));
const ask = vi.hoisted(() => ({ fn: vi.fn() }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_dirauth");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: { directory: "directory.request" } };
});
vi.mock("../env.ts", () => ({
  env: { PUBLIC_URL: BASE, BETTER_AUTH_SECRET: SECRET },
  isProduction: false,
}));
// The worker's side: only the questions are recorded and the answers canned.
vi.mock("./directory.ts", async (original) => ({
  ...(await original<typeof import("./directory.ts")>()),
  askDirectory: ask.fn,
}));

interface Reply {
  status: number;
  json: Record<string, unknown> | null;
  cookies: string[];
  text: string;
}

const person = (patch: Partial<DirectoryUser> = {}): DirectoryUser => ({
  uniqueId: "12345678-9abc-def0-0123-456789abcd01",
  dn: "CN=John Doe,OU=Users,DC=example,DC=lan",
  email: "jdoe@example.lan",
  name: "John Doe",
  groups: ["CN=GarnetOps-Users,OU=Groups,DC=example,DC=lan"],
  role: "member",
  ...patch,
});
const ok = (user: DirectoryUser = person()): SignInResult => ({ outcome: "ok", user });

describe.skipIf(!adminUrl)("directory sign-in endpoint", () => {
  let t: TestDatabase;
  let auth: typeof import("../auth.ts").auth;
  let setFloor: (ms: number) => void;
  let counter = 0;
  let ipCounter = 0;

  const answers: SignInResult[] = [];
  const nextIp = () => `198.51.100.${(++ipCounter % 250) + 1}`;

  async function signIn(
    username: string,
    password: string,
    options: { ip?: string; cookie?: string } = {},
  ): Promise<Reply> {
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/sign-in/username`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: BASE,
          "x-forwarded-for": options.ip ?? nextIp(),
          ...(options.cookie ? { cookie: options.cookie } : {}),
        },
        body: JSON.stringify({ username, password }),
      }),
    );
    const text = await res.text();
    let json: Record<string, unknown> | null = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // not JSON
    }
    return { status: res.status, json, cookies: res.headers.getSetCookie(), text };
  }
  const cookieHeader = (cookies: string[]) => cookies.map((c) => c.split(";")[0]).join("; ");

  async function post(path: string, cookie: string, body: unknown = {}) {
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE, cookie, "x-forwarded-for": nextIp() },
        body: JSON.stringify(body),
      }),
    );
    const text = await res.text();
    return {
      status: res.status,
      text,
      json: text ? (JSON.parse(text) as Record<string, unknown>) : null,
      cookies: res.headers.getSetCookie(),
    };
  }

  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.action, action))).sort(
      (a, b) => a.id - b.id,
    );
  const userByEmail = async (email: string) =>
    (await t.db.select().from(schema.user).where(eq(schema.user.email, email)))[0];
  const membershipOf = async (userId: string) =>
    (await t.db.select().from(schema.membership).where(eq(schema.membership.userId, userId)))[0];
  const identityOf = async (userId: string) =>
    (
      await t.db.select().from(schema.directoryIdentity).where(eq(schema.directoryIdentity.userId, userId))
    )[0];
  const sessionsOf = async (userId: string) =>
    t.db.select().from(schema.session).where(eq(schema.session.userId, userId));

  async function setConfig(patch: Partial<typeof schema.ldapConfig.$inferInsert> = {}) {
    await t.db.delete(schema.ldapConfig);
    await t.db.insert(schema.ldapConfig).values({
      organizationId: ORG,
      enabled: true,
      preset: "active-directory",
      servers: [{ url: "ldaps://dc1.example.lan", pin: null, candidate: null, certStatus: "confirmed" }],
      tlsTrust: "system",
      bindDn: "CN=svc,OU=Service,DC=example,DC=lan",
      userBaseDn: "OU=Users,DC=example,DC=lan",
      userFilter: "(&(objectClass=user)(sAMAccountName={username}))",
      uniqueIdAttribute: "objectGUID",
      groupMode: "nested",
      groupRoles: [],
      ...patch,
    });
  }

  /** A local account (password and authenticator app) that is a member. */
  async function addLocal(email: string, role: "owner" | "admin" | "member" | "viewer" = "member") {
    const id = `user_loc${++counter}`;
    await t.db.insert(schema.user).values({ id, name: `Local ${counter}`, email, twoFactorEnabled: true });
    await t.db.insert(schema.account).values({
      id: `acc_${id}`,
      accountId: id,
      providerId: "credential",
      userId: id,
      password: await hashPassword("a-local-password-long-enough"),
    });
    await t.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role });
    return id;
  }

  beforeAll(async () => {
    ({ auth } = await import("../auth.ts"));
    ({ setFailureFloorForTests: setFloor } = await import("./directory-auth.ts"));
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Directory Org" });
    setFloor(0);
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  beforeEach(async () => {
    answers.length = 0;
    ask.fn.mockReset();
    ask.fn.mockImplementation(async () => {
      const next = answers.shift();
      if (!next) throw new Error("no canned answer");
      return next;
    });
    await t.pool.query(
      'truncate rate_limit, audit_log, session, verification, directory_identity, membership, account, two_factor, user_notification, "user" restart identity cascade',
    );
    await setConfig();
  });

  describe("a person the directory lets in", () => {
    it("gets an account on the first sign-in: unverified mail, no password, the role of the groups", async () => {
      answers.push(ok());
      const reply = await signIn("jdoe", PASSWORD);
      expect(reply.status).toBe(200);
      const user = await userByEmail("jdoe@example.lan");
      expect(user).toMatchObject({ name: "John Doe", emailVerified: false, twoFactorEnabled: false });
      expect(await membershipOf(user?.id as string)).toMatchObject({ organizationId: ORG, role: "member" });
      expect(await identityOf(user?.id as string)).toMatchObject({
        uniqueId: "12345678-9abc-def0-0123-456789abcd01",
        loginName: "jdoe",
        linkedBy: null,
      });
      // No local password was ever made for the account.
      expect(
        await t.db
          .select()
          .from(schema.account)
          .where(eq(schema.account.userId, user?.id as string)),
      ).toEqual([]);
      expect(reply.cookies.some((c) => c.startsWith("garnetops.session_token="))).toBe(true);
      expect((await sessionsOf(user?.id as string)).length).toBe(1);
      expect((await audits("directory.account_created"))[0]).toMatchObject({
        organizationId: ORG,
        actorUserId: user?.id,
        data: { email: "jdoe@example.lan", role: "member" },
      });
      expect((await audits("auth.directory_sign_in"))[0]?.data).toMatchObject({ outcome: "success" });
    });

    it("marks the mail verified only where the directory is trusted for it", async () => {
      await setConfig({ emailVerified: true });
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      expect((await userByEmail("jdoe@example.lan"))?.emailVerified).toBe(true);
    });

    it("sends only the user name and the password to the worker, and keeps the password out of every row", async () => {
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      expect(ask.fn).toHaveBeenCalledTimes(1);
      expect(ask.fn.mock.calls[0]?.[0]).toMatchObject({
        organizationId: ORG,
        kind: "sign-in",
        params: { username: "jdoe" },
        password: PASSWORD,
      });
      const everything = JSON.stringify([
        await t.db.select().from(schema.auditLog),
        await t.db.select().from(schema.user),
        await t.db.select().from(schema.session),
        await t.db.select().from(schema.verification),
        await t.db.select().from(schema.directoryIdentity),
        await t.db.select().from(schema.rateLimit),
      ]);
      expect(everything).not.toContain(PASSWORD);
    });

    it("an account with a second factor gets the second step instead of a session", async () => {
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      const user = await userByEmail("jdoe@example.lan");
      // The person enrolled an authenticator app at the first sign-in.
      await t.db
        .update(schema.user)
        .set({ twoFactorEnabled: true })
        .where(eq(schema.user.id, user?.id as string));
      await t.db.insert(schema.twoFactor).values({
        id: "tf_dir",
        userId: user?.id as string,
        secret: await symmetricEncrypt({ key: SECRET, data: "secret-0123456789abcdef" }),
        backupCodes: await symmetricEncrypt({ key: SECRET, data: "[]" }),
      });
      await t.db.delete(schema.session);
      answers.push(ok());
      const reply = await signIn("jdoe", PASSWORD);
      expect(reply.status).toBe(200);
      expect(reply.json).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ["totp"] });
      expect(reply.cookies.some((c) => c.startsWith("garnetops.two_factor="))).toBe(true);
      // No session exists until the code is right; the cookie of the session that was made is expired.
      expect(await sessionsOf(user?.id as string)).toEqual([]);
      expect(
        reply.cookies
          .filter((c) => c.startsWith("garnetops.session_token="))
          .every((c) => /Max-Age=0|expires=Thu, 01 Jan 1970/i.test(c)),
      ).toBe(true);
    });

    it("lets a new account enrol its authenticator app without a password it does not have", async () => {
      answers.push(ok());
      const reply = await signIn("jdoe", PASSWORD);
      const cookie = cookieHeader(reply.cookies);
      const enable = await post("two-factor/enable", cookie, {});
      expect(enable.status).toBe(200);
      expect(String(enable.json?.totpURI)).toContain("otpauth://totp/");
      const who = await auth.handler(new Request(`${BASE}/api/auth/directory/me`, { headers: { cookie } }));
      expect(await who.json()).toEqual({ managed: true, loginName: "jdoe" });
    });

    it("a local account still has to give its password to enrol", async () => {
      const id = await addLocal("local@example.lan");
      await t.db.update(schema.user).set({ twoFactorEnabled: false }).where(eq(schema.user.id, id));
      await t.db.delete(schema.twoFactor);
      const session = await auth.handler(
        new Request(`${BASE}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: BASE, "x-forwarded-for": nextIp() },
          body: JSON.stringify({ email: "local@example.lan", password: "a-local-password-long-enough" }),
        }),
      );
      const cookie = cookieHeader(session.headers.getSetCookie());
      expect((await post("two-factor/enable", cookie, {})).status).toBe(400);
      expect(
        (await post("two-factor/enable", cookie, { password: "a-local-password-long-enough" })).status,
      ).toBe(200);
      const who = await auth.handler(new Request(`${BASE}/api/auth/directory/me`, { headers: { cookie } }));
      expect(await who.json()).toEqual({ managed: false, loginName: null });
    });
  });

  describe("roles follow the groups, every time", () => {
    it("changes the role at the next sign-in and tells the person", async () => {
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      const user = await userByEmail("jdoe@example.lan");
      answers.push(ok(person({ role: "admin" })));
      await signIn("jdoe", PASSWORD);
      expect((await membershipOf(user?.id as string))?.role).toBe("admin");
      expect((await audits("directory.role_changed"))[0]?.data).toMatchObject({
        before: "member",
        after: "admin",
        via: "sign-in",
      });
      answers.push(ok(person({ role: "viewer" })));
      await signIn("jdoe", PASSWORD);
      expect((await membershipOf(user?.id as string))?.role).toBe("viewer");
    });

    it("a person who left every allowed group is refused, loses the membership and every session, and it is audited", async () => {
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      const user = await userByEmail("jdoe@example.lan");
      await t.db.insert(schema.session).values({
        id: "s_other",
        token: "t_other",
        userId: user?.id as string,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      answers.push({
        outcome: "not-allowed",
        problem: "not-in-group",
        user: person({ role: null, groups: [] }),
      });
      const reply = await signIn("jdoe", PASSWORD);
      expect(reply.status).toBe(401);
      expect(reply.json).toMatchObject({ code: "INVALID_USERNAME_OR_PASSWORD" });
      expect(await membershipOf(user?.id as string)).toBeUndefined();
      expect(await sessionsOf(user?.id as string)).toEqual([]);
      expect((await audits("directory.access_removed"))[0]).toMatchObject({
        actorUserId: user?.id,
        data: { before: "member", via: "sign-in" },
      });
      expect((await audits("auth.directory_sign_in")).at(-1)?.data).toMatchObject({
        outcome: "failure",
        reason: "not-allowed",
      });
      // Back in a group: the same account comes back.
      answers.push(ok(person({ role: "viewer" })));
      expect((await signIn("jdoe", PASSWORD)).status).toBe(200);
      expect(await membershipOf(user?.id as string)).toMatchObject({ role: "viewer" });
      expect((await audits("directory.access_restored")).length).toBe(1);
    });

    it("a person in no allowed group never gets an account", async () => {
      answers.push({
        outcome: "not-allowed",
        problem: "not-in-group",
        user: person({ role: null, groups: [] }),
      });
      const reply = await signIn("cnoone", PASSWORD);
      expect(reply.status).toBe(401);
      expect(await userByEmail("jdoe@example.lan")).toBeUndefined();
      expect(await t.db.select().from(schema.directoryIdentity)).toEqual([]);
      expect((await audits("auth.directory_sign_in"))[0]?.data).toMatchObject({
        reason: "not-allowed",
        dn: "CN=John Doe,OU=Users,DC=example,DC=lan",
      });
    });

    it("never touches an owner, even for a linked identity", async () => {
      const owner = await addLocal("jdoe@example.lan", "owner");
      await t.db.insert(schema.directoryIdentity).values({
        id: "di_owner",
        organizationId: ORG,
        userId: owner,
        uniqueId: "12345678-9abc-def0-0123-456789abcd01",
        dn: "CN=John Doe,OU=Users,DC=example,DC=lan",
        loginName: "jdoe",
      });
      answers.push({
        outcome: "not-allowed",
        problem: "not-in-group",
        user: person({ role: null, groups: [] }),
      });
      await signIn("jdoe", PASSWORD);
      expect((await membershipOf(owner))?.role).toBe("owner");
    });
  });

  describe("linking", () => {
    it("is by the unique id: a changed mail attribute follows the account, it does not take over another", async () => {
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      const first = await userByEmail("jdoe@example.lan");
      // The directory now says another address: the account follows its person.
      answers.push(ok(person({ email: "john.doe@example.lan" })));
      await signIn("jdoe", PASSWORD);
      expect(
        (
          await t.db
            .select()
            .from(schema.user)
            .where(eq(schema.user.id, first?.id as string))
        )[0]?.email,
      ).toBe("john.doe@example.lan");
      expect((await audits("directory.email_changed"))[0]?.data).toMatchObject({
        from: "jdoe@example.lan",
        to: "john.doe@example.lan",
      });
      expect((await t.db.select().from(schema.directoryIdentity)).length).toBe(1);
    });

    it("a mail attribute set to somebody else's address changes nothing about either account", async () => {
      const victim = await addLocal("victim@example.lan", "admin");
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      const first = await userByEmail("jdoe@example.lan");
      answers.push(ok(person({ email: "victim@example.lan" })));
      const reply = await signIn("jdoe", PASSWORD);
      expect(reply.status).toBe(200);
      // The account stays what it is; the victim is untouched and nobody gained their session.
      expect((await userByEmail("victim@example.lan"))?.id).toBe(victim);
      expect((await membershipOf(victim))?.role).toBe("admin");
      expect((await membershipOf(first?.id as string))?.role).toBe("member");
      expect((await userByEmail("jdoe@example.lan"))?.id).toBe(first?.id);
      expect((await audits("directory.email_conflict")).length).toBe(1);
      const sessions = await t.db.select().from(schema.session);
      expect(sessions.every((s) => s.userId === first?.id)).toBe(true);
    });

    it("refuses an account with the same address as a local one and says so in the audit log for the admins", async () => {
      const local = await addLocal("jdoe@example.lan", "admin");
      answers.push(ok());
      const reply = await signIn("jdoe", PASSWORD);
      expect(reply.status).toBe(401);
      expect(reply.json).toMatchObject({ code: "INVALID_USERNAME_OR_PASSWORD" });
      // Nothing was linked, created or changed.
      expect(await t.db.select().from(schema.directoryIdentity)).toEqual([]);
      expect((await t.db.select().from(schema.user)).length).toBe(1);
      expect((await membershipOf(local))?.role).toBe("admin");
      expect(await sessionsOf(local)).toEqual([]);
      const entry = (await audits("auth.directory_sign_in"))[0];
      expect(entry).toMatchObject({
        actorUserId: local,
        data: {
          outcome: "failure",
          reason: "email-collision",
          email: "jdoe@example.lan",
          existingUserId: local,
        },
      });
      expect(String((entry?.data as { hint?: string } | undefined)?.hint ?? "")).toMatch(/link/i);
    });

    it("refuses a person whose directory entry has no usable mail address", async () => {
      answers.push(ok(person({ email: null })));
      expect((await signIn("jdoe", PASSWORD)).status).toBe(401);
      expect((await audits("auth.directory_sign_in"))[0]?.data).toMatchObject({ reason: "no-email" });
      expect(await t.db.select().from(schema.user)).toEqual([]);
    });

    it("two first sign-ins at once make one account", async () => {
      answers.push(ok(), ok());
      const [a, b] = await Promise.all([signIn("jdoe", PASSWORD), signIn("jdoe", PASSWORD)]);
      expect([a.status, b.status]).toEqual([200, 200]);
      expect((await t.db.select().from(schema.user)).length).toBe(1);
      expect((await t.db.select().from(schema.directoryIdentity)).length).toBe(1);
    });
  });

  describe("refusals look the same", () => {
    const refused = (r: Reply) => ({ status: r.status, code: r.json?.code, message: r.json?.message });

    it("an unknown name, a wrong password, a refused group and a switched-off directory give one answer", async () => {
      answers.push({ outcome: "invalid-credentials", problem: "user-not-found" });
      const unknown = await signIn("nobody", PASSWORD);
      answers.push({
        outcome: "invalid-credentials",
        problem: "wrong-password",
        subject: { dn: "CN=John Doe,OU=Users,DC=example,DC=lan", uniqueId: "x" },
      });
      const wrong = await signIn("jdoe", "another-password");
      answers.push({ outcome: "not-allowed", problem: "not-in-group", user: person({ role: null }) });
      const group = await signIn("cnoone", PASSWORD);
      await setConfig({ enabled: false });
      const off = await signIn("jdoe", PASSWORD);
      expect([unknown, wrong, group, off].map(refused)).toEqual(
        Array(4).fill({
          status: 401,
          code: "INVALID_USERNAME_OR_PASSWORD",
          message: "Invalid username or password",
        }),
      );
      // Switched off: nothing was asked.
      expect(ask.fn).toHaveBeenCalledTimes(3);
    });

    it("the audit log names the entry a wrong password was tried for, and never the typed text", async () => {
      const account = await addLocal("jdoe@example.lan");
      await t.db.insert(schema.directoryIdentity).values({
        id: "di_x",
        organizationId: ORG,
        userId: account,
        uniqueId: "uid-x",
        dn: "CN=John Doe,OU=Users,DC=example,DC=lan",
        loginName: "jdoe",
      });
      answers.push({
        outcome: "invalid-credentials",
        problem: "wrong-password",
        subject: { dn: "CN=John Doe,OU=Users,DC=example,DC=lan", uniqueId: "uid-x" },
      });
      await signIn("jdoe", "typo-of-the-password");
      answers.push({ outcome: "invalid-credentials", problem: "user-not-found" });
      await signIn("Winter2026secret", "whatever-password");
      const entries = await audits("auth.directory_sign_in");
      expect(entries[0]).toMatchObject({
        actorUserId: account,
        data: {
          outcome: "failure",
          reason: "invalid-credentials",
          dn: "CN=John Doe,OU=Users,DC=example,DC=lan",
        },
      });
      expect(entries[1]?.actorUserId).toBeNull();
      const text = JSON.stringify(entries);
      expect(text).not.toContain("Winter2026secret");
      expect(text).not.toContain("typo-of-the-password");
      expect(text).not.toContain("whatever-password");
      expect(text).toContain("usernameRef");
    });

    it("a refusal takes at least the floor, whatever the reason", async () => {
      setFloor(300);
      try {
        answers.push({ outcome: "invalid-credentials", problem: "user-not-found" });
        const started = Date.now();
        await signIn("nobody", PASSWORD);
        expect(Date.now() - started).toBeGreaterThanOrEqual(290);
      } finally {
        setFloor(0);
      }
    });

    it("the directory being down is said honestly and is not held against the person", async () => {
      for (const outcome of ["unavailable", "misconfigured"] as const) {
        answers.push({ outcome, problem: "unreachable" });
        const reply = await signIn("jdoe", PASSWORD);
        expect(reply.status).toBe(503);
        expect(reply.json).toMatchObject({ code: "DIRECTORY_UNAVAILABLE" });
      }
      expect(
        await t.db.select().from(schema.rateLimit).where(eq(schema.rateLimit.key, "ldap:user:x")),
      ).toEqual([]);
      expect((await audits("auth.directory_sign_in"))[0]?.data).toMatchObject({
        reason: "unavailable",
        problem: "unreachable",
      });
    });

    it("a worker that does not answer is a 503 too", async () => {
      const { ProblemError } = await import("./problem.ts");
      ask.fn.mockRejectedValueOnce(
        new ProblemError(503, "directory-unavailable", "The directory did not answer in time"),
      );
      expect((await signIn("jdoe", PASSWORD)).status).toBe(503);
    });
  });

  describe("input that never reaches the directory", () => {
    it.each([
      ["a filter", "*)(uid=*"],
      ["a wildcard", "*"],
      ["a NUL", "jdoe\u0000"],
      ["nothing", ""],
      ["spaces", "  "],
      ["too much", "a".repeat(200)],
    ])("a user name with %s", async (_label, name) => {
      const reply = await signIn(name, PASSWORD);
      expect(reply.status).toBe(401);
      expect(ask.fn).not.toHaveBeenCalled();
    });

    it("an empty password", async () => {
      const reply = await signIn("jdoe", "");
      expect(reply.status).toBe(401);
      expect(ask.fn).not.toHaveBeenCalled();
    });

    it("a password longer than anyone has", async () => {
      expect((await signIn("jdoe", "x".repeat(600))).status).toBe(401);
      expect(ask.fn).not.toHaveBeenCalled();
    });
  });

  describe("attempts are limited below a directory's lock-out", () => {
    const wrong = (): SignInResult => ({ outcome: "invalid-credentials", problem: "wrong-password" });

    it("after three wrong passwords for one name nothing more reaches the directory, whatever the address", async () => {
      for (let i = 0; i < 3; i++) {
        answers.push(wrong());
        expect((await signIn("jdoe", `wrong-${i}`)).status).toBe(401);
      }
      const calls = ask.fn.mock.calls.length;
      const blocked = await signIn("jdoe", PASSWORD);
      expect(blocked.status).toBe(429);
      expect(blocked.json).toMatchObject({ code: "TOO_MANY_ATTEMPTS" });
      expect(ask.fn.mock.calls.length).toBe(calls);
      // The name is counted case-insensitively.
      expect((await signIn("JDoe", PASSWORD)).status).toBe(429);
      // Another name is not affected.
      answers.push(ok(person({ uniqueId: "other", email: "other@example.lan" })));
      expect((await signIn("someone-else", PASSWORD)).status).toBe(200);
      expect((await audits("auth.directory_sign_in")).at(-2)?.data).toMatchObject({ reason: "rate-limited" });
    });

    it("an unknown name counts like a known one, so the limit gives nothing away", async () => {
      for (let i = 0; i < 3; i++) {
        answers.push({ outcome: "invalid-credentials", problem: "user-not-found" });
        await signIn("ghost", "x-wrong");
      }
      expect((await signIn("ghost", PASSWORD)).status).toBe(429);
    });

    it("a success clears the count of that name", async () => {
      for (let i = 0; i < 2; i++) {
        answers.push(wrong());
        await signIn("jdoe", `wrong-${i}`);
      }
      answers.push(ok());
      expect((await signIn("jdoe", PASSWORD)).status).toBe(200);
      for (let i = 0; i < 2; i++) {
        answers.push(wrong());
        expect((await signIn("jdoe", `again-${i}`)).status).toBe(401);
      }
    });

    it("spraying many names from one address is stopped by the address limit", async () => {
      const ip = "203.0.113.9";
      // The sign-in limit per minute of the library is 5; spread the attempts so only our own limit is in play.
      await t.pool.query("truncate rate_limit");
      for (let i = 0; i < 20; i++) {
        await t.pool.query("delete from rate_limit where key not like 'ldap:%'");
        answers.push(wrong());
        expect((await signIn(`user${i}`, "guess", { ip })).status).toBe(401);
      }
      await t.pool.query("delete from rate_limit where key not like 'ldap:%'");
      const calls = ask.fn.mock.calls.length;
      expect((await signIn("user99", "guess", { ip })).status).toBe(429);
      expect(ask.fn.mock.calls.length).toBe(calls);
      // Another address is not affected.
      answers.push(wrong());
      expect((await signIn("user99", "guess", { ip: "203.0.113.10" })).status).toBe(401);
    });

    it("the library's own limit of five a minute per address applies too, and survives in the database", async () => {
      const ip = "203.0.113.50";
      const statuses: number[] = [];
      for (let i = 0; i < 7; i++) {
        answers.push(wrong());
        statuses.push((await signIn(`name${i}`, "guess", { ip })).status);
      }
      expect(statuses.filter((s) => s === 429).length).toBeGreaterThanOrEqual(1);
      expect((await t.db.select().from(schema.rateLimit)).length).toBeGreaterThan(0);
    });
  });

  describe("the local sign-in", () => {
    it("is closed for an account that comes from the directory", async () => {
      answers.push(ok());
      await signIn("jdoe", PASSWORD);
      const attempt = (email: string) =>
        auth.handler(
          new Request(`${BASE}/api/auth/sign-in/email`, {
            method: "POST",
            headers: { "content-type": "application/json", origin: BASE, "x-forwarded-for": nextIp() },
            body: JSON.stringify({ email, password: "any-password-long-enough" }),
          }),
        );
      const directory = await attempt("jdoe@example.lan");
      const unknown = await attempt("nobody@example.lan");
      expect(directory.status).toBe(401);
      expect(await directory.json()).toEqual(await unknown.json());
      expect(
        (await audits("auth.sign_in")).some((e) => (e.data as { outcome?: string })?.outcome === "failure"),
      ).toBe(true);
    });
  });

  describe("without a session", () => {
    it("the account question needs one", async () => {
      const res = await auth.handler(new Request(`${BASE}/api/auth/directory/me`));
      expect(res.status).toBe(401);
    });
  });
});
