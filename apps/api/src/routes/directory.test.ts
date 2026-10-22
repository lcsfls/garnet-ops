/**
 * The directory settings API (ADR 0020) against a throw-away PostgreSQL database on the
 * development server: owners only, step-up for every change, the service account's password
 * sealed and never returned, tests before going live, certificate pinning on first contact, and
 * linking an existing account. The worker is replaced by canned answers. Sessions are replaced by
 * a header-driven actor. Skipped without the development PostgreSQL.
 */
import { DIRECTORY_PRESET_VALUES } from "@garnetops/core/directory";
import { hashPassword } from "@garnetops/core/password";
import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const ORG = "org_dirsettings";
const BIND_PASSWORD = "test-only-service-password";
const FP_A = Array.from({ length: 32 }, (_, i) => (i + 10).toString(16).padStart(2, "0").toUpperCase()).join(
  ":",
);
const FP_B = Array.from({ length: 32 }, (_, i) => (i + 60).toString(16).padStart(2, "0").toUpperCase()).join(
  ":",
);

const holder = vi.hoisted(() => ({ db: null as unknown, privateKey: "" }));
const ask = vi.hoisted(() => ({ fn: vi.fn() }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_dirsettings");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: { directory: "directory.request" } };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair, loadVaultPublicKey } = await import("@garnetops/core/vault");
  const pair = generateVaultKeyPair();
  holder.privateKey = pair.privateKeyPem;
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test" },
    isProduction: false,
    vaultPublicKey: loadVaultPublicKey(pair.publicKeyPem),
  };
});
vi.mock("../lib/directory.ts", async (original) => ({
  ...(await original<typeof import("../lib/directory.ts")>()),
  askDirectory: ask.fn,
}));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;

const validBody = (patch: Json = {}): Json => ({
  enabled: false,
  preset: "active-directory",
  servers: ["ldaps://dc1.example.lan", "ldaps://dc2.example.lan:636"],
  tlsTrust: "system",
  caCertificate: "",
  bindDn: "CN=svc-garnetops,OU=Service,DC=example,DC=lan",
  bindPassword: BIND_PASSWORD,
  userBaseDn: "OU=Users,DC=example,DC=lan",
  ...DIRECTORY_PRESET_VALUES["active-directory"],
  groupRoles: [
    { dn: "CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan", role: "admin" },
    { dn: "CN=GarnetOps-Users,OU=Groups,DC=example,DC=lan", role: "member" },
  ],
  emailVerified: false,
  connectTimeoutSeconds: 5,
  operationTimeoutSeconds: 10,
  sizeLimit: 50,
  ...patch,
});

describe.skipIf(!adminUrl)("directory settings API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    options: { role?: string; age?: number; body?: unknown; user?: string } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "owner",
      "x-user": options.user ?? "u_owner",
      "x-age": String(options.age ?? 0),
    };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(`/api/v1${path}`, {
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
  const code = (r: { json: Json | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const save = (patch: Json = {}, options: { role?: string; age?: number } = {}) =>
    call("PUT", "/directory", { body: validBody(patch), ...options });
  const config = async () =>
    (await t.db.select().from(schema.ldapConfig).where(eq(schema.ldapConfig.organizationId, ORG)))[0];
  /** The names of the fields an audit entry says changed. */
  const changedFields = (entry: { data: unknown } | undefined): string[] =>
    ((entry?.data ?? {}) as { changed?: string[] }).changed ?? [];
  const audits = async (action: string) =>
    t.db.select().from(schema.auditLog).where(eq(schema.auditLog.action, action));

  async function addMember(role: "owner" | "admin" | "member" | "viewer", email?: string) {
    const id = `u_dir${++counter}`;
    await t.db.insert(schema.user).values({
      id,
      name: `Person ${counter}`,
      email: email ?? `person${counter}@example.lan`,
      twoFactorEnabled: true,
    });
    await t.db.insert(schema.account).values({
      id: `acc_${id}`,
      accountId: id,
      providerId: "credential",
      userId: id,
      password: await hashPassword("a-local-password-long-enough"),
    });
    await t.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role });
    await t.db
      .insert(schema.session)
      .values({ id: `s_${id}`, token: `t_${id}`, userId: id, expiresAt: new Date(Date.now() + 3600_000) });
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { directoryRoutes } = await import("./directory.ts");
    const { teamRoutes } = await import("./team.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Org" });
    await t.db
      .insert(schema.user)
      .values({ id: "u_owner", name: "Owner", email: "owner@example.lan", twoFactorEnabled: true });
    await t.db.insert(schema.membership).values({ organizationId: ORG, userId: "u_owner", role: "owner" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "owner@example.lan",
          name: "Owner",
          organizationId: ORG,
          role: c.req.header("x-role"),
          ip: "198.51.100.7",
          sessionId: "s1",
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/directory", directoryRoutes as never);
    v1.route("/team", teamRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  beforeEach(async () => {
    ask.fn.mockReset();
    await t.pool.query(
      "truncate rate_limit, audit_log, session, directory_identity, ldap_config, secret, invitation restart identity cascade",
    );
    await t.pool.query("delete from membership where user_id <> 'u_owner'");
    await t.pool.query("delete from account");
    await t.pool.query("delete from \"user\" where id <> 'u_owner'");
  });

  describe("who may", () => {
    it.each([
      ["GET", "/directory"],
      ["PUT", "/directory"],
      ["POST", "/directory/test"],
      ["POST", "/directory/certificates/scan"],
      ["POST", "/directory/certificates/confirm"],
      ["POST", "/directory/lookup"],
      ["POST", "/directory/link"],
    ])("%s %s is for owners only", async (method, path) => {
      for (const role of ["admin", "member", "viewer"]) {
        const r = await call(method, path, { role, body: method === "GET" ? undefined : {} });
        expect(r.status).toBe(403);
      }
    });

    it("shows an unconfigured directory", async () => {
      const r = await call("GET", "/directory");
      expect(r.json).toMatchObject({ configured: false, settings: null, servers: [], accounts: 0 });
    });
  });

  describe("saving", () => {
    it("needs a recent sign-in", async () => {
      const r = await save({}, { age: 11 * 60 });
      expect(r.status).toBe(403);
      expect(code(r)).toBe("step-up-required");
      expect(await config()).toBeUndefined();
    });

    it("stores the settings, seals the password and never returns it", async () => {
      const r = await save();
      expect(r.status).toBe(200);
      expect(r.json).toMatchObject({
        configured: true,
        settings: {
          enabled: false,
          bindPasswordSet: true,
          servers: ["ldaps://dc1.example.lan", "ldaps://dc2.example.lan"],
        },
        testedAt: null,
      });
      expect(r.text).not.toContain(BIND_PASSWORD);
      const row = await config();
      expect(row?.bindSecretId).toBeTruthy();
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, row?.bindSecretId as string));
      expect(secret).toMatchObject({ organizationId: ORG, purpose: "ldap-bind-password" });
      expect(JSON.stringify(secret?.sealed)).not.toContain(BIND_PASSWORD);
      // Only the vault's private key opens it, and only for this organisation, record and purpose.
      const key = loadVaultPrivateKey(holder.privateKey);
      const binding = {
        organizationId: ORG,
        recordId: secret?.id as string,
        purpose: "ldap-bind-password" as const,
      };
      expect(open(secret?.sealed, binding, key).toString()).toBe(BIND_PASSWORD);
      expect(() => open(secret?.sealed, { ...binding, purpose: "ldap-user-password" }, key)).toThrow();
      expect(() => open(secret?.sealed, { ...binding, organizationId: "org_other" }, key)).toThrow();
      const everything = JSON.stringify([
        await t.db.select().from(schema.ldapConfig),
        await t.db.select().from(schema.auditLog),
      ]);
      expect(everything).not.toContain(BIND_PASSWORD);
    });

    it("audits the change with what changed and never the password", async () => {
      await save();
      const [created] = await audits("directory.settings_created");
      expect(created).toMatchObject({
        organizationId: ORG,
        actorUserId: "u_owner",
        data: { enabled: false, tlsTrust: "system" },
      });
      await save({ bindPassword: undefined, userBaseDn: "OU=People,DC=example,DC=lan" });
      const [changed] = await audits("directory.settings_changed");
      expect(changedFields(changed)).toContain("userBaseDn");
      expect(changedFields(changed)).not.toContain("bindPassword");
      await save({ bindPassword: "test-only-another-password" });
      const entries = await audits("directory.settings_changed");
      expect(changedFields(entries.at(-1))).toContain("bindPassword");
      expect(JSON.stringify(entries)).not.toContain("test-only-another-password");
    });

    it("keeps the stored password when none is sent, and replaces it (deleting the old one) when one is", async () => {
      await save();
      const first = (await config())?.bindSecretId;
      await save({ bindPassword: undefined, sizeLimit: 60 });
      expect((await config())?.bindSecretId).toBe(first);
      await save({ bindPassword: "test-only-another-password" });
      const second = (await config())?.bindSecretId;
      expect(second).not.toBe(first);
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, first as string)),
      ).toEqual([]);
    });

    it("a new password lifts the pause after a refusal", async () => {
      await save();
      await t.db.update(schema.ldapConfig).set({ bindBlockedUntil: new Date(Date.now() + 600_000) });
      const r = await call("GET", "/directory");
      expect(r.json?.bindBlockedUntil).toBeTruthy();
      await save({ bindPassword: "test-only-another-password" });
      expect((await config())?.bindBlockedUntil).toBeNull();
    });

    it("needs a password the first time", async () => {
      const r = await save({ bindPassword: undefined });
      expect(r.status).toBe(422);
      expect(r.json?.errors).toContainEqual({ path: "bindPassword", message: "password_required" });
    });

    it.each([
      [{ servers: [] }, "servers"],
      [{ servers: ["http://dc1.example.lan"] }, "servers.0"],
      [{ servers: ["ldap://127.0.0.1"] }, "servers.0"],
      [{ servers: ["ldaps://169.254.169.254"] }, "servers.0"],
      [{ servers: ["ldaps://user:pw@dc1.example.lan"] }, "servers.0"],
      [{ tlsTrust: "ca", caCertificate: "not a certificate" }, "caCertificate"],
      [{ bindDn: "" }, "bindDn"],
      [{ userBaseDn: "cn=a\\" }, "userBaseDn"],
      [{ userFilter: "(sAMAccountName=jdoe)" }, "userFilter"],
      [{ userFilter: "(uid={username}" }, "userFilter"],
      [{ uniqueIdAttribute: "object guid" }, "uniqueIdAttribute"],
      [{ groupRoles: [] }, "groupRoles"],
      [
        {
          groupRoles: [
            { dn: "cn=a,dc=x", role: "viewer" },
            { dn: "CN=A,DC=X", role: "admin" },
          ],
        },
        "groupRoles.1",
      ],
      [{ connectTimeoutSeconds: 0 }, "connectTimeoutSeconds"],
      [{ sizeLimit: 100000 }, "sizeLimit"],
    ])("refuses %j", async (patch, field) => {
      const r = await save(patch as Json);
      expect(r.status).toBe(422);
      expect(((r.json?.errors ?? []) as { path: string }[]).map((e) => e.path)).toContain(field);
      expect(await config()).toBeUndefined();
    });

    it("never accepts owner as the role of a group", async () => {
      const r = await save({ groupRoles: [{ dn: "cn=a,dc=x", role: "owner" }] });
      expect(r.status).toBe(422);
    });
  });

  describe("going live", () => {
    it("cannot be switched on before a test with a person", async () => {
      const r = await save({ enabled: true });
      expect(r.status).toBe(409);
      expect(code(r)).toBe("not-tested");
      expect(await config()).toBeUndefined();
    });

    it("can be switched on after one", async () => {
      await save();
      await t.db.update(schema.ldapConfig).set({ testedAt: new Date() });
      const r = await save({ enabled: true, bindPassword: undefined });
      expect(r.status).toBe(200);
      expect(r.json?.settings.enabled).toBe(true);
    });

    it("a change to how the directory is reached switches it off and asks for a new test", async () => {
      await save();
      await t.db.update(schema.ldapConfig).set({ testedAt: new Date(), enabled: true });
      const r = await save({
        enabled: true,
        bindPassword: undefined,
        userFilter: "(&(objectClass=person)(sAMAccountName={username}))",
      });
      expect(r.status).toBe(200);
      expect(r.json).toMatchObject({ switchedOff: true, settings: { enabled: false }, testedAt: null });
      expect((await audits("directory.settings_changed")).at(-1)?.data).toMatchObject({ switchedOff: true });
    });

    it("a change of the group roles keeps it on", async () => {
      await save();
      await t.db.update(schema.ldapConfig).set({ testedAt: new Date(), enabled: true });
      const r = await save({
        enabled: true,
        bindPassword: undefined,
        groupRoles: [{ dn: "CN=GarnetOps-Viewers,OU=Groups,DC=example,DC=lan", role: "viewer" }],
      });
      expect(r.json).toMatchObject({ switchedOff: false, settings: { enabled: true } });
      expect((await config())?.testedAt).not.toBeNull();
    });

    it("stays on when only the test was cleared (a newly confirmed certificate), but cannot be switched on again untested", async () => {
      await save();
      await t.db.update(schema.ldapConfig).set({ testedAt: null, enabled: true });
      const stays = await save({ enabled: true, bindPassword: undefined, sizeLimit: 70 });
      expect(stays.status).toBe(200);
      expect(stays.json?.settings.enabled).toBe(true);
      await t.db.update(schema.ldapConfig).set({ testedAt: null, enabled: false });
      const on = await save({ enabled: true, bindPassword: undefined });
      expect(code(on)).toBe("not-tested");
    });

    it("can always be switched off", async () => {
      await save();
      await t.db.update(schema.ldapConfig).set({ testedAt: new Date(), enabled: true });
      const r = await save({ enabled: false, bindPassword: undefined });
      expect(r.json?.settings.enabled).toBe(false);
    });
  });

  describe("the connection test", () => {
    it("asks the worker, returns what it found and audits it", async () => {
      await save();
      ask.fn.mockResolvedValue({
        ok: true,
        servers: [],
        user: { dn: "CN=John Doe,DC=example,DC=lan", role: "admin" },
        latencyMs: 12,
      });
      const r = await call("POST", "/directory/test", { body: { username: "jdoe" } });
      expect(r.status).toBe(200);
      expect(r.json?.result).toMatchObject({ ok: true, user: { role: "admin" } });
      expect(ask.fn).toHaveBeenCalledWith(
        expect.objectContaining({ organizationId: ORG, kind: "test", params: { username: "jdoe" } }),
      );
      expect((await audits("directory.test_run"))[0]?.data).toMatchObject({ ok: true, username: "jdoe" });
    });

    it("works without a user name", async () => {
      await save();
      ask.fn.mockResolvedValue({ ok: true, servers: [], latencyMs: 1 });
      expect((await call("POST", "/directory/test", { body: {} })).status).toBe(200);
      expect(ask.fn).toHaveBeenCalledWith(expect.objectContaining({ params: {} }));
    });

    it("refuses a user name with filter syntax before the worker hears of it", async () => {
      await save();
      const r = await call("POST", "/directory/test", { body: { username: "*)(uid=*" } });
      expect(r.status).toBe(422);
      expect(ask.fn).not.toHaveBeenCalled();
    });

    it("needs saved settings", async () => {
      expect((await call("POST", "/directory/test", { body: {} })).status).toBe(409);
    });

    it("is limited to ten a minute", async () => {
      await save();
      ask.fn.mockResolvedValue({ ok: true, servers: [], latencyMs: 1 });
      for (let i = 0; i < 10; i++)
        expect((await call("POST", "/directory/test", { body: {} })).status).toBe(200);
      expect((await call("POST", "/directory/test", { body: {} })).status).toBe(429);
    });
  });

  describe("certificate pinning", () => {
    const candidate = (fingerprint: string) => ({
      fingerprint,
      subject: "CN=dc1.example.lan",
      issuer: "CN=dc1.example.lan",
      validFrom: "2026-01-01T00:00:00.000Z",
      validTo: "2027-01-01T00:00:00.000Z",
      trusted: false,
      seenAt: "2026-10-01T00:00:00.000Z",
    });
    const pinned = async () => (await config())?.servers.find((s) => s.url === "ldaps://dc1.example.lan");

    it("starts every server unconfirmed when pinning is switched on", async () => {
      const r = await save({ tlsTrust: "pin" });
      expect(r.json?.servers).toMatchObject([
        {
          url: "ldaps://dc1.example.lan",
          transport: "ldaps",
          certificate: { status: "pending", pin: null, candidate: null },
        },
        { url: "ldaps://dc2.example.lan", certificate: { status: "pending" } },
      ]);
    });

    it("shows no certificate state when pinning is off", async () => {
      const r = await save();
      expect(r.json?.servers[0].certificate).toBeNull();
    });

    it("pins exactly the fingerprint that was shown, with a recent sign-in", async () => {
      await save({ tlsTrust: "pin" });
      const row = await config();
      await t.db.update(schema.ldapConfig).set({
        servers: (row?.servers ?? []).map((s, i) => (i === 0 ? { ...s, candidate: candidate(FP_A) } : s)),
      });
      const stale = await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: FP_A },
        age: 11 * 60,
      });
      expect(code(stale)).toBe("step-up-required");
      const wrong = await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: FP_B },
      });
      expect(code(wrong)).toBe("fingerprint-mismatch");
      const bad = await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: "nope" },
      });
      expect(bad.status).toBe(422);
      const r = await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: FP_A.toLowerCase() },
      });
      expect(r.status).toBe(200);
      expect(await pinned()).toMatchObject({
        certStatus: "confirmed",
        candidate: null,
        pin: { fingerprint: FP_A, confirmedBy: "u_owner" },
      });
      expect((await audits("directory.certificate_confirmed"))[0]?.data).toMatchObject({
        server: "ldaps://dc1.example.lan",
        fingerprint: FP_A,
      });
    });

    it("a confirmed pin resets the test: trust changed", async () => {
      await save({ tlsTrust: "pin" });
      const row = await config();
      await t.db.update(schema.ldapConfig).set({
        testedAt: new Date(),
        servers: (row?.servers ?? []).map((s, i) => (i === 0 ? { ...s, candidate: candidate(FP_A) } : s)),
      });
      await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: FP_A },
      });
      expect((await config())?.testedAt).toBeNull();
    });

    it("a change after a pin: the old pin stays until the new fingerprint is confirmed", async () => {
      await save({ tlsTrust: "pin" });
      const row = await config();
      const pin = { ...candidate(FP_A), confirmedAt: "2026-10-01T00:00:00.000Z", confirmedBy: "u_owner" };
      await t.db.update(schema.ldapConfig).set({
        servers: (row?.servers ?? []).map((s, i) =>
          i === 0 ? { ...s, pin, certStatus: "changed" as const, candidate: candidate(FP_B) } : s,
        ),
      });
      expect(
        (await save({ tlsTrust: "pin", bindPassword: undefined })).json?.servers[0].certificate,
      ).toMatchObject({
        status: "changed",
        pin: { fingerprint: FP_A },
        candidate: { fingerprint: FP_B },
      });
    });

    it("has nothing to confirm without a candidate, or without pinning", async () => {
      await save({ tlsTrust: "pin" });
      const none = await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: FP_A },
      });
      expect(code(none)).toBe("no-certificate");
      await save({ bindPassword: undefined });
      const off = await call("POST", "/directory/certificates/confirm", {
        body: { url: "ldaps://dc1.example.lan", fingerprint: FP_A },
      });
      expect(code(off)).toBe("not-pinning");
    });

    it("reading the certificates asks the worker for them and says nothing else", async () => {
      await save({ tlsTrust: "pin" });
      ask.fn.mockResolvedValue({ servers: [] });
      const r = await call("POST", "/directory/certificates/scan", { body: {} });
      expect(r.status).toBe(200);
      expect(ask.fn).toHaveBeenCalledWith(expect.objectContaining({ kind: "certificate", params: {} }));
      const one = await call("POST", "/directory/certificates/scan", {
        body: { url: "ldaps://elsewhere.example.lan" },
      });
      expect(one.status).toBe(404);
    });

    it("keeps the pins of servers that stay in the list when the list changes", async () => {
      await save({ tlsTrust: "pin" });
      const row = await config();
      const pin = { ...candidate(FP_A), confirmedAt: "2026-10-01T00:00:00.000Z", confirmedBy: "u_owner" };
      await t.db.update(schema.ldapConfig).set({
        servers: (row?.servers ?? []).map((s, i) =>
          i === 0 ? { ...s, pin, certStatus: "confirmed" as const } : s,
        ),
      });
      await save({
        tlsTrust: "pin",
        bindPassword: undefined,
        servers: ["ldaps://dc1.example.lan", "ldaps://dc3.example.lan"],
      });
      const servers = (await config())?.servers ?? [];
      expect(servers.map((s) => s.url)).toEqual(["ldaps://dc1.example.lan", "ldaps://dc3.example.lan"]);
      expect(servers[0]?.pin?.fingerprint).toBe(FP_A);
      expect(servers[1]?.pin).toBeNull();
      // Leaving pinning drops the pins: switching back means confirming again.
      await save({ tlsTrust: "system", bindPassword: undefined });
      await save({ tlsTrust: "pin", bindPassword: undefined });
      expect((await config())?.servers.every((s) => s.pin === null)).toBe(true);
    });
  });

  describe("linking an account", () => {
    const person = (patch: Json = {}) => ({
      uniqueId: "12345678-9abc-def0-0123-456789abcd01",
      dn: "CN=John Doe,OU=Users,DC=example,DC=lan",
      email: "jdoe@example.lan",
      name: "John Doe",
      groups: ["CN=GarnetOps-Users,OU=Groups,DC=example,DC=lan"],
      role: "member",
      ...patch,
    });
    const link = (userId: string, age = 0) =>
      call("POST", "/directory/link", { body: { userId, username: "jdoe" }, age });

    beforeEach(async () => {
      await save();
    });

    it("shows what the directory says and whether the address matches", async () => {
      const id = await addMember("viewer", "jdoe@example.lan");
      ask.fn.mockResolvedValue({ outcome: "ok", user: person() });
      const r = await call("POST", "/directory/lookup", { body: { userId: id, username: "jdoe" } });
      expect(r.json).toMatchObject({
        outcome: "ok",
        emailMatches: true,
        alreadyLinked: false,
        person: { dn: "CN=John Doe,OU=Users,DC=example,DC=lan", role: "member" },
        account: { role: "viewer" },
      });
      const other = await addMember("member", "someone.else@example.lan");
      expect(
        (await call("POST", "/directory/lookup", { body: { userId: other, username: "jdoe" } })).json
          ?.emailMatches,
      ).toBe(false);
    });

    it("turns a local account into a directory account: identity, no password, role from the groups, sessions ended", async () => {
      const id = await addMember("viewer", "jdoe@example.lan");
      ask.fn.mockResolvedValue({ outcome: "ok", user: person({ role: "admin" }) });
      const r = await link(id);
      expect(r.status).toBe(200);
      expect(r.json).toMatchObject({ ok: true, role: "admin" });
      expect(
        (
          await t.db.select().from(schema.directoryIdentity).where(eq(schema.directoryIdentity.userId, id))
        )[0],
      ).toMatchObject({
        uniqueId: "12345678-9abc-def0-0123-456789abcd01",
        linkedBy: "u_owner",
        loginName: "jdoe",
      });
      expect(await t.db.select().from(schema.account).where(eq(schema.account.userId, id))).toEqual([]);
      expect(
        (await t.db.select().from(schema.membership).where(eq(schema.membership.userId, id)))[0]?.role,
      ).toBe("admin");
      expect(await t.db.select().from(schema.session).where(eq(schema.session.userId, id))).toEqual([]);
      // The authenticator app stays.
      expect((await t.db.select().from(schema.user).where(eq(schema.user.id, id)))[0]?.twoFactorEnabled).toBe(
        true,
      );
      expect((await audits("directory.account_linked"))[0]).toMatchObject({
        targetId: id,
        data: { before: "viewer", after: "admin" },
      });
    });

    it("needs a recent sign-in", async () => {
      const id = await addMember("viewer", "jdoe@example.lan");
      expect(code(await link(id, 11 * 60))).toBe("step-up-required");
      expect(ask.fn).not.toHaveBeenCalled();
    });

    it("never links an owner: owners stay local, so an outage cannot lock the installation out", async () => {
      const id = await addMember("owner", "jdoe@example.lan");
      const r = await link(id);
      expect(r.status).toBe(409);
      expect(code(r)).toBe("owner");
      expect(ask.fn).not.toHaveBeenCalled();
    });

    it("refuses when the address in the directory is not the account's", async () => {
      const id = await addMember("member", "someone.else@example.lan");
      ask.fn.mockResolvedValue({ outcome: "ok", user: person() });
      expect(code(await link(id))).toBe("email-mismatch");
      expect(await t.db.select().from(schema.directoryIdentity)).toEqual([]);
      expect(await t.db.select().from(schema.account).where(eq(schema.account.userId, id))).toHaveLength(1);
    });

    it("refuses a person in no allowed group", async () => {
      const id = await addMember("member", "jdoe@example.lan");
      ask.fn.mockResolvedValue({
        outcome: "not-allowed",
        problem: "not-in-group",
        user: person({ role: null, groups: [] }),
      });
      expect(code(await link(id))).toBe("not-allowed");
    });

    it("refuses when the person is not found, or the directory cannot be asked", async () => {
      const id = await addMember("member", "jdoe@example.lan");
      ask.fn.mockResolvedValue({ outcome: "invalid-credentials", problem: "user-not-found" });
      expect(code(await link(id))).toBe("not-allowed");
      ask.fn.mockResolvedValue({ outcome: "unavailable", problem: "unreachable" });
      expect(code(await link(id))).toBe("not-allowed");
    });

    it("refuses an account that already comes from the directory, and a person who is already linked", async () => {
      const first = await addMember("member", "jdoe@example.lan");
      ask.fn.mockResolvedValue({ outcome: "ok", user: person() });
      expect((await link(first)).status).toBe(200);
      expect(code(await link(first))).toBe("already-linked");
      const second = await addMember("member", "jdoe@example.lan".replace("jdoe", "jdoe2"));
      ask.fn.mockResolvedValue({ outcome: "ok", user: person({ email: "jdoe2@example.lan" }) });
      expect(code(await link(second))).toBe("already-linked");
    });

    it("a user name with filter syntax never reaches the worker", async () => {
      const id = await addMember("member", "jdoe@example.lan");
      const r = await call("POST", "/directory/lookup", { body: { userId: id, username: "*)(cn=*" } });
      expect(r.status).toBe(422);
      expect(ask.fn).not.toHaveBeenCalled();
    });

    it("does not know a member of another organisation", async () => {
      const r = await call("POST", "/directory/lookup", { body: { userId: "u_nobody", username: "jdoe" } });
      expect(r.status).toBe(404);
    });
  });

  describe("the team page", () => {
    async function makeDirectoryAccount(role: "admin" | "member" | "viewer", email: string) {
      const id = await addMember(role, email);
      await t.db.delete(schema.account).where(eq(schema.account.userId, id));
      await t.db.insert(schema.directoryIdentity).values({
        id: `di_${id}`,
        organizationId: ORG,
        userId: id,
        uniqueId: `uid-${id}`,
        dn: `CN=${id},OU=Users,DC=example,DC=lan`,
        loginName: id,
      });
      return id;
    }

    it("shows where each account comes from", async () => {
      const local = await addMember("member", "local@example.lan");
      const remote = await makeDirectoryAccount("viewer", "remote@example.lan");
      const r = await call("GET", "/team/members", { role: "admin" });
      const byId = Object.fromEntries((r.json as Json[]).map((m) => [m.userId, m.source]));
      expect(byId).toMatchObject({ [local]: "local", [remote]: "directory", u_owner: "local" });
      // The dummy row never leaks.
      expect(r.text).not.toContain("directoryIdentityId");
    });

    it("refuses to change the role of a directory account: it would be undone at the next sign-in", async () => {
      const remote = await makeDirectoryAccount("viewer", "remote@example.lan");
      const r = await call("PATCH", `/team/members/${remote}`, { role: "admin", body: { role: "member" } });
      expect(r.status).toBe(409);
      expect(code(r)).toBe("managed-by-directory");
      expect(
        (await t.db.select().from(schema.membership).where(eq(schema.membership.userId, remote)))[0]?.role,
      ).toBe("viewer");
    });

    it("refuses to remove a directory account, which the directory would bring back", async () => {
      const remote = await makeDirectoryAccount("viewer", "remote@example.lan");
      const r = await call("DELETE", `/team/members/${remote}`, { role: "admin" });
      expect(code(r)).toBe("managed-by-directory");
      expect(await t.db.select().from(schema.session).where(eq(schema.session.userId, remote))).toHaveLength(
        1,
      );
    });

    it("still changes the role of a local account", async () => {
      const local = await addMember("viewer", "local@example.lan");
      expect(
        (await call("PATCH", `/team/members/${local}`, { role: "admin", body: { role: "member" } })).status,
      ).toBe(204);
    });

    it("does not invite someone who signs in with the directory", async () => {
      // Their access was removed (by the directory), the account stays.
      const remote = await makeDirectoryAccount("viewer", "remote@example.lan");
      await t.db.delete(schema.membership).where(eq(schema.membership.userId, remote));
      const r = await call("POST", "/team/invitations", {
        body: { email: "Remote@Example.lan", role: "member" },
      });
      expect(code(r)).toBe("directory-account");
    });
  });
});
