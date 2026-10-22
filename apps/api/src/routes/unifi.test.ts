/**
 * The UniFi API (ADR 0022) against a throw-away PostgreSQL database on the development server: who may read and
 * change, which actions need a recent sign-in, validation (addresses, keys, the IPS user), that the API key and the
 * IPS password are only ever sealed, the certificate confirmation, the IPS preview settings, and the device list
 * with its filters and flags. Sessions are replaced by a header-driven actor; the queue is a recorder. Skipped
 * without the development PostgreSQL.
 */
import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const queue = vi.hoisted(() => ({
  sent: [] as { name: string; data: Record<string, unknown>; options: Record<string, unknown> }[],
  db: null as unknown,
  vault: null as null | { publicKeyPem: string; privateKeyPem: string },
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_unifi");
  queue.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: Record<string, unknown>, options: Record<string, unknown>) => {
        queue.sent.push({ name, data, options });
        return "job";
      },
    },
    QUEUES: { unifiCertificate: "unifi.certificate", unifiSync: "unifi.sync" },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: generate, loadVaultPublicKey } = await import("@garnetops/core/vault");
  queue.vault = generate();
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: loadVaultPublicKey(queue.vault.publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_uf_a";
const OTHER = "org_uf_b";
const STALE = 11 * 60;
// Made up at run time, so no fixture looks like a real credential.
const KEY = `${["fixture", "api", "key"].join("-")}-${"0123456789".repeat(3)}`;
const PASSWORD = `${["fixture", "ips", "password"].join(" ")} ${"9876543210".repeat(2)}`;
const FP_A = Array.from({ length: 32 }, (_, i) => (i + 16).toString(16).toUpperCase()).join(":");
const FP_B = Array.from({ length: 32 }, (_, i) => (i + 48).toString(16).toUpperCase()).join(":");
const DAY = 86_400_000;

describe.skipIf(!adminUrl)("UniFi API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; age?: number; body?: unknown } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": options.org ?? ORG,
      "x-age": String(options.age ?? 0),
      "x-ip": "198.51.100.7",
    };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // not JSON
    }
    return { status: res.status, json: json as Json | null, text };
  }
  const itemsOf = (r: { json: Json | null }): Json[] => (r.json?.items ?? []) as Json[];
  const problemCode = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const errorsOf = (r: { json: Json | null }): Json[] => (r.json?.errors ?? []) as Json[];
  const fieldCodes = (r: { json: Json | null }) =>
    Object.fromEntries(errorsOf(r).map((e) => [e.path as string, e.message as string]));
  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog)).filter((a) => a.action === action);

  const valid = (extra: Record<string, unknown> = {}) => ({
    name: `Console ${++counter}`,
    apiUrl: `https://udm${counter}.example.lan`,
    apiKey: KEY,
    ...extra,
  });

  async function addConnection(overrides: Partial<typeof schema.unifiConnection.$inferInsert> = {}) {
    const id = `ufc_apitest${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.unifiConnection).values({
      id,
      organizationId: ORG,
      name: `Seeded ${counter}`,
      apiUrl: `https://seeded${counter}.example.lan:443`,
      host: `seeded${counter}.example.lan`,
      port: 443,
      certStatus: "confirmed",
      certFingerprint: FP_A,
      apiBase: "unifi-os",
      ...overrides,
    });
    return id;
  }
  async function addSite(connectionId: string, name = "Main office", org = ORG) {
    const id = `ufs_apitest${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.unifiSite).values({
      id,
      organizationId: org,
      connectionId,
      unifiId: `0a1b2c3d-0000-4000-8000-${String(counter).padStart(12, "0")}`,
      name,
      internalRef: "default",
      clientCount: 12,
      lastSeenAt: new Date(),
    });
    return id;
  }
  async function addDevice(
    connectionId: string,
    siteId: string,
    name: string,
    overrides: Partial<typeof schema.unifiDevice.$inferInsert> = {},
    org = ORG,
  ) {
    const now = new Date();
    const id = `ufd_apitest${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.unifiDevice).values({
      id,
      organizationId: org,
      connectionId,
      siteId,
      unifiId: `0d0d0d0d-0000-4000-8000-${String(counter).padStart(12, "0")}`,
      name,
      model: "U7 Example",
      mac: `02:00:00:00:00:${String(counter % 100).padStart(2, "0")}`,
      ip: `192.0.2.${counter % 250}`,
      state: "online",
      rawState: "ONLINE",
      stateSince: new Date(now.getTime() - 3 * DAY),
      firmwareVersion: "6.7.1",
      firmwareUpdatable: false,
      firstSeenAt: now,
      lastSeenAt: now,
      ...overrides,
    });
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { unifiRoutes } = await import("./unifi.ts");
    t = queue.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values({ id: "user_a", name: "Erika", email: "erika@example.test" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: "user_a",
          email: "erika@example.test",
          name: "Erika",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: c.req.header("x-ip") ?? null,
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/unifi", unifiRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    queue.sent.length = 0;
    await t.pool.query("truncate unifi_connection, secret, audit_log, rate_limit restart identity cascade");
  });

  describe("who may do what", () => {
    const writes: [string, string, unknown][] = [
      ["POST", "/api/v1/unifi/connections", {}],
      ["PATCH", "/api/v1/unifi/connections/ufc_none", { name: "x" }],
      ["DELETE", "/api/v1/unifi/connections/ufc_none", undefined],
      ["POST", "/api/v1/unifi/connections/ufc_none/certificate/scan", undefined],
      ["POST", "/api/v1/unifi/connections/ufc_none/certificate/confirm", { fingerprint: FP_A }],
      ["POST", "/api/v1/unifi/connections/ufc_none/sync", undefined],
      ["PUT", "/api/v1/unifi/connections/ufc_none/ips", { enabled: false }],
      ["DELETE", "/api/v1/unifi/connections/ufc_none/ips", undefined],
    ];

    it("lets only owners and admins change anything", async () => {
      for (const role of ["member", "viewer"] as const) {
        for (const [method, path, body] of writes) {
          const r = await call(method, path, { role, ...(body !== undefined ? { body } : {}) });
          expect(r.status, `${role} ${method} ${path}`).toBe(403);
        }
      }
      for (const role of ["owner", "admin"] as const) {
        const r = await call("POST", "/api/v1/unifi/connections", { role, body: valid() });
        expect(r.status, role).toBe(201);
      }
    });

    it("lets everyone in the organisation read, and shows the IPS user name and the address only to admins", async () => {
      const id = await addConnection({ ipsEnabled: true, ipsUsername: "garnetops-view", ipsSecretId: null });
      for (const role of ["owner", "admin", "member", "viewer"] as const) {
        const list = await call("GET", "/api/v1/unifi/connections", { role });
        expect(list.status, role).toBe(200);
        const row = itemsOf(list)[0] as Json;
        expect(row.id).toBe(id);
        expect(row.ips.username).toBe(role === "owner" || role === "admin" ? "garnetops-view" : null);
        // Nothing secret is part of any answer.
        expect(list.text).not.toMatch(/secretId|ipsSecret|apiKey|"password"/i);
        expect((await call("GET", "/api/v1/unifi/devices", { role })).status).toBe(200);
        expect((await call("GET", "/api/v1/unifi/sites", { role })).status).toBe(200);
        expect((await call("GET", `/api/v1/unifi/connections/${id}/runs`, { role })).status).toBe(200);
      }
    });

    it("scopes everything to the organisation: another organisation's connection does not exist", async () => {
      const id = await addConnection({ organizationId: OTHER });
      for (const [method, path, body] of [
        ["PATCH", `/api/v1/unifi/connections/${id}`, { name: "x" }],
        ["DELETE", `/api/v1/unifi/connections/${id}`, undefined],
        ["POST", `/api/v1/unifi/connections/${id}/sync`, undefined],
        ["POST", `/api/v1/unifi/connections/${id}/certificate/scan`, undefined],
        ["PUT", `/api/v1/unifi/connections/${id}/ips`, { enabled: false }],
        ["GET", `/api/v1/unifi/connections/${id}/runs`, undefined],
      ] as const) {
        const r = await call(method, path, { ...(body !== undefined ? { body } : {}) });
        expect(r.status, `${method} ${path}`).toBe(404);
      }
      expect(itemsOf(await call("GET", "/api/v1/unifi/connections"))).toHaveLength(0);
      expect(itemsOf(await call("GET", "/api/v1/unifi/connections", { org: OTHER })).length).toBe(1);
    });
  });

  describe("adding a connection", () => {
    it("needs a recent sign-in, and does nothing before it", async () => {
      const r = await call("POST", "/api/v1/unifi/connections", { age: STALE, body: valid() });
      expect(r.status).toBe(403);
      expect(problemCode(r)).toBe("step-up-required");
      expect(await t.db.select().from(schema.unifiConnection)).toHaveLength(0);
      expect(await t.db.select().from(schema.secret)).toHaveLength(0);
    });

    it("seals the key for the worker, never stores or returns it, and queues the certificate read", async () => {
      const r = await call("POST", "/api/v1/unifi/connections", { body: valid({ name: "Main" }) });
      expect(r.status).toBe(201);
      const id = r.json?.id as string;
      const [row] = await t.db.select().from(schema.unifiConnection).where(eq(schema.unifiConnection.id, id));
      expect(row).toMatchObject({
        name: "Main",
        host: expect.stringMatching(/^udm\d+\.example\.lan$/),
        port: 443,
        apiBase: "auto",
        certStatus: "pending",
        enabled: true,
        ipsEnabled: false,
      });
      expect(row?.apiUrl).toMatch(/^https:\/\/udm\d+\.example\.lan:443$/);
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, row?.secretId as string));
      expect(secret).toMatchObject({ purpose: "unifi-api-key", organizationId: ORG });
      expect(JSON.stringify(secret?.sealed)).not.toContain(KEY);
      // The worker's key opens it, bound to organisation, record and purpose.
      const vault = loadVaultPrivateKey((queue.vault as { privateKeyPem: string }).privateKeyPem);
      const plain = open(
        secret?.sealed,
        { organizationId: ORG, recordId: secret?.id as string, purpose: "unifi-api-key" },
        vault,
      );
      expect(plain.toString("utf8")).toBe(KEY);
      expect(() =>
        open(
          secret?.sealed,
          { organizationId: ORG, recordId: secret?.id as string, purpose: "unifi-ips-password" },
          vault,
        ),
      ).toThrow();
      // Not in the answer, the list, the audit log, or the queue.
      expect(r.text).not.toContain(KEY);
      const list = await call("GET", "/api/v1/unifi/connections");
      expect(list.text).not.toContain(KEY);
      expect(list.json?.items[0]).toMatchObject({ hasKey: true });
      const audit = await audits("unifi.connection_created");
      expect(audit).toHaveLength(1);
      expect(JSON.stringify(audit[0]?.data)).not.toContain(KEY);
      expect(JSON.stringify(queue.sent)).not.toContain(KEY);
      expect(queue.sent).toEqual([
        {
          name: "unifi.certificate",
          data: { connectionId: id },
          options: expect.objectContaining({ singletonKey: id }),
        },
      ]);
    });

    it("validates the name, the address and the key, with codes the form can show", async () => {
      const bad = async (body: Record<string, unknown>) => {
        const r = await call("POST", "/api/v1/unifi/connections", { body: valid(body) });
        expect(r.status, JSON.stringify(body)).toBe(422);
        return fieldCodes(r);
      };
      expect(await bad({ name: "" })).toMatchObject({ name: "name_invalid" });
      expect(await bad({ apiUrl: "" })).toMatchObject({ apiUrl: "url_empty" });
      expect(await bad({ apiUrl: "http://udm.example.lan" })).toMatchObject({ apiUrl: "url_notHttps" });
      expect(await bad({ apiUrl: "https://u:p@udm.example.lan" })).toMatchObject({
        apiUrl: "url_credentials",
      });
      expect(await bad({ apiUrl: "https://udm.example.lan/proxy/network" })).toMatchObject({
        apiUrl: "url_path",
      });
      for (const host of ["127.0.0.1", "localhost", "[::1]", "169.254.169.254", "127.1"]) {
        expect(await bad({ apiUrl: `https://${host}` }), host).toMatchObject({ apiUrl: "url_address" });
      }
      expect(await bad({ apiKey: "short" })).toMatchObject({ apiKey: "key_invalid" });
      expect(await bad({ apiKey: `${KEY} with blank` })).toMatchObject({ apiKey: "key_invalid" });
      expect(
        (await call("POST", "/api/v1/unifi/connections", { body: valid({ apiBase: "cloud" }) })).status,
      ).toBe(422);
      expect(await t.db.select().from(schema.unifiConnection)).toHaveLength(0);
    });

    it("refuses duplicates and too many connections", async () => {
      const first = valid({ name: "One", apiUrl: "https://one.example.lan" });
      expect((await call("POST", "/api/v1/unifi/connections", { body: first })).status).toBe(201);
      for (const body of [
        valid({ name: "One" }),
        valid({ name: "Two", apiUrl: "https://one.example.lan:443/" }),
      ]) {
        const r = await call("POST", "/api/v1/unifi/connections", { body });
        expect(r.status).toBe(409);
        expect(problemCode(r)).toBe("duplicate");
      }
      for (let i = 0; i < 4; i++) {
        expect((await call("POST", "/api/v1/unifi/connections", { body: valid() })).status).toBe(201);
      }
      const r = await call("POST", "/api/v1/unifi/connections", { body: valid() });
      expect(r.status).toBe(409);
      expect(problemCode(r)).toBe("limit-reached");
    });
  });

  describe("changing a connection", () => {
    it("renames and switches on or off without a recent sign-in", async () => {
      const id = await addConnection();
      const r = await call("PATCH", `/api/v1/unifi/connections/${id}`, {
        age: STALE,
        body: { name: "Renamed", enabled: false, apiBase: "network-app" },
      });
      expect(r.status).toBe(204);
      const [row] = await t.db.select().from(schema.unifiConnection).where(eq(schema.unifiConnection.id, id));
      expect(row).toMatchObject({
        name: "Renamed",
        enabled: false,
        apiBase: "network-app",
        certStatus: "confirmed",
      });
      expect((await audits("unifi.connection_changed"))[0]?.data).toMatchObject({
        changed: ["name", "enabled", "apiBase"],
      });
    });

    it("needs a recent sign-in for a new address or key; a new address drops the pin and reads again", async () => {
      const id = await addConnection({ ipsEnabled: true, ipsUsername: "viewer-user" });
      expect(
        (
          await call("PATCH", `/api/v1/unifi/connections/${id}`, {
            age: STALE,
            body: { apiUrl: "https://new.example.lan" },
          })
        ).status,
      ).toBe(403);
      expect(
        (await call("PATCH", `/api/v1/unifi/connections/${id}`, { age: STALE, body: { apiKey: KEY } }))
          .status,
      ).toBe(403);
      expect(
        (
          await call("PATCH", `/api/v1/unifi/connections/${id}`, {
            body: { apiUrl: "https://new.example.lan:8443" },
          })
        ).status,
      ).toBe(204);
      const [row] = await t.db.select().from(schema.unifiConnection).where(eq(schema.unifiConnection.id, id));
      expect(row).toMatchObject({
        host: "new.example.lan",
        port: 8443,
        certStatus: "pending",
        certFingerprint: null,
      });
      expect(queue.sent.map((q) => q.name)).toEqual(["unifi.certificate"]);
    });

    it("replaces the key: the old secret goes, the new one is sealed, and a confirmed console syncs again", async () => {
      const created = await call("POST", "/api/v1/unifi/connections", { body: valid() });
      const id = created.json?.id as string;
      await t.db.update(schema.unifiConnection).set({ certStatus: "confirmed", certFingerprint: FP_A });
      const [before] = await t.db
        .select()
        .from(schema.unifiConnection)
        .where(eq(schema.unifiConnection.id, id));
      queue.sent.length = 0;
      const newKey = `${KEY}-rotated`;
      expect(
        (await call("PATCH", `/api/v1/unifi/connections/${id}`, { body: { apiKey: newKey } })).status,
      ).toBe(204);
      const [after] = await t.db
        .select()
        .from(schema.unifiConnection)
        .where(eq(schema.unifiConnection.id, id));
      expect(after?.secretId).not.toBe(before?.secretId);
      const secrets = await t.db.select().from(schema.secret);
      expect(secrets.map((s) => s.id)).toEqual([after?.secretId]);
      expect(JSON.stringify(secrets)).not.toContain(newKey);
      expect(queue.sent.map((q) => q.name)).toEqual(["unifi.sync"]);
      const audit = await audits("unifi.connection_changed");
      expect(JSON.stringify(audit)).not.toContain(newKey);
      expect(JSON.stringify(audit)).not.toContain(KEY);
    });

    it("removes a connection with its secrets, and needs a recent sign-in for it", async () => {
      const created = await call("POST", "/api/v1/unifi/connections", { body: valid() });
      const id = created.json?.id as string;
      expect((await call("DELETE", `/api/v1/unifi/connections/${id}`, { age: STALE })).status).toBe(403);
      expect((await call("DELETE", `/api/v1/unifi/connections/${id}`)).status).toBe(204);
      expect(await t.db.select().from(schema.unifiConnection)).toHaveLength(0);
      expect(await t.db.select().from(schema.secret)).toHaveLength(0);
      expect(await audits("unifi.connection_deleted")).toHaveLength(1);
    });
  });

  describe("the certificate", () => {
    const candidate = {
      candidateFingerprint: FP_B,
      candidateSubject: "CN=udm.example.lan",
      candidateIssuer: "CN=udm.example.lan",
      candidateCaTrusted: false,
      candidateSeenAt: new Date(),
    };

    it("pins exactly the fingerprint the admin compared, with a recent sign-in, and audits it", async () => {
      const id = await addConnection({ certStatus: "pending", certFingerprint: null, ...candidate });
      expect(
        (
          await call("POST", `/api/v1/unifi/connections/${id}/certificate/confirm`, {
            age: STALE,
            body: { fingerprint: FP_B },
          })
        ).status,
      ).toBe(403);
      // The fingerprint of a different certificate: refused, nothing pinned.
      const wrong = await call("POST", `/api/v1/unifi/connections/${id}/certificate/confirm`, {
        body: { fingerprint: FP_A },
      });
      expect(wrong.status).toBe(409);
      expect(problemCode(wrong)).toBe("fingerprint-mismatch");
      expect(
        (
          await call("POST", `/api/v1/unifi/connections/${id}/certificate/confirm`, {
            body: { fingerprint: "nonsense" },
          })
        ).status,
      ).toBe(422);
      expect(queue.sent).toEqual([]);

      const r = await call("POST", `/api/v1/unifi/connections/${id}/certificate/confirm`, {
        body: { fingerprint: FP_B.toLowerCase() },
      });
      expect(r.status).toBe(200);
      const [row] = await t.db.select().from(schema.unifiConnection).where(eq(schema.unifiConnection.id, id));
      expect(row).toMatchObject({
        certStatus: "confirmed",
        certFingerprint: FP_B,
        candidateFingerprint: null,
      });
      const audit = await audits("unifi.certificate_confirmed");
      expect(audit[0]?.data).toMatchObject({ fingerprint: FP_B, previous: null });
      // The first sync is queued, as a setup run.
      expect(queue.sent.map((q) => q.name)).toEqual(["unifi.sync"]);
      const [run] = await t.db.select().from(schema.unifiSyncRun);
      expect(run).toMatchObject({ trigger: "setup", state: "queued" });
    });

    it("has nothing to confirm without a candidate, and shows both certificates after a change", async () => {
      const none = await addConnection();
      const r = await call("POST", `/api/v1/unifi/connections/${none}/certificate/confirm`, {
        body: { fingerprint: FP_A },
      });
      expect(r.status).toBe(409);
      expect(problemCode(r)).toBe("no-certificate");
      const changed = await addConnection({ certStatus: "changed", ...candidate });
      const list = await call("GET", "/api/v1/unifi/connections");
      const row = itemsOf(list).find((i) => i.id === changed) as Json;
      expect(row.certificate).toMatchObject({
        status: "changed",
        fingerprint: FP_A,
        candidate: { fingerprint: FP_B },
      });
    });

    it("syncs only after the certificate is confirmed, and never queues two runs at once", async () => {
      const pending = await addConnection({ certStatus: "pending", certFingerprint: null });
      const refused = await call("POST", `/api/v1/unifi/connections/${pending}/sync`);
      expect(refused.status).toBe(409);
      expect(problemCode(refused)).toBe("certificate-unconfirmed");
      const id = await addConnection();
      const first = await call("POST", `/api/v1/unifi/connections/${id}/sync`);
      expect(first.status).toBe(202);
      const second = await call("POST", `/api/v1/unifi/connections/${id}/sync`);
      expect(second.status).toBe(200);
      expect(second.json?.alreadyQueued).toBe(true);
      expect(queue.sent.filter((q) => q.name === "unifi.sync")).toHaveLength(1);
      expect(queue.sent[0]?.options).toMatchObject({ retryLimit: 0, singletonKey: id });
    });
  });

  describe("the IPS preview", () => {
    const put = (id: string, body: Record<string, unknown>, options: { age?: number; role?: Role } = {}) =>
      call("PUT", `/api/v1/unifi/connections/${id}/ips`, { body, ...options });

    it("is off by default and says so", async () => {
      await addConnection();
      const row = itemsOf(await call("GET", "/api/v1/unifi/connections"))[0] as Json;
      expect(row.ips).toMatchObject({
        enabled: false,
        state: "off",
        hasPassword: false,
        rights: { reported: [], acknowledged: true, acknowledgedAt: null },
      });
    });

    it("needs the acknowledgement, a user and a password, and refuses administrator names", async () => {
      const id = await addConnection();
      const attempt = async (body: Record<string, unknown>) => {
        const r = await put(id, body);
        expect(r.status, JSON.stringify(body)).toBe(422);
        return fieldCodes(r);
      };
      expect(await attempt({ enabled: true })).toMatchObject({
        acknowledgePreview: "preview_not_acknowledged",
        username: "username_missing",
        password: "password_missing",
      });
      expect(
        await attempt({ enabled: true, acknowledgePreview: true, username: "admin", password: PASSWORD }),
      ).toMatchObject({
        username: "username_forbidden",
      });
      for (const name of ["root", "ubnt", "Administrator", "owner", "unifi", "admin@example.com"]) {
        expect(await attempt({ username: name }), name).toMatchObject({ username: "username_forbidden" });
      }
      expect(await attempt({ username: "bad name" })).toMatchObject({ username: "username_invalid" });
      expect(await attempt({ username: "viewer-user", password: "short" })).toMatchObject({
        password: "password_invalid",
      });
      expect(await attempt({ intervalSeconds: 5 })).toMatchObject({ intervalSeconds: "interval_invalid" });
      expect(await attempt({ intervalSeconds: 601 })).toMatchObject({ intervalSeconds: "interval_invalid" });
      expect(await t.db.select().from(schema.secret)).toHaveLength(0);
      const [row] = await t.db.select().from(schema.unifiConnection);
      expect(row?.ipsEnabled).toBe(false);
    });

    it("needs a recent sign-in to switch on or to change who logs in; switching off needs none", async () => {
      const id = await addConnection();
      const on = {
        enabled: true,
        acknowledgePreview: true,
        username: "garnetops-view",
        password: PASSWORD,
        intervalSeconds: 90,
      };
      const stale = await put(id, on, { age: STALE });
      expect(stale.status).toBe(403);
      expect(problemCode(stale)).toBe("step-up-required");
      expect((await t.db.select().from(schema.unifiConnection))[0]?.ipsEnabled).toBe(false);

      expect((await put(id, on)).status).toBe(204);
      const [row] = await t.db.select().from(schema.unifiConnection);
      expect(row).toMatchObject({
        ipsEnabled: true,
        ipsUsername: "garnetops-view",
        ipsIntervalSeconds: 90,
        ipsEnabledBy: "user_a",
        ipsFailures: 0,
      });
      expect(row?.ipsEnabledAt).not.toBeNull();

      expect((await put(id, { password: PASSWORD }, { age: STALE })).status).toBe(403);
      expect((await put(id, { username: "other-view" }, { age: STALE })).status).toBe(403);
      expect((await put(id, { intervalSeconds: 120 }, { age: STALE })).status).toBe(204);
      expect((await put(id, { enabled: false }, { age: STALE })).status).toBe(204);
      expect((await t.db.select().from(schema.unifiConnection))[0]).toMatchObject({
        ipsEnabled: false,
        ipsIntervalSeconds: 120,
        ipsUsername: "garnetops-view",
      });
    });

    it("seals the password for the worker, and it is in no answer, audit entry or queue message", async () => {
      const id = await addConnection();
      const r = await put(id, {
        enabled: true,
        acknowledgePreview: true,
        username: "garnetops-view",
        password: PASSWORD,
      });
      expect(r.status).toBe(204);
      const [row] = await t.db.select().from(schema.unifiConnection);
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, row?.ipsSecretId as string));
      expect(secret?.purpose).toBe("unifi-ips-password");
      const vault = loadVaultPrivateKey((queue.vault as { privateKeyPem: string }).privateKeyPem);
      expect(
        open(
          secret?.sealed,
          { organizationId: ORG, recordId: secret?.id as string, purpose: "unifi-ips-password" },
          vault,
        ).toString("utf8"),
      ).toBe(PASSWORD);
      const list = await call("GET", "/api/v1/unifi/connections");
      expect(list.text).not.toContain(PASSWORD);
      expect(list.json?.items[0].ips).toMatchObject({
        enabled: true,
        hasPassword: true,
        username: "garnetops-view",
      });
      const audit = await audits("unifi.ips_changed");
      expect(audit).toHaveLength(1);
      expect(audit[0]?.data).toMatchObject({
        changed: expect.arrayContaining(["enabled", "username", "password"]),
        user: "garnetops-view",
      });
      expect(JSON.stringify(audit)).not.toContain(PASSWORD);

      // A new password replaces the secret, and voids the reported rights and their acknowledgement.
      await t.db.update(schema.unifiConnection).set({
        ipsRights: ["owner"],
        ipsRightsAcknowledged: ["owner"],
        ipsRightsAcknowledgedAt: new Date(),
        ipsFailures: 4,
        ipsLastError: "x",
      });
      expect((await put(id, { password: `${PASSWORD}2` })).status).toBe(204);
      const [next] = await t.db.select().from(schema.unifiConnection);
      expect(next).toMatchObject({
        ipsRights: [],
        ipsRightsAcknowledged: [],
        ipsRightsAcknowledgedAt: null,
        ipsFailures: 0,
        ipsLastError: null,
      });
      expect(next?.ipsSecretId).not.toBe(row?.ipsSecretId);
      expect(await t.db.select().from(schema.secret)).toHaveLength(1);
    });

    it("reports the state: paused until the certificate is confirmed and a sync has run", async () => {
      const id = await addConnection({ certStatus: "pending", certFingerprint: null, apiBase: "auto" });
      await put(id, {
        enabled: true,
        acknowledgePreview: true,
        username: "garnetops-view",
        password: PASSWORD,
      });
      const state = async () => (await call("GET", "/api/v1/unifi/connections")).json?.items[0].ips as Json;
      expect(await state()).toMatchObject({ state: "paused", reason: "certificate" });
      await t.db.update(schema.unifiConnection).set({ certStatus: "confirmed", certFingerprint: FP_A });
      expect(await state()).toMatchObject({ state: "paused", reason: "no-sync" });
      await t.db.update(schema.unifiConnection).set({ apiBase: "unifi-os", lastSyncAt: new Date() });
      expect(await state()).toMatchObject({ state: "waiting" });
      await t.db
        .update(schema.unifiConnection)
        .set({ ipsLastPollAt: new Date(), ipsLastEventAt: new Date() });
      expect(await state()).toMatchObject({ state: "live" });
      // Rights beyond viewing that nobody acknowledged: paused, whatever else is fine.
      await t.db.update(schema.unifiConnection).set({ ipsRights: ["owner"] });
      expect(await state()).toMatchObject({
        state: "paused",
        reason: "rights",
        rights: { reported: ["owner"], acknowledged: false },
      });
      await t.db.update(schema.unifiConnection).set({ ipsRightsAcknowledged: ["role: x"] });
      expect(await state()).toMatchObject({ state: "paused", reason: "rights" });
      await t.db
        .update(schema.unifiConnection)
        .set({ ipsRightsAcknowledged: ["owner"], ipsRightsAcknowledgedAt: new Date() });
      expect(await state()).toMatchObject({ state: "live", rights: { acknowledged: true } });
      await t.db.update(schema.unifiConnection).set({ enabled: false });
      expect(await state()).toMatchObject({ state: "paused", reason: "disabled" });
    });

    describe("acknowledging rights beyond viewing", () => {
      const ack = (id: string, rights: string[], options: { age?: number; role?: Role } = {}) =>
        call("POST", `/api/v1/unifi/connections/${id}/ips/rights/acknowledge`, {
          body: { rights },
          ...options,
        });
      const RIGHTS = ["role: Super Admin", "super_admin"];
      async function withRights() {
        const id = await addConnection();
        await put(id, {
          enabled: true,
          acknowledgePreview: true,
          username: "garnetops-view",
          password: PASSWORD,
        });
        await t.db.update(schema.unifiConnection).set({
          certStatus: "confirmed",
          certFingerprint: FP_A,
          apiBase: "unifi-os",
          lastSyncAt: new Date(),
        });
        await t.db.update(schema.unifiConnection).set({ ipsRights: RIGHTS });
        return id;
      }

      it("acknowledges exactly the list that was shown, audits it and starts the poll", async () => {
        const id = await withRights();
        await t.db.update(schema.unifiConnection).set({ ipsNextPollAt: new Date(Date.now() + 600_000) });
        const r = await ack(id, [...RIGHTS].reverse());
        expect(r.status).toBe(204);
        const [row] = await t.db.select().from(schema.unifiConnection);
        expect(row).toMatchObject({
          ipsRightsAcknowledged: RIGHTS,
          ipsRightsAcknowledgedBy: "user_a",
        });
        expect(row?.ipsRightsAcknowledgedAt).toBeInstanceOf(Date);
        expect(row?.ipsNextPollAt.getTime()).toBeLessThanOrEqual(Date.now() + 1000);
        const audit = await audits("unifi.ips_rights_acknowledged");
        expect(audit).toHaveLength(1);
        expect(audit[0]?.data).toMatchObject({ user: "garnetops-view", rights: RIGHTS });
        const state = (await call("GET", "/api/v1/unifi/connections")).json?.items[0].ips as Json;
        expect(state.rights).toMatchObject({ reported: RIGHTS, acknowledged: true });
        expect(state.state).not.toBe("paused");
      });

      it("refuses a list that differs from the reported one, and an acknowledgement with nothing to acknowledge", async () => {
        const id = await withRights();
        for (const rights of [[], ["super_admin"], [...RIGHTS, "owner"], ["owner"]]) {
          const r = await ack(id, rights);
          expect(r.status, JSON.stringify(rights)).toBe(409);
          expect(problemCode(r)).toBe("rights-changed");
        }
        expect(await audits("unifi.ips_rights_acknowledged")).toHaveLength(0);
        await t.db.update(schema.unifiConnection).set({ ipsRights: [] });
        const none = await ack(id, RIGHTS);
        expect(none.status).toBe(409);
        expect(problemCode(none)).toBe("no-extra-rights");
        const [row] = await t.db.select().from(schema.unifiConnection);
        expect(row?.ipsRightsAcknowledged).toEqual([]);
      });

      it("needs an admin and a recent sign-in, and does nothing before it", async () => {
        const id = await withRights();
        const stale = await ack(id, RIGHTS, { age: STALE });
        expect(stale.status).toBe(403);
        expect(problemCode(stale)).toBe("step-up-required");
        const member = await ack(id, RIGHTS, { role: "member" });
        expect(member.status).toBe(403);
        const [row] = await t.db.select().from(schema.unifiConnection);
        expect(row?.ipsRightsAcknowledged).toEqual([]);
        expect(await audits("unifi.ips_rights_acknowledged")).toHaveLength(0);
      });

      it("answers 404 for an unknown connection and changes nothing", async () => {
        const id = await withRights();
        const r = await ack("00000000-0000-4000-8000-000000000000", RIGHTS);
        expect(r.status).toBe(404);
        const [row] = await t.db
          .select()
          .from(schema.unifiConnection)
          .where(eq(schema.unifiConnection.id, id));
        expect(row?.ipsRightsAcknowledged).toEqual([]);
      });

      it("voids reported rights and their acknowledgement when the user is replaced or removed", async () => {
        const id = await withRights();
        await ack(id, RIGHTS);
        expect((await put(id, { username: "another-view-user", password: `${PASSWORD}3` })).status).toBe(204);
        let [row] = await t.db.select().from(schema.unifiConnection);
        expect(row).toMatchObject({
          ipsRights: [],
          ipsRightsAcknowledged: [],
          ipsRightsAcknowledgedAt: null,
          ipsRightsAcknowledgedBy: null,
        });
        await t.db.update(schema.unifiConnection).set({ ipsRights: RIGHTS, ipsRightsAcknowledged: RIGHTS });
        expect((await call("DELETE", `/api/v1/unifi/connections/${id}/ips`)).status).toBe(204);
        [row] = await t.db.select().from(schema.unifiConnection);
        expect(row).toMatchObject({ ipsRights: [], ipsRightsAcknowledged: [] });
      });
    });

    it("removes the user and the password without a recent sign-in", async () => {
      const id = await addConnection();
      await put(id, {
        enabled: true,
        acknowledgePreview: true,
        username: "garnetops-view",
        password: PASSWORD,
      });
      const r = await call("DELETE", `/api/v1/unifi/connections/${id}/ips`, { age: STALE });
      expect(r.status).toBe(204);
      const [row] = await t.db.select().from(schema.unifiConnection);
      expect(row).toMatchObject({ ipsEnabled: false, ipsUsername: null, ipsSecretId: null });
      expect(await t.db.select().from(schema.secret)).toHaveLength(0);
      expect(await audits("unifi.ips_removed")).toHaveLength(1);
    });
  });

  describe("devices", () => {
    async function seed() {
      const connection = await addConnection({ name: "Main console" });
      const main = await addSite(connection, "Main office");
      const branch = await addSite(connection, "Branch");
      await addDevice(connection, main, "gateway", {
        model: "UCG Example",
        firmwareVersion: "4.0.6",
        firmwareUpdatable: true,
        uptimeSec: 864000,
        ip: "192.0.2.1",
      });
      await addDevice(connection, main, "switch-1", {
        model: "USW Example",
        firmwareVersion: "7.1.26",
        firmwareUpdatable: false,
        uptimeSec: 100,
        ip: "192.0.2.2",
      });
      await addDevice(connection, main, "ap-hall", {
        state: "offline",
        rawState: "OFFLINE",
        firmwareUpdatable: true,
        ip: "192.0.2.3",
      });
      await addDevice(connection, branch, "ap-branch", {
        state: "other",
        rawState: "PENDING_ADOPTION",
        firmwareUpdatable: null,
        ip: null,
      });
      return { connection, main, branch };
    }
    const names = (r: { json: Json | null }) => ((r.json?.items ?? []) as Json[]).map((i) => i.name);

    it("lists devices with their flags and firmware status, never calling one vulnerable", async () => {
      await seed();
      const r = await call("GET", "/api/v1/unifi/devices", { role: "viewer" });
      expect(names(r)).toEqual(["ap-branch", "ap-hall", "gateway", "switch-1"]);
      expect(r.json?.total).toBe(4);
      const byName = Object.fromEntries(itemsOf(r).map((i) => [i.name, i]));
      expect(byName.gateway).toMatchObject({
        firmware: "updateAvailable",
        flags: ["updateAvailable"],
        connectionName: "Main console",
        siteName: "Main office",
      });
      expect(byName["ap-hall"]).toMatchObject({ state: "offline", flags: ["offline", "updateAvailable"] });
      expect(byName["switch-1"]).toMatchObject({ firmware: "current", flags: [] });
      expect(byName["ap-branch"]).toMatchObject({ state: "other", firmware: "unknown", flags: [], ip: null });
      expect(r.text).not.toMatch(/vulnerab/i);
    });

    it("filters by text, flag, state and site, and counts per flag", async () => {
      const { main } = await seed();
      expect(names(await call("GET", "/api/v1/unifi/devices?q=ucg"))).toEqual(["gateway"]);
      expect(names(await call("GET", "/api/v1/unifi/devices?q=192.0.2.2"))).toEqual(["switch-1"]);
      expect(names(await call("GET", "/api/v1/unifi/devices?q=4.0.6"))).toEqual(["gateway"]);
      expect(names(await call("GET", "/api/v1/unifi/devices?flag=offline"))).toEqual(["ap-hall"]);
      expect(names(await call("GET", "/api/v1/unifi/devices?flag=update"))).toEqual(["ap-hall", "gateway"]);
      expect(names(await call("GET", "/api/v1/unifi/devices?state=other"))).toEqual(["ap-branch"]);
      expect(names(await call("GET", `/api/v1/unifi/devices?site=${main}`))).toEqual([
        "ap-hall",
        "gateway",
        "switch-1",
      ]);
      expect((await call("GET", "/api/v1/unifi/devices/counts")).json).toEqual({
        all: 4,
        offline: 1,
        update: 2,
      });
      expect((await call("GET", "/api/v1/unifi/devices/counts?q=gateway")).json).toEqual({
        all: 1,
        offline: 0,
        update: 1,
      });
      // A percent sign is text, not a wildcard.
      expect(names(await call("GET", "/api/v1/unifi/devices?q=%25"))).toEqual([]);
      expect((await call("GET", "/api/v1/unifi/devices?flag=vulnerable")).status).toBe(422);
    });

    it("sorts by every column, in both directions, and pages with a cursor", async () => {
      await seed();
      for (const sort of ["name", "model", "site", "state", "ip", "firmware", "uptime", "lastSeen"]) {
        for (const dir of ["asc", "desc"]) {
          const r = await call("GET", `/api/v1/unifi/devices?sort=${sort}&dir=${dir}`);
          expect(r.status, `${sort} ${dir}`).toBe(200);
          expect(names(r)).toHaveLength(4);
        }
      }
      expect(names(await call("GET", "/api/v1/unifi/devices?sort=uptime"))[0]).toBe("gateway");
      expect((await call("GET", "/api/v1/unifi/devices?sort=password")).status).toBe(422);
    });

    it("pages with a cursor, in a stable order", async () => {
      const connection = await addConnection();
      const site = await addSite(connection);
      for (let i = 0; i < 30; i++) await addDevice(connection, site, `device-${String(i).padStart(2, "0")}`);
      const first = await call("GET", "/api/v1/unifi/devices?sort=name");
      expect(names(first)).toHaveLength(25);
      expect(first.json).toMatchObject({ total: 30, pageSize: 25 });
      expect(first.json?.next).toBeTruthy();
      const second = await call(
        "GET",
        `/api/v1/unifi/devices?sort=name&cursor=${encodeURIComponent(first.json?.next)}`,
      );
      expect(names(second)).toEqual(["device-25", "device-26", "device-27", "device-28", "device-29"]);
      expect(second.json?.next).toBeNull();
      expect(second.json?.prev).toBeTruthy();
      expect((await call("GET", "/api/v1/unifi/devices?pageSize=7")).status).toBe(422);
      expect((await call("GET", "/api/v1/unifi/devices?cursor=garbage")).status).toBe(400);
    });

    it("shows one device, and nothing of another organisation", async () => {
      const { connection, main } = await seed();
      const other = await addConnection({ organizationId: OTHER, name: "Theirs" });
      const otherSite = await addSite(other, "Theirs", OTHER);
      const secret = await addDevice(other, otherSite, "foreign-ap", {}, OTHER);
      const list = await call("GET", "/api/v1/unifi/devices");
      expect(names(list)).not.toContain("foreign-ap");
      const id = itemsOf(list)[0]?.id;
      const one = await call("GET", `/api/v1/unifi/devices/${id}`);
      expect(one.status).toBe(200);
      expect(one.json).toMatchObject({ id, mac: expect.stringMatching(/^02:00:00:00:00:/) });
      expect((await call("GET", `/api/v1/unifi/devices/${secret}`)).status).toBe(404);
      expect((await call("GET", "/api/v1/unifi/devices/ufd_none")).status).toBe(404);
      const sites = await call("GET", "/api/v1/unifi/sites");
      expect((sites.json as unknown as Json[]).map((s) => s.name).sort()).toEqual(["Branch", "Main office"]);
      expect(connection && main).toBeTruthy();
    });

    it("counts online devices, updates, sites and clients per connection", async () => {
      await seed();
      const row = itemsOf(await call("GET", "/api/v1/unifi/connections"))[0] as Json;
      expect(row.counts).toEqual({ sites: 2, clients: 24, devices: 4, online: 2, offline: 1, updatable: 2 });
    });
  });
});
