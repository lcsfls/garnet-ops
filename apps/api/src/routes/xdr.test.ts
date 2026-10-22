/**
 * The Wazuh / XDR API (ADR 0015) against a throw-away PostgreSQL database on the development
 * server: who may read and change, which actions need a recent sign-in, validation, that the two
 * passwords are only ever sealed, the certificate and privilege confirmations, the page data and
 * agent list, linking agents and servers, the AI summary request and the enrollment helper.
 * Sessions are replaced by a header-driven actor; the queue is a recorder. Skipped without the
 * development PostgreSQL.
 */

import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { wazuhSourceRef } from "@garnetops/core/wazuh";
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
  const t = await create(target, "api_xdr");
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
    QUEUES: {
      hostAccessKey: "host.access-key",
      hostKeyscan: "host.keyscan",
      hostInventory: "host.inventory",
      xdrCertificate: "xdr.certificate",
      xdrSync: "xdr.sync",
      xdrSummary: "xdr.summary",
    },
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
const ORG = "org_xdr_a";
const OTHER = "org_xdr_b";
const STALE = 11 * 60;
const MANAGER_PASSWORD = "manager password for api tests 31";
const INDEXER_PASSWORD = "indexer password for api tests 32";
const FP_A = Array.from({ length: 32 }, (_, i) => (i + 16).toString(16).toUpperCase()).join(":");
const FP_B = Array.from({ length: 32 }, (_, i) => (i + 48).toString(16).toUpperCase()).join(":");
const SNAPSHOT = {
  windows: {
    "24h": {
      readAt: "2026-10-21T08:00:00.000Z",
      total: 300,
      bySeverity: { critical: 2, high: 8, medium: 40, low: 250 },
      previous: { total: 200, bySeverity: { critical: 1, high: 8, medium: 30, low: 161 } },
      tactics: [{ name: "Credential Access", count: 30 }],
      agents: [{ agentId: "001", name: "web-01", count: 120 }],
      fim: 4,
    },
  },
  vulnerabilities: {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    agentsAffected: 2,
    readAt: "2026-10-21T08:00:00.000Z",
  },
};

describe.skipIf(!adminUrl)("Wazuh API", () => {
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
  /** The `items` of a list answer, or an empty list. */
  const itemsOf = (r: { json: Json | null }): Json[] => (r.json?.items ?? []) as Json[];
  const problemCode = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();

  const valid = (extra: Record<string, unknown> = {}) => ({
    name: "Main lab",
    managerApiUrl: "https://wazuh-api.example.lan",
    managerUsername: "garnetops-api",
    managerPassword: MANAGER_PASSWORD,
    indexerApiUrl: "https://wazuh-idx.example.lan",
    indexerUsername: "garnetops-idx",
    indexerPassword: INDEXER_PASSWORD,
    ...extra,
  });

  /** A connection as the sync would have left it. */
  async function seed(
    options: {
      org?: string;
      connection?: Partial<typeof schema.wazuhConnection.$inferInsert>;
      manager?: Partial<typeof schema.wazuhEndpoint.$inferInsert>;
      indexer?: Partial<typeof schema.wazuhEndpoint.$inferInsert>;
      snapshot?: boolean;
    } = {},
  ) {
    const org = options.org ?? ORG;
    const n = ++counter;
    const id = `wzc_apitest${String(n).padStart(9, "0")}`;
    await t.db.insert(schema.wazuhConnection).values({
      id,
      organizationId: org,
      name: "Seeded lab",
      adapter: "wazuh4",
      managerVersion: "4.12.0",
      indexerVersion: "7.10.2",
      lastSyncAt: new Date(),
      ...options.connection,
    });
    const ids: Record<"manager" | "indexer", string> = {
      manager: `wze_m${id.slice(-9)}`,
      indexer: `wze_i${id.slice(-9)}`,
    };
    await t.db.insert(schema.wazuhEndpoint).values([
      {
        id: ids.manager,
        organizationId: org,
        connectionId: id,
        kind: "manager",
        apiUrl: "https://seeded-api.example.lan:55000",
        host: "seeded-api.example.lan",
        port: 55000,
        username: "garnetops-api",
        certStatus: "confirmed",
        certFingerprint: FP_A,
        ...options.manager,
      },
      {
        id: ids.indexer,
        organizationId: org,
        connectionId: id,
        kind: "indexer",
        apiUrl: "https://seeded-idx.example.lan:9200",
        host: "seeded-idx.example.lan",
        port: 9200,
        username: "garnetops-idx",
        certStatus: "confirmed",
        certFingerprint: FP_A,
        ...options.indexer,
      },
    ]);
    if (options.snapshot !== false) {
      await t.db
        .insert(schema.wazuhSnapshot)
        .values({ connectionId: id, organizationId: org, data: SNAPSHOT, syncedAt: new Date() });
    }
    return { id, ...ids };
  }

  async function addAgent(
    connectionId: string,
    agentId: string,
    over: Partial<typeof schema.wazuhAgent.$inferInsert> = {},
    org = ORG,
  ) {
    const now = new Date();
    const id = `wza_api${connectionId.slice(-6)}${agentId}`;
    await t.db.insert(schema.wazuhAgent).values({
      id,
      organizationId: org,
      connectionId,
      agentId,
      name: `agent-${agentId}`,
      ip: `192.0.2.${Number(agentId) + 10}`,
      status: "active",
      groups: ["default"],
      firstSeenAt: now,
      lastSeenAt: now,
      ...over,
    });
    return id;
  }
  async function addHost(name: string, address: string, org = ORG) {
    const id = `host_xdr${String(++counter).padStart(8, "0")}`;
    await t.db.insert(schema.host).values({ id, organizationId: org, name, address });
    return id;
  }
  /** A throw-away certificate authority in PEM form. */
  async function makeCa() {
    const { execFileSync } = await import("node:child_process");
    const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "garnetops-xdr-ca-"));
    try {
      execFileSync(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:prime256v1",
          "-nodes",
          "-days",
          "1",
          "-subj",
          "/CN=Example Root CA/O=Example",
          "-keyout",
          join(dir, "k.pem"),
          "-out",
          join(dir, "c.pem"),
        ],
        { stdio: "ignore" },
      );
      return { pem: readFileSync(join(dir, "c.pem"), "utf8"), key: readFileSync(join(dir, "k.pem"), "utf8") };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  const connectionRow = async (id: string) =>
    (await t.db.select().from(schema.wazuhConnection).where(eq(schema.wazuhConnection.id, id)))[0];
  const endpointRow = async (id: string) =>
    (await t.db.select().from(schema.wazuhEndpoint).where(eq(schema.wazuhEndpoint.id, id)))[0];

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { xdrRoutes } = await import("./xdr.ts");
    const { hostRoutes } = await import("./hosts.ts");
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
    v1.route("/xdr", xdrRoutes as never);
    v1.route("/hosts", hostRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    queue.sent.length = 0;
    await t.db.delete(schema.wazuhConnection);
    await t.db.delete(schema.host);
    await t.db.delete(schema.secret);
    await t.db.delete(schema.aiSettings);
    await t.db.delete(schema.auditLog);
  });

  describe("who may do what", () => {
    const writes: [string, string, unknown][] = [
      ["POST", "/api/v1/xdr/connection", {}],
      ["PATCH", "/api/v1/xdr/connection", { name: "x" }],
      ["DELETE", "/api/v1/xdr/connection", undefined],
      ["POST", "/api/v1/xdr/endpoints/manager/certificate/scan", undefined],
      ["POST", "/api/v1/xdr/endpoints/indexer/certificate/confirm", { fingerprint: FP_A }],
      ["POST", "/api/v1/xdr/privileges/acknowledge", { privileges: ["api:agent:restart"] }],
      ["POST", "/api/v1/xdr/sync", undefined],
      ["POST", "/api/v1/xdr/agents/wza_none/link", { hostId: "host_none" }],
      ["DELETE", "/api/v1/xdr/agents/wza_none/link", undefined],
    ];

    it("lets every member of the organisation read, and shows addresses and user names to admins only", async () => {
      const c = await seed();
      await addAgent(c.id, "001");
      for (const role of ["viewer", "member", "admin", "owner"] as Role[]) {
        for (const path of [
          "status",
          "connection",
          "overview",
          "agents",
          "agents/counts",
          "runs",
          "summary",
        ]) {
          expect((await call("GET", `/api/v1/xdr/${path}`, { role })).status, `${role} ${path}`).toBe(200);
        }
        const r = await call("GET", "/api/v1/xdr/connection", { role });
        const connection = (r.json as Json).connection as Json;
        const manager = (connection.endpoints as Json[])[0] as Json;
        const admin = role === "admin" || role === "owner";
        expect(manager.apiUrl, role).toBe(admin ? "https://seeded-api.example.lan:55000" : undefined);
        expect(manager.username, role).toBe(admin ? "garnetops-api" : undefined);
        expect(manager.certificate.status).toBe("confirmed");
        expect(manager.certificate.fingerprint, role).toBe(admin ? FP_A : undefined);
        expect(connection.enrollmentHost, role).toBe(admin ? null : undefined);
        expect(r.text).not.toContain("secretId");
        expect(r.text).not.toContain("caPem");
      }
    });

    it("lets only owners and admins change anything", async () => {
      for (const role of ["viewer", "member"] as Role[]) {
        for (const [method, path, body] of writes) {
          const r = await call(method, path, { role, body });
          expect(r.status, `${role} ${method} ${path}`).toBe(403);
          expect(problemCode(r)).toBe("forbidden");
        }
      }
      expect(queue.sent).toEqual([]);
      const r = await call("POST", "/api/v1/xdr/connection", { role: "owner", body: valid() });
      expect(r.status).toBe(201);
    });

    it("keeps organisations apart", async () => {
      const c = await seed();
      const agent = await addAgent(c.id, "001");
      const host = await addHost("someone", "192.0.2.9", OTHER);
      for (const [method, path, body] of [
        ["GET", "/api/v1/xdr/runs", undefined],
        ["PATCH", "/api/v1/xdr/connection", { name: "x" }],
        ["DELETE", "/api/v1/xdr/connection", undefined],
        ["POST", "/api/v1/xdr/endpoints/manager/certificate/scan", undefined],
        ["POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", { fingerprint: FP_A }],
        ["POST", "/api/v1/xdr/privileges/acknowledge", { privileges: ["x"] }],
        ["POST", "/api/v1/xdr/sync", undefined],
        ["POST", `/api/v1/xdr/agents/${agent}/link`, { hostId: host }],
        ["DELETE", `/api/v1/xdr/agents/${agent}/link`, undefined],
        ["GET", "/api/v1/xdr/enrollment?os=debian", undefined],
        ["POST", "/api/v1/xdr/summary", {}],
      ] as [string, string, unknown][]) {
        expect((await call(method, path, { org: OTHER, body })).status, `${method} ${path}`).toBe(404);
      }
      expect((await call("GET", "/api/v1/xdr/status", { org: OTHER })).json).toEqual({ connected: false });
      expect((await call("GET", "/api/v1/xdr/status")).json).toEqual({ connected: true });
      expect((await call("GET", "/api/v1/xdr/connection", { org: OTHER })).json?.connection).toBeNull();
      expect((await call("GET", "/api/v1/xdr/overview", { org: OTHER })).json).toEqual({ connection: null });
      expect((await call("GET", "/api/v1/xdr/agents", { org: OTHER })).json?.items).toEqual([]);
      // A server of another organisation cannot be linked.
      const foreign = await call("POST", `/api/v1/xdr/agents/${agent}/link`, { body: { hostId: host } });
      expect([foreign.status, foreign.json?.errors]).toEqual([
        422,
        [{ path: "hostId", message: "host_unknown" }],
      ]);
    });
  });

  describe("recent sign-in (step-up)", () => {
    it("is needed to add, re-point, change a password, upload an authority, change shown addresses, remove, confirm and acknowledge - not to look, rename or switch off", async () => {
      const ca = await makeCa();
      const c = await seed({
        manager: { candidateFingerprint: FP_B, trustMode: "ca", caPem: ca.pem },
        connection: { extraPrivileges: ["api:agent:restart"] },
      });
      const stale = { age: STALE };
      const expectStepUp = async (method: string, path: string, body?: unknown) => {
        const r = await call(method, path, { ...stale, body });
        expect([r.status, problemCode(r)], `${method} ${path}`).toEqual([403, "step-up-required"]);
        expect(r.json?.maxAgeSeconds).toBe(600);
      };
      await expectStepUp("POST", "/api/v1/xdr/connection", valid());
      await expectStepUp("PATCH", "/api/v1/xdr/connection", { managerApiUrl: "https://other.example.lan" });
      await expectStepUp("PATCH", "/api/v1/xdr/connection", {
        indexerUsername: "other-user",
        indexerPassword: INDEXER_PASSWORD,
      });
      await expectStepUp("PATCH", "/api/v1/xdr/connection", { managerCaPem: null });
      await expectStepUp("PATCH", "/api/v1/xdr/connection", { indexerCaPem: ca.pem });
      await expectStepUp("PATCH", "/api/v1/xdr/connection", {
        dashboardUrl: "https://dashboard.example.lan",
      });
      await expectStepUp("PATCH", "/api/v1/xdr/connection", { enrollmentHost: "wazuh.example.lan" });
      await expectStepUp("DELETE", "/api/v1/xdr/connection");
      await expectStepUp("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", { fingerprint: FP_B });
      await expectStepUp("POST", "/api/v1/xdr/privileges/acknowledge", { privileges: ["api:agent:restart"] });
      // Nothing happened.
      expect(await endpointRow(c.manager)).toMatchObject({
        certFingerprint: FP_A,
        candidateFingerprint: FP_B,
        trustMode: "ca",
      });
      expect((await connectionRow(c.id))?.acknowledgedPrivileges).toEqual([]);
      expect(queue.sent).toEqual([]);

      expect((await call("GET", "/api/v1/xdr/connection", stale)).status).toBe(200);
      expect(
        (await call("PATCH", "/api/v1/xdr/connection", { ...stale, body: { name: "Renamed" } })).status,
      ).toBe(204);
      expect(
        (await call("PATCH", "/api/v1/xdr/connection", { ...stale, body: { enabled: false } })).status,
      ).toBe(204);
      expect((await call("POST", "/api/v1/xdr/endpoints/manager/certificate/scan", stale)).status).toBe(202);
      expect((await call("POST", "/api/v1/xdr/sync", stale)).status).toBe(202);
    });

    it("answers a bad request with the validation errors, not with the step-up demand", async () => {
      const r = await call("POST", "/api/v1/xdr/connection", {
        age: STALE,
        body: valid({ managerApiUrl: "http://x.example.lan" }),
      });
      expect(r.status).toBe(422);
    });
  });

  describe("connecting", () => {
    it("seals both passwords, queues two certificate reads, audits - and returns or stores the passwords nowhere else", async () => {
      const r = await call("POST", "/api/v1/xdr/connection", {
        body: valid({
          name: "  Main lab  ",
          managerApiUrl: " HTTPS://Wazuh-API.Example.LAN ",
          dashboardUrl: "https://dashboard.example.lan/app/wz-home",
          enrollmentHost: "Wazuh.Example.LAN",
        }),
      });
      expect(r.status).toBe(201);
      expect(r.text).not.toContain(MANAGER_PASSWORD);
      const id = r.json?.id as string;
      expect(await connectionRow(id)).toMatchObject({
        organizationId: ORG,
        name: "Main lab",
        dashboardUrl: "https://dashboard.example.lan/app/wz-home",
        enrollmentHost: "wazuh.example.lan",
        enabled: true,
        createdBy: "user_a",
      });
      const endpoints = await t.db
        .select()
        .from(schema.wazuhEndpoint)
        .where(eq(schema.wazuhEndpoint.connectionId, id));
      const manager = endpoints.find((x) => x.kind === "manager");
      const indexer = endpoints.find((x) => x.kind === "indexer");
      expect(manager).toMatchObject({
        apiUrl: "https://wazuh-api.example.lan:55000",
        host: "wazuh-api.example.lan",
        port: 55000,
        username: "garnetops-api",
        trustMode: "pin",
        certStatus: "pending",
        certFingerprint: null,
      });
      expect(indexer).toMatchObject({
        apiUrl: "https://wazuh-idx.example.lan:9200",
        port: 9200,
        trustMode: "pin",
      });
      expect(queue.sent.map((x) => [x.name, x.data.endpointId])).toEqual([
        ["xdr.certificate", manager?.id],
        ["xdr.certificate", indexer?.id],
      ]);

      // Only the worker can open them: sealed in the vault, bound to organisation, record and purpose.
      const vault = loadVaultPrivateKey((queue.vault as { privateKeyPem: string }).privateKeyPem);
      for (const [endpoint, purpose, password] of [
        [manager, "wazuh-api-password", MANAGER_PASSWORD],
        [indexer, "wazuh-indexer-password", INDEXER_PASSWORD],
      ] as const) {
        const [secret] = await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, endpoint?.secretId as string));
        expect(secret).toMatchObject({ purpose, organizationId: ORG });
        expect(JSON.stringify(secret?.sealed)).not.toContain(password);
        expect(
          open(
            secret?.sealed,
            { organizationId: ORG, recordId: secret?.id as string, purpose },
            vault,
          ).toString("utf8"),
        ).toBe(password);
        // Not usable for another purpose or organisation.
        expect(() =>
          open(
            secret?.sealed,
            { organizationId: ORG, recordId: secret?.id as string, purpose: "proxmox-token" },
            vault,
          ),
        ).toThrow();
        expect(() =>
          open(secret?.sealed, { organizationId: OTHER, recordId: secret?.id as string, purpose }, vault),
        ).toThrow();
      }

      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        action: "xdr.connection_created",
        actorUserId: "user_a",
        organizationId: ORG,
        ip: "198.51.100.7",
      });
      expect(audit[0]?.data).toEqual({
        name: "Main lab",
        managerUrl: "https://wazuh-api.example.lan:55000",
        managerUser: "garnetops-api",
        managerTrust: "pin",
        indexerUrl: "https://wazuh-idx.example.lan:9200",
        indexerUser: "garnetops-idx",
        indexerTrust: "pin",
        dashboardUrl: "https://dashboard.example.lan/app/wz-home",
        enrollmentHost: "wazuh.example.lan",
      });
      for (const table of ["wazuh_connection", "wazuh_endpoint", "audit_log", "secret"]) {
        const dump = await t.pool.query(`select row_to_json(x)::text as r from ${table} x`);
        const all = dump.rows.map((x: { r: string }) => x.r).join("\n");
        expect(all, table).not.toContain(MANAGER_PASSWORD);
        expect(all, table).not.toContain(INDEXER_PASSWORD);
      }
      const list = await call("GET", "/api/v1/xdr/connection");
      expect(list.text).not.toContain(MANAGER_PASSWORD);
    });

    it("names every wrong field with a code and refuses unsafe addresses and the default administrative users", async () => {
      const r = await call("POST", "/api/v1/xdr/connection", {
        body: {
          name: "",
          dashboardUrl: "javascript:alert(1)",
          enrollmentHost: "host; id",
          managerApiUrl: "http://127.0.0.1:55000",
          managerUsername: "wazuh-wui",
          managerPassword: "short",
          indexerApiUrl: "https://169.254.169.254",
          indexerUsername: "admin",
          indexerPassword: "short",
        },
      });
      expect(r.status).toBe(422);
      expect(r.json?.errors).toEqual([
        { path: "name", message: "name_invalid" },
        { path: "dashboardUrl", message: "dashboard_invalid" },
        { path: "enrollmentHost", message: "enrollment_invalid" },
        { path: "managerApiUrl", message: "url_notHttps" },
        { path: "indexerApiUrl", message: "url_address" },
        { path: "managerUsername", message: "user_privileged" },
        { path: "indexerUsername", message: "user_privileged" },
        { path: "managerPassword", message: "password_invalid" },
        { path: "indexerPassword", message: "password_invalid" },
      ]);
      const codes: [string, string][] = [
        ["https://127.0.0.1:55000", "url_address"],
        ["https://localhost", "url_address"],
        ["https://[::1]", "url_address"],
        ["https://user:pw@wazuh.example.lan", "url_credentials"],
        ["https://wazuh.example.lan/agents", "url_path"],
        ["wazuh.example.lan", "url_notHttps"],
      ];
      for (const [managerApiUrl, code] of codes) {
        const bad = await call("POST", "/api/v1/xdr/connection", { body: valid({ managerApiUrl }) });
        expect(bad.json?.errors, managerApiUrl).toEqual([{ path: "managerApiUrl", message: code }]);
      }
      expect(await t.db.select().from(schema.wazuhConnection)).toHaveLength(0);
      expect(await t.db.select().from(schema.secret)).toHaveLength(0);
      expect(queue.sent).toEqual([]);
    });

    it("refuses two endpoints that are the same server, and a second connection", async () => {
      const same = await call("POST", "/api/v1/xdr/connection", {
        body: valid({
          managerApiUrl: "https://wazuh.example.lan:9200",
          indexerApiUrl: "https://wazuh.example.lan:9200",
        }),
      });
      expect(same.json?.errors).toEqual([{ path: "indexerApiUrl", message: "url_same_as_manager" }]);
      expect((await call("POST", "/api/v1/xdr/connection", { body: valid() })).status).toBe(201);
      const again = await call("POST", "/api/v1/xdr/connection", { body: valid({ name: "Second" }) });
      expect([again.status, problemCode(again)]).toEqual([409, "limit-reached"]);
    });

    it("accepts a certificate authority instead of a pin, and refuses text that is not a certificate", async () => {
      {
        const { pem, key } = await makeCa();
        const bad = await call("POST", "/api/v1/xdr/connection", {
          body: valid({ managerCaPem: key, indexerCaPem: "not a certificate" }),
        });
        expect(bad.json?.errors).toEqual([
          { path: "managerCaPem", message: "ca_invalid" },
          { path: "indexerCaPem", message: "ca_invalid" },
        ]);
        const ok = await call("POST", "/api/v1/xdr/connection", { body: valid({ managerCaPem: pem }) });
        expect(ok.status).toBe(201);
        const [manager] = await t.db
          .select()
          .from(schema.wazuhEndpoint)
          .where(eq(schema.wazuhEndpoint.kind, "manager"));
        expect(manager).toMatchObject({ trustMode: "ca", certStatus: "pending" });
        expect(manager?.caPem).toContain("BEGIN CERTIFICATE");
        const shown = (await call("GET", "/api/v1/xdr/connection")).json?.connection.endpoints[0];
        expect(shown.trust).toBe("ca");
        expect(shown.ca).toMatchObject({ count: 1, subjects: [expect.stringContaining("Example Root CA")] });
        // A private key never ends up in a row.
        const dump = await t.pool.query("select row_to_json(x)::text as r from wazuh_endpoint x");
        expect(dump.rows.map((x: { r: string }) => x.r).join("")).not.toContain("PRIVATE KEY");
      }
    });
  });

  describe("changing the connection", () => {
    it("re-pointing forgets the certificate and the acknowledgement and reads the certificate again", async () => {
      const c = await seed({
        connection: { extraPrivileges: ["api:agent:restart"], acknowledgedPrivileges: ["api:agent:restart"] },
      });
      const r = await call("PATCH", "/api/v1/xdr/connection", {
        body: { indexerApiUrl: "https://other-idx.example.lan:9201" },
      });
      expect(r.status).toBe(204);
      expect(await endpointRow(c.indexer)).toMatchObject({
        apiUrl: "https://other-idx.example.lan:9201",
        host: "other-idx.example.lan",
        port: 9201,
        certStatus: "pending",
        certFingerprint: null,
      });
      // The other endpoint is left alone.
      expect(await endpointRow(c.manager)).toMatchObject({ certStatus: "confirmed", certFingerprint: FP_A });
      expect(await connectionRow(c.id)).toMatchObject({ extraPrivileges: [], acknowledgedPrivileges: [] });
      expect(queue.sent.map((x) => [x.name, x.data.endpointId])).toEqual([["xdr.certificate", c.indexer]]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
      expect(audit[0]?.data).toMatchObject({
        changed: ["indexerApiUrl"],
        indexerUrl: "https://other-idx.example.lan:9201",
      });
    });

    it("a new password replaces the sealed one, deletes the old secret and starts a sync", async () => {
      const created = await call("POST", "/api/v1/xdr/connection", { body: valid() });
      const id = created.json?.id as string;
      await t.db
        .update(schema.wazuhEndpoint)
        .set({ certStatus: "confirmed", certFingerprint: FP_A })
        .where(eq(schema.wazuhEndpoint.connectionId, id));
      queue.sent.length = 0;
      const [before] = await t.db
        .select()
        .from(schema.wazuhEndpoint)
        .where(eq(schema.wazuhEndpoint.kind, "indexer"));
      const r = await call("PATCH", "/api/v1/xdr/connection", {
        body: { indexerUsername: "garnetops-idx2", indexerPassword: "another indexer password 55" },
      });
      expect(r.status).toBe(204);
      const [after] = await t.db
        .select()
        .from(schema.wazuhEndpoint)
        .where(eq(schema.wazuhEndpoint.kind, "indexer"));
      expect(after?.username).toBe("garnetops-idx2");
      expect(after?.secretId).not.toBe(before?.secretId);
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, before?.secretId as string)),
      ).toHaveLength(0);
      expect(await t.db.select().from(schema.secret)).toHaveLength(2);
      expect(queue.sent.map((x) => x.name)).toEqual(["xdr.sync"]);
      const dump = await t.pool.query("select row_to_json(x)::text as r from audit_log x");
      expect(dump.rows.map((x: { r: string }) => x.r).join("")).not.toContain("another indexer password");
    });

    it("a user name without its password is refused, and so is a bad value", async () => {
      await seed();
      const noPassword = await call("PATCH", "/api/v1/xdr/connection", {
        body: { managerUsername: "someone-else" },
      });
      expect(noPassword.json?.errors).toEqual([{ path: "managerPassword", message: "password_invalid" }]);
      const bad = await call("PATCH", "/api/v1/xdr/connection", {
        body: { managerApiUrl: "https://127.0.0.1", indexerPassword: "x" },
      });
      expect(bad.status).toBe(422);
    });

    it("keeps the endpoints apart, switches trust, and renames without any sign-in", async () => {
      const c = await seed();
      const same = await call("PATCH", "/api/v1/xdr/connection", {
        body: { indexerApiUrl: "https://seeded-api.example.lan:55000" },
      });
      expect(same.json?.errors).toEqual([{ path: "indexerApiUrl", message: "url_same_as_manager" }]);
      const noChange = await call("PATCH", "/api/v1/xdr/connection", { body: { name: "Seeded lab" } });
      expect(noChange.status).toBe(204);
      expect(queue.sent).toEqual([]);
      const off = await call("PATCH", "/api/v1/xdr/connection", {
        body: { enabled: false, dashboardUrl: null },
      });
      expect(off.status).toBe(204);
      expect(await connectionRow(c.id)).toMatchObject({ enabled: false, dashboardUrl: null });
    });

    it("removing the connection removes both secrets and everything read from Wazuh", async () => {
      const created = await call("POST", "/api/v1/xdr/connection", { body: valid() });
      const id = created.json?.id as string;
      await addAgent(id, "001");
      await t.db
        .insert(schema.wazuhSnapshot)
        .values({ connectionId: id, organizationId: ORG, data: SNAPSHOT, syncedAt: new Date() });
      const r = await call("DELETE", "/api/v1/xdr/connection");
      expect(r.status).toBe(204);
      for (const table of ["wazuh_connection", "wazuh_endpoint", "wazuh_agent", "wazuh_snapshot", "secret"]) {
        const rows = await t.pool.query(`select 1 from ${table}`);
        expect(rows.rowCount, table).toBe(0);
      }
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((x) => x.action)).toEqual(["xdr.connection_created", "xdr.connection_deleted"]);
    });
  });

  describe("certificates and privileges", () => {
    it("pins exactly the fingerprint that was shown, audits it, and starts the sync only when both are confirmed", async () => {
      const c = await seed({
        manager: {
          certStatus: "pending",
          certFingerprint: null,
          candidateFingerprint: FP_B,
          candidateSubject: "CN=wazuh-api.example.lan",
          candidateIssuer: "CN=wazuh-api.example.lan",
          candidateCaTrusted: false,
        },
        indexer: { certStatus: "pending", certFingerprint: null, candidateFingerprint: FP_A },
      });
      const wrong = await call("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", {
        body: { fingerprint: FP_A },
      });
      expect([wrong.status, problemCode(wrong)]).toEqual([409, "fingerprint-mismatch"]);
      const bad = await call("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", {
        body: { fingerprint: "nope" },
      });
      expect(bad.status).toBe(422);
      expect(queue.sent).toEqual([]);

      const first = await call("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", {
        body: { fingerprint: FP_B.toLowerCase() },
      });
      expect(first.status).toBe(200);
      expect(first.json).toEqual({ runId: null });
      expect(await endpointRow(c.manager)).toMatchObject({
        certStatus: "confirmed",
        certFingerprint: FP_B,
        candidateFingerprint: null,
        certConfirmedBy: "user_a",
      });
      expect(queue.sent).toEqual([]);

      const second = await call("POST", "/api/v1/xdr/endpoints/indexer/certificate/confirm", {
        body: { fingerprint: FP_A },
      });
      expect(second.status).toBe(200);
      expect(queue.sent.map((x) => x.name)).toEqual(["xdr.sync"]);
      const runs = await t.db.select().from(schema.wazuhSyncRun);
      expect(runs).toMatchObject([{ trigger: "setup", state: "queued", requestedBy: "user_a" }]);

      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
      expect(audit.map((x) => x.action)).toEqual(["xdr.certificate_confirmed", "xdr.certificate_confirmed"]);
      expect(audit[0]?.data).toMatchObject({
        endpoint: "manager",
        fingerprint: FP_B,
        subject: "CN=wazuh-api.example.lan",
        caTrusted: false,
      });
      const again = await call("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", {
        body: { fingerprint: FP_B },
      });
      expect([again.status, problemCode(again)]).toEqual([409, "no-certificate"]);
    });

    it("shows both certificates after a change and lets an admin confirm the new one", async () => {
      const c = await seed({ manager: { certStatus: "changed", candidateFingerprint: FP_B } });
      const shown = (await call("GET", "/api/v1/xdr/connection")).json?.connection.endpoints[0];
      expect(shown.certificate).toMatchObject({
        status: "changed",
        fingerprint: FP_A,
        candidate: { fingerprint: FP_B },
      });
      expect(
        (
          await call("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", {
            body: { fingerprint: FP_B },
          })
        ).status,
      ).toBe(200);
      expect((await endpointRow(c.manager))?.certFingerprint).toBe(FP_B);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
      expect(audit[0]?.data).toMatchObject({ previous: FP_A, fingerprint: FP_B });
    });

    it("has nothing to confirm for an endpoint that is verified by an uploaded authority", async () => {
      await seed({
        manager: {
          trustMode: "ca",
          caPem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
          candidateFingerprint: FP_B,
        },
      });
      const r = await call("POST", "/api/v1/xdr/endpoints/manager/certificate/confirm", {
        body: { fingerprint: FP_B },
      });
      expect([r.status, problemCode(r)]).toEqual([409, "trust-mode"]);
    });

    it("an acknowledgement names the privileges that were shown", async () => {
      const c = await seed({
        connection: { extraPrivileges: ["api:agent:restart", "indexer:role:all_access"] },
      });
      const none = await call("POST", "/api/v1/xdr/privileges/acknowledge", {
        body: { privileges: ["api:agent:restart"] },
      });
      expect([none.status, problemCode(none)]).toEqual([409, "privileges-changed"]);
      const shown = (await call("GET", "/api/v1/xdr/connection")).json?.connection.privileges;
      expect(shown).toMatchObject({
        extra: ["api:agent:restart", "indexer:role:all_access"],
        acknowledged: false,
      });
      expect(queue.sent).toEqual([]);
      const ok = await call("POST", "/api/v1/xdr/privileges/acknowledge", {
        body: { privileges: ["indexer:role:all_access", "api:agent:restart"] },
      });
      expect(ok.status).toBe(204);
      expect(await connectionRow(c.id)).toMatchObject({
        acknowledgedPrivileges: ["api:agent:restart", "indexer:role:all_access"],
        privilegesAcknowledgedBy: "user_a",
      });
      expect(queue.sent.map((x) => x.name)).toEqual(["xdr.sync"]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
      expect(audit.map((x) => x.action)).toEqual(["xdr.privileges_acknowledged"]);
      expect((await call("GET", "/api/v1/xdr/connection")).json?.connection.privileges.acknowledged).toBe(
        true,
      );
    });

    it("has no privileges to acknowledge when the users can only read", async () => {
      await seed();
      const r = await call("POST", "/api/v1/xdr/privileges/acknowledge", { body: { privileges: [] } });
      expect([r.status, problemCode(r)]).toEqual([409, "no-extra-privileges"]);
    });

    it("a sync needs both certificates, runs once at a time and is audited", async () => {
      const c = await seed({ indexer: { certStatus: "pending", certFingerprint: null } });
      const refused = await call("POST", "/api/v1/xdr/sync");
      expect([refused.status, problemCode(refused)]).toEqual([409, "certificate-unconfirmed"]);
      await t.db
        .update(schema.wazuhEndpoint)
        .set({ certStatus: "confirmed", certFingerprint: FP_A })
        .where(eq(schema.wazuhEndpoint.id, c.indexer));
      const first = await call("POST", "/api/v1/xdr/sync");
      expect(first.status).toBe(202);
      const second = await call("POST", "/api/v1/xdr/sync");
      expect([second.status, second.json?.alreadyQueued]).toEqual([200, true]);
      expect(queue.sent.map((x) => x.name)).toEqual(["xdr.sync"]);
      expect(queue.sent[0]?.options).toMatchObject({ retryLimit: 0, singletonKey: c.id });
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
      expect(audit.map((x) => x.action)).toEqual(["xdr.sync_requested"]);
      const runs = (await call("GET", "/api/v1/xdr/runs")).json as unknown as Json[];
      expect(runs).toHaveLength(1);
    });
  });

  describe("the XDR page", () => {
    it("returns the aggregates, the agent counts, the file integrity sample and the state of AI", async () => {
      const c = await seed();
      await addAgent(c.id, "000", { isManager: true, name: "manager" });
      await addAgent(c.id, "001");
      await addAgent(c.id, "002", { status: "disconnected" });
      await addAgent(c.id, "003", { status: "never_connected" });
      const host = await addHost("agent-001", "192.0.2.11");
      await t.db.update(schema.wazuhAgent).set({ hostId: host }).where(eq(schema.wazuhAgent.agentId, "001"));
      const hostB = await addHost("agent-002", "192.0.2.12");
      await t.db
        .update(schema.wazuhAgent)
        .set({ suggestedHostId: hostB, suggestionReason: "name" })
        .where(eq(schema.wazuhAgent.agentId, "002"));
      await t.db.insert(schema.wazuhFimEvent).values([
        {
          id: "wzf_1",
          organizationId: ORG,
          connectionId: c.id,
          at: new Date("2026-10-21T07:00:00Z"),
          agentId: "001",
          agentName: "web-01",
          path: "/etc/passwd",
          event: "modified",
          ruleLevel: 7,
        },
        {
          id: "wzf_2",
          organizationId: ORG,
          connectionId: c.id,
          at: new Date("2026-10-21T07:30:00Z"),
          agentId: "002",
          agentName: "db-01",
          path: "<img src=x onerror=alert(1)>",
          event: "added",
          ruleLevel: null,
        },
      ]);
      const r = await call("GET", "/api/v1/xdr/overview", { role: "viewer" });
      expect(r.status).toBe(200);
      const body = r.json as Json;
      expect(body.connection).toMatchObject({
        name: "Seeded lab",
        adapter: { id: "wazuh4", preview: false },
        managerVersion: "4.12.0",
      });
      expect(body.windows["24h"]).toMatchObject({ total: 300, fim: 4 });
      expect(body.vulnerabilities).toMatchObject({ critical: 1, agentsAffected: 2 });
      // The manager itself is not counted as a monitored agent.
      expect(body.agents).toEqual({
        total: 3,
        active: 1,
        disconnected: 1,
        neverConnected: 1,
        pending: 0,
        linked: 1,
        suggested: 1,
      });
      expect(body.fim.map((x: Json) => x.path)).toEqual(["<img src=x onerror=alert(1)>", "/etc/passwd"]);
      expect(body.ai).toEqual({ state: "not-configured" });
      expect(body.syncIntervalMinutes).toBe(15);

      await t.db.insert(schema.aiSettings).values({
        organizationId: ORG,
        baseUrl: "http://llm.example.lan/v1",
        model: "m",
        enabled: false,
        contextPolicy: "metadata",
      });
      expect((await call("GET", "/api/v1/xdr/overview")).json?.ai).toEqual({ state: "disabled" });
      await t.db.update(schema.aiSettings).set({ enabled: true });
      expect((await call("GET", "/api/v1/xdr/overview")).json?.ai).toEqual({ state: "ready", model: "m" });
    });

    it("marks 5.x as preview", async () => {
      await seed({ connection: { adapter: "wazuh5", managerVersion: "5.0.0" } });
      expect((await call("GET", "/api/v1/xdr/overview")).json?.connection.adapter).toEqual({
        id: "wazuh5",
        preview: true,
      });
    });

    it("pages through many agents in the order chosen, without repeating or skipping one", async () => {
      const c = await seed();
      for (let i = 1; i <= 60; i++) {
        await addAgent(c.id, String(i).padStart(3, "0"), {
          name: `box-${String(i).padStart(2, "0")}`,
          lastKeepAliveAt: new Date(Date.now() - i * 60_000),
        });
      }
      const seen: string[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < 5; page++) {
        const r: { json: Json | null } = await call(
          "GET",
          `/api/v1/xdr/agents?sort=keepAlive&pageSize=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        );
        seen.push(...itemsOf(r).map((x) => x.name));
        cursor = r.json?.next ?? null;
        if (!cursor) break;
      }
      expect(seen).toHaveLength(60);
      expect(new Set(seen).size).toBe(60);
      expect(seen[0]).toBe("box-01");
      expect(seen[59]).toBe("box-60");
    });

    it("lists agents with filters, search, sorting and pages, and counts by state", async () => {
      const c = await seed();
      for (let i = 1; i <= 7; i++) {
        await addAgent(c.id, String(i).padStart(3, "0"), {
          name: `host-${String(i).padStart(2, "0")}`,
          status: i % 3 === 0 ? "disconnected" : "active",
          groups: i % 2 === 0 ? ["default", "web"] : ["default"],
          osName: i % 2 === 0 ? "Ubuntu" : "Debian GNU/Linux",
          vulnCritical: i === 5 ? 3 : i === 6 ? 0 : null,
          vulnHigh: i === 5 ? 1 : i === 6 ? 9 : null,
          lastKeepAliveAt: new Date(Date.now() - i * 60_000),
        });
      }
      const names = (r: { json: Json | null }) => itemsOf(r).map((x) => x.name);
      expect(names(await call("GET", "/api/v1/xdr/agents"))).toEqual([
        "host-01",
        "host-02",
        "host-03",
        "host-04",
        "host-05",
        "host-06",
        "host-07",
      ]);
      expect(names(await call("GET", "/api/v1/xdr/agents?status=disconnected"))).toEqual([
        "host-03",
        "host-06",
      ]);
      expect(names(await call("GET", "/api/v1/xdr/agents?group=web"))).toEqual([
        "host-02",
        "host-04",
        "host-06",
      ]);
      expect(names(await call("GET", "/api/v1/xdr/agents?q=ubuntu"))).toEqual([
        "host-02",
        "host-04",
        "host-06",
      ]);
      expect(names(await call("GET", "/api/v1/xdr/agents?q=192.0.2.15"))).toEqual(["host-05"]);
      expect(names(await call("GET", "/api/v1/xdr/agents?q=%25"))).toEqual([]);
      expect(names(await call("GET", "/api/v1/xdr/agents?sort=vulnerabilities"))).toEqual([
        "host-05",
        "host-06",
        "host-07",
        "host-04",
        "host-03",
        "host-02",
        "host-01",
      ]);
      expect(names(await call("GET", "/api/v1/xdr/agents?sort=name&dir=desc"))[0]).toBe("host-07");
      const first = await call("GET", "/api/v1/xdr/agents?sort=keepAlive");
      expect(names(first)[0]).toBe("host-01");
      const agent = itemsOf(first)[0] as Json;
      expect(agent).not.toHaveProperty("hostId");
      expect(agent.vulnerabilities).toBeNull();
      expect(
        itemsOf(await call("GET", "/api/v1/xdr/agents?sort=vulnerabilities"))[0]?.vulnerabilities,
      ).toEqual({ critical: 3, high: 1, medium: 0, low: 0 });
      expect((await call("GET", "/api/v1/xdr/agents/counts")).json).toEqual({
        all: 7,
        active: 5,
        disconnected: 2,
        never_connected: 0,
        pending: 0,
        unknown: 0,
      });
      expect((await call("GET", "/api/v1/xdr/agents?sort=nonsense")).status).toBe(422);
      expect((await call("GET", "/api/v1/xdr/agents?group=bad%20group")).status).toBe(422);
    });
  });

  describe("linking agents and servers", () => {
    it("an admin confirms a link, a server has one agent, and unlinking is audited", async () => {
      const c = await seed();
      const one = await addAgent(c.id, "001");
      const two = await addAgent(c.id, "002");
      const manager = await addAgent(c.id, "000", { isManager: true });
      const host = await addHost("web-01", "192.0.2.11");
      await t.db
        .update(schema.wazuhAgent)
        .set({ suggestedHostId: host, suggestionReason: "address" })
        .where(eq(schema.wazuhAgent.id, one));
      const listed = (await call("GET", "/api/v1/xdr/agents?link=suggested")).json?.items as Json[];
      expect(listed.map((x) => [x.name, x.suggestion])).toEqual([
        ["agent-001", { hostId: host, hostName: "web-01", reason: "address" }],
      ]);

      expect((await call("POST", `/api/v1/xdr/agents/${one}/link`, { body: { hostId: host } })).status).toBe(
        204,
      );
      const linked = (await call("GET", "/api/v1/xdr/agents?link=linked")).json?.items as Json[];
      expect(linked.map((x) => [x.name, x.server, x.suggestion])).toEqual([
        ["agent-001", { id: host, name: "web-01" }, null],
      ]);

      const taken = await call("POST", `/api/v1/xdr/agents/${two}/link`, { body: { hostId: host } });
      expect([taken.status, problemCode(taken)]).toEqual([409, "already-linked"]);
      const refusedManager = await call("POST", `/api/v1/xdr/agents/${manager}/link`, {
        body: { hostId: host },
      });
      expect([refusedManager.status, problemCode(refusedManager)]).toEqual([409, "manager-agent"]);
      expect(
        (await call("POST", `/api/v1/xdr/agents/${two}/link`, { body: { hostId: "host_nope" } })).status,
      ).toBe(422);

      // The server's own record shows the agent.
      const server = (await call("GET", `/api/v1/hosts/${host}`)).json as Json;
      expect(server.wazuh).toMatchObject({
        agentId: one,
        agentName: "agent-001",
        status: "active",
        connectionName: "Seeded lab",
      });
      expect(itemsOf(await call("GET", "/api/v1/hosts?pageSize=100"))[0]?.wazuh).toMatchObject({
        agentName: "agent-001",
      });

      expect((await call("DELETE", `/api/v1/xdr/agents/${one}/link`)).status).toBe(204);
      expect(itemsOf(await call("GET", "/api/v1/xdr/agents?link=linked"))).toHaveLength(0);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, one));
      expect(audit.map((x) => x.action)).toEqual(["xdr.agent_linked", "xdr.agent_unlinked"]);
      expect(audit[0]?.data).toMatchObject({ agentName: "agent-001", hostName: "web-01" });
    });

    it("creates a server from an agent and links them in one step", async () => {
      const c = await seed();
      const one = await addAgent(c.id, "001");
      const manager = await addAgent(c.id, "000", { isManager: true });
      void manager;
      const ref = wazuhSourceRef(c.id, "001");
      const r = await call("POST", "/api/v1/hosts", {
        body: { address: "192.0.2.61", name: "from-agent", source: "wazuh", sourceRef: ref },
      });
      expect(r.status).toBe(201);
      const [host] = await t.db.select().from(schema.host).where(eq(schema.host.id, r.json?.id));
      expect(host).toMatchObject({ source: "wazuh", sourceRef: ref });
      const [agent] = await t.db.select().from(schema.wazuhAgent).where(eq(schema.wazuhAgent.id, one));
      expect(agent).toMatchObject({ hostId: host?.id, linkedBy: "user_a", suggestedHostId: null });
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, r.json?.id));
      expect(audit[0]?.data).toMatchObject({ source: "wazuh", sourceRef: ref });
      // One server per agent, no reference to agents that do not exist or belong to someone else.
      const again = await call("POST", "/api/v1/hosts", {
        body: { address: "192.0.2.62", source: "wazuh", sourceRef: ref },
      });
      expect([again.status, problemCode(again)]).toEqual([409, "already-linked"]);
      for (const bad of [wazuhSourceRef(c.id, "099"), wazuhSourceRef(c.id, "000"), "garbage"]) {
        const x = await call("POST", "/api/v1/hosts", {
          body: { address: "192.0.2.63", source: "wazuh", sourceRef: bad },
        });
        expect([422, 409], bad).toContain(x.status);
      }
      const foreign = await call("POST", "/api/v1/hosts", {
        org: OTHER,
        body: { address: "192.0.2.64", source: "wazuh", sourceRef: wazuhSourceRef(c.id, "001") },
      });
      expect([foreign.status, foreign.json?.errors]).toEqual([
        422,
        [{ path: "sourceRef", message: "source_unknown" }],
      ]);
    });
  });

  describe("AI summary", () => {
    const ready = () =>
      t.db.insert(schema.aiSettings).values({
        organizationId: ORG,
        baseUrl: "http://llm.example.lan/v1",
        model: "local-model",
        enabled: true,
        contextPolicy: "metadata",
      });

    it("is only available when AI is configured and switched on, and there is something to summarise", async () => {
      const c = await seed();
      const none = await call("POST", "/api/v1/xdr/summary", { body: {} });
      expect([none.status, problemCode(none), none.json?.state]).toEqual([
        409,
        "ai-not-ready",
        "not-configured",
      ]);
      await ready();
      await t.db.update(schema.aiSettings).set({ enabled: false });
      const off = await call("POST", "/api/v1/xdr/summary", { body: {} });
      expect(off.json?.state).toBe("disabled");
      await t.db.update(schema.aiSettings).set({ enabled: true });
      await t.db.delete(schema.wazuhSnapshot);
      const empty = await call("POST", "/api/v1/xdr/summary", { body: {} });
      expect([empty.status, problemCode(empty)]).toEqual([409, "no-data"]);
      expect(queue.sent).toEqual([]);
      void c;
    });

    it("queues one summary for the worker, audits it as an AI request without the prompt, and allows only members", async () => {
      const c = await seed();
      await ready();
      expect((await call("POST", "/api/v1/xdr/summary", { role: "viewer", body: {} })).status).toBe(403);
      const r = await call("POST", "/api/v1/xdr/summary", { role: "member", body: { language: "de" } });
      expect(r.status).toBe(202);
      expect(queue.sent).toEqual([
        {
          name: "xdr.summary",
          data: { summaryId: r.json?.id },
          options: { retryLimit: 0, expireInSeconds: 900 },
        },
      ]);
      const [row] = await t.db
        .select()
        .from(schema.wazuhSummary)
        .where(eq(schema.wazuhSummary.id, r.json?.id));
      expect(row).toMatchObject({
        status: "pending",
        language: "de",
        connectionId: c.id,
        requestedBy: "user_a",
        content: "",
      });
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.action, "ai.request"));
      expect(audit).toHaveLength(1);
      expect(audit[0]?.data).toEqual({ kind: "xdr-summary", model: "local-model", summaryId: r.json?.id });
      // One at a time.
      const busy = await call("POST", "/api/v1/xdr/summary", { body: {} });
      expect([busy.status, problemCode(busy)]).toEqual([429, "summary-busy"]);
    });

    it("shows the latest summary only when it is complete, labelled by who asked", async () => {
      const c = await seed();
      await ready();
      expect((await call("GET", "/api/v1/xdr/summary")).json).toEqual({ summary: null });
      await t.db.insert(schema.wazuhSummary).values({
        id: "wzm_done",
        organizationId: ORG,
        connectionId: c.id,
        status: "complete",
        content: "Quiet **week**.",
        model: "local-model",
        requestedBy: "user_a",
        createdAt: new Date(Date.now() - 60_000),
        finishedAt: new Date(),
      });
      await t.db.insert(schema.wazuhSummary).values({
        id: "wzm_new",
        organizationId: ORG,
        connectionId: c.id,
        status: "running",
        content: "partial secret text",
        requestedBy: "user_a",
      });
      const running = await call("GET", "/api/v1/xdr/summary", { role: "viewer" });
      expect(running.json?.summary).toMatchObject({
        id: "wzm_new",
        status: "running",
        content: "",
        author: "Erika",
      });
      expect(running.text).not.toContain("partial secret text");
      await t.db
        .update(schema.wazuhSummary)
        .set({ status: "complete", content: "Done." })
        .where(eq(schema.wazuhSummary.id, "wzm_new"));
      expect((await call("GET", "/api/v1/xdr/summary")).json?.summary).toMatchObject({
        status: "complete",
        content: "Done.",
      });
      await t.db
        .update(schema.wazuhSummary)
        .set({ status: "failed", error: "timeout", content: "" })
        .where(eq(schema.wazuhSummary.id, "wzm_new"));
      expect((await call("GET", "/api/v1/xdr/summary")).json?.summary).toMatchObject({
        status: "failed",
        error: "timeout",
      });
    });
  });

  describe("agent enrollment helper", () => {
    it("returns the official commands with the manager address of the settings, and the version of the manager", async () => {
      await seed({ connection: { enrollmentHost: "wazuh.example.lan" } });
      const r = await call(
        "GET",
        "/api/v1/xdr/enrollment?os=debian&arch=amd64&group=default,web&name=web-01",
        { role: "member" },
      );
      expect(r.status).toBe(200);
      const body = r.json as Json;
      expect(body).toMatchObject({
        ok: true,
        manager: "wazuh.example.lan",
        addressFromApi: false,
        managerVersion: "4.12.0",
        series: "4.x",
        preview: false,
        packageVersion: "4.12.0",
        passwordPlaceholder: false,
      });
      const all = (body.steps as Json[]).map((s) => s.text).join("\n");
      expect(all).toContain(
        "WAZUH_MANAGER='wazuh.example.lan' WAZUH_AGENT_GROUP='default,web' WAZUH_AGENT_NAME='web-01' apt-get install wazuh-agent=4.12.0-1",
      );
      expect(all).toContain("https://packages.wazuh.com/key/GPG-KEY-WAZUH");
    });

    it("uses the API address when no enrollment address is set, and says so; asks for a placeholder, never a password", async () => {
      await seed();
      const r = await call("GET", "/api/v1/xdr/enrollment?os=windows&password=1");
      expect(r.json).toMatchObject({
        manager: "seeded-api.example.lan",
        addressFromApi: true,
        passwordPlaceholder: true,
      });
      expect(((r.json?.steps ?? []) as Json[]).map((s) => s.text).join("\n")).toContain(
        "WAZUH_REGISTRATION_PASSWORD='<ENROLLMENT_PASSWORD>'",
      );
      expect((await call("GET", "/api/v1/xdr/enrollment?os=macos&arch=arm64")).json?.steps[0].text).toContain(
        "arm64.pkg",
      );
    });

    it("refuses input that could end up in a shell, and viewers", async () => {
      await seed();
      for (const query of [
        "os=debian&group=x;id",
        "os=debian&name=$(id)",
        "os=debian&group=a%20b",
        "os=plan9",
        "os=debian&arch=sparc",
        "os=debian&password=hunter2",
      ]) {
        const r = await call("GET", `/api/v1/xdr/enrollment?${query}`);
        expect(r.status, query).toBe(422);
      }
      expect((await call("GET", "/api/v1/xdr/enrollment?os=debian", { role: "viewer" })).status).toBe(403);
    });

    it("needs a synced version, and an enrollment address that is only a host name or address", async () => {
      await seed({ connection: { managerVersion: null } });
      const r = await call("GET", "/api/v1/xdr/enrollment?os=debian");
      expect([r.status, problemCode(r)]).toEqual([409, "not-synced"]);
      const bad = await call("PATCH", "/api/v1/xdr/connection", {
        body: { enrollmentHost: "host.example.lan; curl evil" },
      });
      expect(bad.json?.errors).toEqual([{ path: "enrollmentHost", message: "enrollment_invalid" }]);
    });
  });
});
