/**
 * The Proxmox VE API (ADR 0012) against a throw-away PostgreSQL database on the development
 * server: who may read and change, which actions need a recent sign-in, validation, that the
 * token secret is only ever sealed, the certificate and privilege confirmations, the guest
 * list with its filters and flags, and servers created from a guest. Sessions are replaced by a
 * header-driven actor; the queue is a recorder. Skipped without the development PostgreSQL.
 */

import { proxmoxSourceRef } from "@garnetops/core/proxmox-flags";
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
  const t = await create(target, "api_proxmox");
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
      proxmoxCertificate: "proxmox.certificate",
      proxmoxSync: "proxmox.sync",
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
const ORG = "org_px_a";
const OTHER = "org_px_b";
const STALE = 11 * 60;
const SECRET = "99999999-8888-4777-8666-555555555555";
const FP_A = Array.from({ length: 32 }, (_, i) => (i + 16).toString(16).toUpperCase()).join(":");
const FP_B = Array.from({ length: 32 }, (_, i) => (i + 48).toString(16).toUpperCase()).join(":");
const DAY = 86_400_000;

describe.skipIf(!adminUrl)("Proxmox API", () => {
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
  const problemCode = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();

  const valid = (extra: Record<string, unknown> = {}) => ({
    name: `Lab ${++counter}`,
    apiUrl: `https://pve${counter}.example.lan:8006`,
    tokenId: "garnetops@pve!inventory",
    tokenSecret: SECRET,
    ...extra,
  });

  async function addCluster(overrides: Partial<typeof schema.proxmoxCluster.$inferInsert> = {}) {
    const id = `pxc_apitest${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.proxmoxCluster).values({
      id,
      organizationId: ORG,
      name: `Seeded ${counter}`,
      apiUrl: `https://seeded${counter}.example.lan:8006`,
      host: `seeded${counter}.example.lan`,
      port: 8006,
      tokenId: "garnetops@pve!inventory",
      certStatus: "confirmed",
      certFingerprint: FP_A,
      backupsReadable: true,
      ...overrides,
    });
    return id;
  }

  async function addGuest(
    clusterId: string,
    vmid: number,
    overrides: Partial<typeof schema.proxmoxGuest.$inferInsert> = {},
  ) {
    const now = new Date();
    await t.db.insert(schema.proxmoxGuest).values({
      id: `pxg_${clusterId.slice(-8)}${String(vmid).padStart(8, "0")}`,
      organizationId: ORG,
      clusterId,
      vmid,
      type: "qemu",
      name: `guest-${vmid}`,
      node: "pve1",
      status: "running",
      statusSince: new Date(now.getTime() - 100 * DAY),
      lastBackupAt: new Date(now.getTime() - 1 * DAY),
      firstSeenAt: now,
      lastSeenAt: now,
      ...overrides,
    });
    return `pxg_${clusterId.slice(-8)}${String(vmid).padStart(8, "0")}`;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { proxmoxRoutes } = await import("./proxmox.ts");
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
    v1.route("/proxmox", proxmoxRoutes as never);
    v1.route("/hosts", hostRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(() => {
    queue.sent.length = 0;
  });

  describe("who may do what", () => {
    const writes: [string, string, unknown][] = [
      ["POST", "/api/v1/proxmox/clusters", {}],
      ["PATCH", "/api/v1/proxmox/clusters/pxc_none", { name: "x" }],
      ["DELETE", "/api/v1/proxmox/clusters/pxc_none", undefined],
      ["POST", "/api/v1/proxmox/clusters/pxc_none/certificate/scan", undefined],
      ["POST", "/api/v1/proxmox/clusters/pxc_none/certificate/confirm", { fingerprint: FP_A }],
      ["POST", "/api/v1/proxmox/clusters/pxc_none/privileges/acknowledge", { privileges: ["VM.PowerMgmt"] }],
      ["POST", "/api/v1/proxmox/clusters/pxc_none/sync", undefined],
    ];

    it("lets every member of the organisation read, and shows the token id to admins only", async () => {
      const id = await addCluster();
      for (const role of ["viewer", "member", "admin", "owner"] as Role[]) {
        for (const path of [
          "/api/v1/proxmox/clusters",
          `/api/v1/proxmox/clusters/${id}/runs`,
          "/api/v1/proxmox/nodes",
          "/api/v1/proxmox/storage",
          "/api/v1/proxmox/guests",
          "/api/v1/proxmox/guests/counts",
        ]) {
          expect((await call("GET", path, { role })).status, `${role} ${path}`).toBe(200);
        }
        const list = await call("GET", "/api/v1/proxmox/clusters", { role });
        const item = ((list.json as Json).items as Json[]).find((x) => x.id === id);
        expect(item?.tokenId, role).toBe(
          role === "admin" || role === "owner" ? "garnetops@pve!inventory" : null,
        );
        expect(item).not.toHaveProperty("secretId");
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
      const r = await call("POST", "/api/v1/proxmox/clusters", { role: "owner", body: valid() });
      expect(r.status).toBe(201);
    });

    it("keeps organisations apart", async () => {
      const id = await addCluster();
      const guest = await addGuest(id, 100);
      for (const [method, path, body] of [
        ["GET", `/api/v1/proxmox/clusters/${id}/runs`, undefined],
        ["GET", `/api/v1/proxmox/guests/${guest}`, undefined],
        ["PATCH", `/api/v1/proxmox/clusters/${id}`, { name: "x" }],
        ["DELETE", `/api/v1/proxmox/clusters/${id}`, undefined],
        ["POST", `/api/v1/proxmox/clusters/${id}/certificate/scan`, undefined],
        ["POST", `/api/v1/proxmox/clusters/${id}/certificate/confirm`, { fingerprint: FP_A }],
        ["POST", `/api/v1/proxmox/clusters/${id}/privileges/acknowledge`, { privileges: ["x.y"] }],
        ["POST", `/api/v1/proxmox/clusters/${id}/sync`, undefined],
      ] as [string, string, unknown][]) {
        expect((await call(method, path, { org: OTHER, body })).status, `${method} ${path}`).toBe(404);
      }
      for (const path of ["clusters", "nodes", "storage", "guests"]) {
        const r = await call("GET", `/api/v1/proxmox/${path}`, { org: OTHER });
        expect((r.json?.items ?? r.json) as unknown[]).toHaveLength(0);
      }
      expect((await call("GET", "/api/v1/proxmox/guests/counts", { org: OTHER })).json).toEqual({
        all: 0,
        stale: 0,
        untracked: 0,
      });
    });
  });

  describe("recent sign-in (step-up)", () => {
    it("is needed to add, re-point, change the token, remove, confirm and acknowledge - not to look or rename", async () => {
      const id = await addCluster({
        candidateFingerprint: FP_B,
        extraPrivileges: ["VM.PowerMgmt"],
      });
      const stale = { age: STALE };
      const expectStepUp = async (method: string, path: string, body?: unknown) => {
        const r = await call(method, path, { ...stale, body });
        expect([r.status, problemCode(r)], `${method} ${path}`).toEqual([403, "step-up-required"]);
        expect(r.json?.maxAgeSeconds).toBe(600);
      };
      await expectStepUp("POST", "/api/v1/proxmox/clusters", valid());
      await expectStepUp("PATCH", `/api/v1/proxmox/clusters/${id}`, {
        apiUrl: "https://other.example.lan:8006",
      });
      await expectStepUp("PATCH", `/api/v1/proxmox/clusters/${id}`, { tokenSecret: SECRET });
      await expectStepUp("DELETE", `/api/v1/proxmox/clusters/${id}`);
      await expectStepUp("POST", `/api/v1/proxmox/clusters/${id}/certificate/confirm`, { fingerprint: FP_B });
      await expectStepUp("POST", `/api/v1/proxmox/clusters/${id}/privileges/acknowledge`, {
        privileges: ["VM.PowerMgmt"],
      });
      // Nothing happened.
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({
        certFingerprint: FP_A,
        candidateFingerprint: FP_B,
        acknowledgedPrivileges: [],
      });
      expect(queue.sent).toEqual([]);

      expect((await call("GET", "/api/v1/proxmox/clusters", stale)).status).toBe(200);
      expect(
        (await call("PATCH", `/api/v1/proxmox/clusters/${id}`, { ...stale, body: { name: "Renamed" } }))
          .status,
      ).toBe(204);
      expect(
        (await call("PATCH", `/api/v1/proxmox/clusters/${id}`, { ...stale, body: { enabled: false } }))
          .status,
      ).toBe(204);
      expect((await call("POST", `/api/v1/proxmox/clusters/${id}/certificate/scan`, stale)).status).toBe(202);
      expect((await call("POST", `/api/v1/proxmox/clusters/${id}/sync`, stale)).status).toBe(202);
    });

    it("answers a bad request with the validation errors, not with the step-up demand", async () => {
      const r = await call("POST", "/api/v1/proxmox/clusters", {
        age: STALE,
        body: valid({ apiUrl: "http://x.example.lan" }),
      });
      expect(r.status).toBe(422);
    });
  });

  describe("adding a connection", () => {
    it("seals the secret, queues the certificate read, audits - and returns or stores the secret nowhere else", async () => {
      const body = valid({ name: "  Main lab  ", apiUrl: " HTTPS://PVE-Main.Example.LAN " });
      const r = await call("POST", "/api/v1/proxmox/clusters", { body });
      expect(r.status).toBe(201);
      expect(r.text).not.toContain(SECRET);
      const id = r.json?.id as string;
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({
        organizationId: ORG,
        name: "Main lab",
        apiUrl: "https://pve-main.example.lan:8006",
        host: "pve-main.example.lan",
        port: 8006,
        tokenId: "garnetops@pve!inventory",
        certStatus: "pending",
        certFingerprint: null,
        enabled: true,
        createdBy: "user_a",
      });
      expect(queue.sent).toEqual([
        {
          name: "proxmox.certificate",
          data: { clusterId: id },
          options: expect.objectContaining({ singletonKey: id }),
        },
      ]);

      // Only the worker can open it: sealed in the vault, bound to organisation, record and purpose.
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, row?.secretId as string));
      expect(secret).toMatchObject({ purpose: "proxmox-token", organizationId: ORG });
      expect(JSON.stringify(secret?.sealed)).not.toContain(SECRET);
      const vault = loadVaultPrivateKey((queue.vault as { privateKeyPem: string }).privateKeyPem);
      expect(
        open(
          secret?.sealed,
          { organizationId: ORG, recordId: secret?.id as string, purpose: "proxmox-token" },
          vault,
        ).toString("utf8"),
      ).toBe(SECRET);
      expect(() =>
        open(
          secret?.sealed,
          { organizationId: OTHER, recordId: secret?.id as string, purpose: "proxmox-token" },
          vault,
        ),
      ).toThrow();

      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        action: "proxmox.cluster_created",
        actorUserId: "user_a",
        organizationId: ORG,
        ip: "198.51.100.7",
      });
      expect(audit[0]?.data).toEqual({
        name: "Main lab",
        apiUrl: "https://pve-main.example.lan:8006",
        tokenId: "garnetops@pve!inventory",
      });

      // Nowhere in the database in clear text.
      for (const table of ["proxmox_cluster", "audit_log", "secret"]) {
        const dump = await t.pool.query(`select row_to_json(x)::text as r from ${table} x`);
        expect(dump.rows.map((x: { r: string }) => x.r).join("\n"), table).not.toContain(SECRET);
      }
      const list = await call("GET", "/api/v1/proxmox/clusters");
      expect(list.text).not.toContain(SECRET);
    });

    it("names every wrong field with a code and refuses unsafe addresses and root", async () => {
      const r = await call("POST", "/api/v1/proxmox/clusters", {
        body: {
          name: "",
          apiUrl: "http://127.0.0.1:8006",
          tokenId: "root@pam!garnetops",
          tokenSecret: "short",
        },
      });
      expect(r.status).toBe(422);
      expect(r.json?.errors).toEqual([
        { path: "name", message: "name_invalid" },
        { path: "apiUrl", message: "url_notHttps" },
        { path: "tokenId", message: "token_root" },
        { path: "tokenSecret", message: "secret_invalid" },
      ]);
      const codes: [string, string][] = [
        ["https://127.0.0.1:8006", "url_address"],
        ["https://localhost", "url_address"],
        ["https://169.254.169.254", "url_address"],
        ["https://[::1]", "url_address"],
        ["https://user:pw@pve.example.lan", "url_credentials"],
        ["https://pve.example.lan/api2/json", "url_path"],
        ["pve.example.lan", "url_notHttps"],
      ];
      for (const [apiUrl, code] of codes) {
        const bad = await call("POST", "/api/v1/proxmox/clusters", { body: valid({ apiUrl }) });
        expect(bad.json?.errors, apiUrl).toEqual([{ path: "apiUrl", message: code }]);
      }
      const noToken = await call("POST", "/api/v1/proxmox/clusters", {
        body: valid({ tokenId: "garnetops" }),
      });
      expect(noToken.json?.errors).toEqual([{ path: "tokenId", message: "token_invalid" }]);
      expect(queue.sent).toEqual([]);
    });

    it("refuses duplicates and too many connections", async () => {
      const first = valid();
      expect((await call("POST", "/api/v1/proxmox/clusters", { body: first })).status).toBe(201);
      for (const dup of [first, valid({ apiUrl: first.apiUrl }), valid({ name: first.name })]) {
        const r = await call("POST", "/api/v1/proxmox/clusters", { body: dup });
        expect([r.status, problemCode(r)]).toEqual([409, "duplicate"]);
      }
      const count = (
        await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.organizationId, OTHER))
      ).length;
      expect(count).toBe(0);
      for (let i = 0; i < 12; i++) {
        await call("POST", "/api/v1/proxmox/clusters", { org: OTHER, body: valid() });
      }
      const room = await call("POST", "/api/v1/proxmox/clusters", { org: OTHER, body: valid() });
      expect([room.status, problemCode(room)]).toEqual([409, "limit-reached"]);
      expect(
        (
          await t.db
            .select()
            .from(schema.proxmoxCluster)
            .where(eq(schema.proxmoxCluster.organizationId, OTHER))
        ).length,
      ).toBe(10);
    });
  });

  describe("certificate", () => {
    it("pins exactly the fingerprint that was shown, audits it and starts the first sync", async () => {
      const id = await addCluster({
        certStatus: "pending",
        certFingerprint: null,
        candidateFingerprint: FP_A,
        candidateSubject: "CN=pve1.example.lan",
        candidateIssuer: "CN=pve1.example.lan",
        candidateCaTrusted: false,
        candidateValidTo: new Date(Date.now() + 100 * DAY),
        candidateSeenAt: new Date(),
      });
      const confirm = (fingerprint: string) =>
        call("POST", `/api/v1/proxmox/clusters/${id}/certificate/confirm`, { body: { fingerprint } });

      expect((await confirm("not a fingerprint")).status).toBe(422);
      const other = await confirm(FP_B);
      expect([other.status, problemCode(other)]).toEqual([409, "fingerprint-mismatch"]);
      expect(queue.sent).toEqual([]);

      const ok = await confirm(FP_A.toLowerCase());
      expect(ok.status).toBe(200);
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({
        certStatus: "confirmed",
        certFingerprint: FP_A,
        certSubject: "CN=pve1.example.lan",
        candidateFingerprint: null,
        certConfirmedBy: "user_a",
      });
      expect(queue.sent.map((j) => j.name)).toEqual(["proxmox.sync"]);
      const [run] = await t.db
        .select()
        .from(schema.proxmoxSyncRun)
        .where(eq(schema.proxmoxSyncRun.clusterId, id));
      expect(run).toMatchObject({ state: "queued", trigger: "setup", requestedBy: "user_a" });
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((a) => a.action)).toEqual(["proxmox.certificate_confirmed"]);
      expect(audit[0]?.data).toMatchObject({ fingerprint: FP_A, previous: null, caTrusted: false });

      const again = await confirm(FP_A);
      expect([again.status, problemCode(again)]).toEqual([409, "no-certificate"]);
    });

    it("confirming a changed certificate records the one it replaces", async () => {
      const id = await addCluster({ certStatus: "changed", candidateFingerprint: FP_B });
      const r = await call("POST", `/api/v1/proxmox/clusters/${id}/certificate/confirm`, {
        body: { fingerprint: FP_B },
      });
      expect(r.status).toBe(200);
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({ certStatus: "confirmed", certFingerprint: FP_B });
      const [run] = await t.db
        .select()
        .from(schema.proxmoxSyncRun)
        .where(eq(schema.proxmoxSyncRun.clusterId, id));
      expect(run?.trigger).toBe("manual");
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit[0]?.data).toMatchObject({ fingerprint: FP_B, previous: FP_A });
    });

    it("asking again only queues the worker, and never pins", async () => {
      const id = await addCluster({ certStatus: "pending", certFingerprint: null });
      const r = await call("POST", `/api/v1/proxmox/clusters/${id}/certificate/scan`);
      expect(r.status).toBe(202);
      expect(queue.sent.map((j) => j.name)).toEqual(["proxmox.certificate"]);
      expect(
        (await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id)))[0]
          ?.certFingerprint,
      ).toBeNull();
    });
  });

  describe("token privileges", () => {
    it("shows what the token can do beyond reading and needs the admin to acknowledge exactly that", async () => {
      const id = await addCluster({
        extraPrivileges: ["Permissions.Modify", "VM.PowerMgmt"],
        lastError: "x",
      });
      const list = await call("GET", "/api/v1/proxmox/clusters");
      const item = ((list.json as Json).items as Json[]).find((x) => x.id === id) as Json;
      expect(item.privileges).toMatchObject({
        extra: ["Permissions.Modify", "VM.PowerMgmt"],
        acknowledged: false,
      });

      const ack = (privileges: string[]) =>
        call("POST", `/api/v1/proxmox/clusters/${id}/privileges/acknowledge`, { body: { privileges } });
      const partial = await ack(["VM.PowerMgmt"]);
      expect([partial.status, problemCode(partial)]).toEqual([409, "privileges-changed"]);
      const more = await ack(["VM.PowerMgmt", "Permissions.Modify", "Sys.Console"]);
      expect(more.status).toBe(409);
      expect(queue.sent).toEqual([]);

      expect((await ack(["VM.PowerMgmt", "Permissions.Modify"])).status).toBe(204);
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({
        acknowledgedPrivileges: ["Permissions.Modify", "VM.PowerMgmt"],
        privilegesAcknowledgedBy: "user_a",
        lastError: null,
      });
      expect(queue.sent.map((j) => j.name)).toEqual(["proxmox.sync"]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((a) => a.action)).toEqual(["proxmox.privileges_acknowledged"]);
      expect(audit[0]?.data).toEqual({ name: row?.name, privileges: ["Permissions.Modify", "VM.PowerMgmt"] });
      const after = (await call("GET", "/api/v1/proxmox/clusters")).json?.items as Json[];
      expect(after.find((x) => x.id === id)?.privileges.acknowledged).toBe(true);
    });

    it("has nothing to acknowledge for a token that only reads", async () => {
      const id = await addCluster();
      const r = await call("POST", `/api/v1/proxmox/clusters/${id}/privileges/acknowledge`, {
        body: { privileges: [] },
      });
      expect([r.status, problemCode(r)]).toEqual([409, "no-extra-privileges"]);
    });
  });

  describe("sync", () => {
    it("needs a confirmed certificate and does not queue a second run while one is waiting", async () => {
      const pending = await addCluster({ certStatus: "pending", certFingerprint: null });
      const r = await call("POST", `/api/v1/proxmox/clusters/${pending}/sync`);
      expect([r.status, problemCode(r)]).toEqual([409, "certificate-unconfirmed"]);
      expect(queue.sent).toEqual([]);

      const id = await addCluster();
      const first = await call("POST", `/api/v1/proxmox/clusters/${id}/sync`);
      expect(first.status).toBe(202);
      const second = await call("POST", `/api/v1/proxmox/clusters/${id}/sync`);
      expect(second.status).toBe(200);
      expect(second.json).toEqual({ runId: first.json?.runId, alreadyQueued: true });
      expect(queue.sent).toHaveLength(1);
      expect(queue.sent[0]).toMatchObject({
        name: "proxmox.sync",
        data: { runId: first.json?.runId },
        options: { retryLimit: 0, singletonKey: id },
      });
      const runs = await call("GET", `/api/v1/proxmox/clusters/${id}/runs`);
      expect(runs.json).toHaveLength(1);
      expect(runs.json?.[0]).toMatchObject({ state: "queued", trigger: "manual" });
    });
  });

  describe("changing and removing a connection", () => {
    it("renames and switches off without touching anything else", async () => {
      const id = await addCluster();
      expect(
        (
          await call("PATCH", `/api/v1/proxmox/clusters/${id}`, {
            body: { name: "Better name", enabled: false },
          })
        ).status,
      ).toBe(204);
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({
        name: "Better name",
        enabled: false,
        certStatus: "confirmed",
        certFingerprint: FP_A,
      });
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit[0]).toMatchObject({ action: "proxmox.cluster_changed" });
      expect(audit[0]?.data).toMatchObject({ changed: ["name", "enabled"] });
      expect(queue.sent).toEqual([]);
      // Nothing changed, nothing audited.
      const again = await call("PATCH", `/api/v1/proxmox/clusters/${id}`, { body: { name: "Better name" } });
      expect(again.status).toBe(204);
      expect(await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id))).toHaveLength(
        1,
      );
    });

    it("trusts nothing about the old server after it was pointed at another one", async () => {
      const id = await addCluster({
        extraPrivileges: ["VM.PowerMgmt"],
        acknowledgedPrivileges: ["VM.PowerMgmt"],
        lastError: "old",
      });
      const r = await call("PATCH", `/api/v1/proxmox/clusters/${id}`, {
        body: { apiUrl: "https://new-host.example.lan:8443" },
      });
      expect(r.status).toBe(204);
      const [row] = await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      expect(row).toMatchObject({
        host: "new-host.example.lan",
        port: 8443,
        certStatus: "pending",
        certFingerprint: null,
        extraPrivileges: [],
        acknowledgedPrivileges: [],
        lastError: null,
      });
      expect(queue.sent.map((j) => j.name)).toEqual(["proxmox.certificate"]);
    });

    it("replaces a token as a whole: new sealed secret, old one deleted, privileges looked at again", async () => {
      const real = await addCluster({ acknowledgedPrivileges: ["VM.PowerMgmt"] });
      const oldSecret = `sec_old${counter}`;
      await t.db.insert(schema.secret).values({
        id: oldSecret,
        organizationId: ORG,
        purpose: "proxmox-token",
        sealed: {},
        vaultKeyId: "k",
      });
      await t.db
        .update(schema.proxmoxCluster)
        .set({ secretId: oldSecret })
        .where(eq(schema.proxmoxCluster.id, real));
      queue.sent.length = 0;
      const newSecret = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
      const r = await call("PATCH", `/api/v1/proxmox/clusters/${real}`, {
        body: { tokenId: "other@pve!ro2", tokenSecret: newSecret },
      });
      expect(r.status).toBe(204);
      const [after] = await t.db
        .select()
        .from(schema.proxmoxCluster)
        .where(eq(schema.proxmoxCluster.id, real));
      expect(after?.tokenId).toBe("other@pve!ro2");
      expect(after?.secretId).not.toBe(oldSecret);
      expect(after?.acknowledgedPrivileges).toEqual([]);
      expect(await t.db.select().from(schema.secret).where(eq(schema.secret.id, oldSecret))).toHaveLength(0);
      const [sealed] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, after?.secretId as string));
      const vault = loadVaultPrivateKey((queue.vault as { privateKeyPem: string }).privateKeyPem);
      expect(
        open(
          sealed?.sealed,
          { organizationId: ORG, recordId: sealed?.id as string, purpose: "proxmox-token" },
          vault,
        ).toString("utf8"),
      ).toBe(newSecret);
      const dump = await t.pool.query("select row_to_json(x)::text as r from audit_log x");
      expect(dump.rows.map((x: { r: string }) => x.r).join("\n")).not.toContain(newSecret);
      // The certificate pin stays (same server): a sync reads the new token's privileges.
      expect(queue.sent.map((j) => j.name)).toEqual(["proxmox.sync"]);
      // A token id alone is not enough: the secret belongs with it.
      const idOnly = await call("PATCH", `/api/v1/proxmox/clusters/${real}`, {
        body: { tokenId: "someone@pve!else" },
      });
      expect(idOnly.json?.errors).toEqual([{ path: "tokenSecret", message: "secret_invalid" }]);
    });

    it("removes the connection, its sealed secret and everything read from it", async () => {
      const id = await addCluster();
      const secretId = `sec_px${counter}`;
      await t.db
        .insert(schema.secret)
        .values({ id: secretId, organizationId: ORG, purpose: "proxmox-token", sealed: {}, vaultKeyId: "k" });
      await t.db.update(schema.proxmoxCluster).set({ secretId }).where(eq(schema.proxmoxCluster.id, id));
      await addGuest(id, 100);
      const r = await call("DELETE", `/api/v1/proxmox/clusters/${id}`);
      expect(r.status).toBe(204);
      expect(
        await t.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id)),
      ).toHaveLength(0);
      expect(
        await t.db.select().from(schema.proxmoxGuest).where(eq(schema.proxmoxGuest.clusterId, id)),
      ).toHaveLength(0);
      expect(await t.db.select().from(schema.secret).where(eq(schema.secret.id, secretId))).toHaveLength(0);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((a) => a.action)).toEqual(["proxmox.cluster_deleted"]);
    });
  });

  describe("guests", () => {
    let cluster = "";
    let shared = "";
    const ids: Record<string, string> = {};

    beforeAll(async () => {
      // A cluster of its own, so the other tests' rows do not count.
      cluster = await addCluster({ name: "Guest lab", backupsReadable: true });
      shared = cluster;
      const now = Date.now();
      ids.web = await addGuest(cluster, 100, {
        name: "web-01",
        ostype: "l26",
        tags: ["prod", "web"],
        ips: ["192.0.2.50"],
        lastBackupAt: new Date(now - 1 * DAY),
        cpu: 0.5,
        mem: 3,
        maxDisk: 30,
        uptime: 100,
      });
      ids.noBackup = await addGuest(cluster, 101, {
        name: "db-01",
        node: "pve2",
        lastBackupAt: null,
        cpu: 0.1,
        mem: 9,
        maxDisk: 10,
        uptime: 5,
      });
      ids.oldBackup = await addGuest(cluster, 102, {
        name: "app-01",
        lastBackupAt: new Date(now - 8 * DAY),
        cpu: 0.9,
        mem: 1,
        maxDisk: 20,
      });
      ids.fresh = await addGuest(cluster, 103, { name: "fresh-01", lastBackupAt: new Date(now - 6.5 * DAY) });
      ids.stopped = await addGuest(cluster, 104, {
        name: "old-test",
        status: "stopped",
        statusSince: new Date(now - 31 * DAY),
        lastBackupAt: new Date(now - 2 * DAY),
        type: "lxc",
      });
      ids.stoppedRecently = await addGuest(cluster, 105, {
        name: "stopped-recent",
        status: "stopped",
        statusSince: new Date(now - 29 * DAY),
        lastBackupAt: new Date(now - 2 * DAY),
        type: "lxc",
      });
      ids.snap = await addGuest(cluster, 106, {
        name: "snap-01",
        oldestSnapshotAt: new Date(now - 40 * DAY),
        newestSnapshotAt: new Date(now - 1 * DAY),
        snapshotCount: 3,
        lastBackupAt: new Date(now - 1 * DAY),
      });
      ids.template = await addGuest(cluster, 9000, {
        name: "template",
        template: true,
        status: "stopped",
        statusSince: new Date(now - 90 * DAY),
        lastBackupAt: null,
        oldestSnapshotAt: new Date(now - 90 * DAY),
      });
      ids.linked = await addGuest(cluster, 107, { name: "linked-01", lastBackupAt: new Date(now - 1 * DAY) });
      await t.db.insert(schema.host).values({
        id: "host_pxlinked0000000001",
        organizationId: ORG,
        name: "linked-01",
        address: "linked-01.example.lan",
        source: "proxmox",
        sourceRef: proxmoxSourceRef(cluster, 107),
      });
      // Healthy: backed up, linked, no snapshots. Everything else running is untracked.
      for (const key of ["web", "noBackup", "oldBackup", "fresh", "snap"]) void ids[key];
    });

    const list = async (query = "") => {
      const r = await call("GET", `/api/v1/proxmox/guests?cluster=${shared}&pageSize=100${query}`);
      expect(r.status).toBe(200);
      return r.json as Json;
    };
    const names = (page: Json) => (page.items as Json[]).map((x) => x.name);

    it("flags stopped for long, no recent backup, old snapshot and untracked, and never flags a template", async () => {
      const page = await list();
      const flags = Object.fromEntries((page.items as Json[]).map((x) => [x.name, x.flags]));
      expect(flags).toEqual({
        "web-01": ["untracked"],
        "db-01": ["noRecentBackup", "untracked"],
        "app-01": ["noRecentBackup", "untracked"],
        "fresh-01": ["untracked"],
        "old-test": ["stoppedLong"],
        "stopped-recent": [],
        "snap-01": ["oldSnapshot", "untracked"],
        template: [],
        "linked-01": [],
      });
      const linkedGuest = (page.items as Json[]).find((x) => x.name === "linked-01");
      expect(linkedGuest?.server).toEqual({ id: "host_pxlinked0000000001", name: "linked-01" });
    });

    it("filters by flag in SQL exactly as the rules say", async () => {
      expect(names(await list("&flag=untracked")).sort()).toEqual([
        "app-01",
        "db-01",
        "fresh-01",
        "snap-01",
        "web-01",
      ]);
      expect(names(await list("&flag=stale")).sort()).toEqual(["app-01", "db-01", "old-test", "snap-01"]);
      expect((await call("GET", `/api/v1/proxmox/guests/counts?cluster=${shared}`)).json).toEqual({
        all: 9,
        stale: 4,
        untracked: 5,
      });
    });

    it("does not flag a missing backup when the backups could not be read", async () => {
      const unreadable = await addCluster({ name: "Unreadable", backupsReadable: false });
      await addGuest(unreadable, 100, { name: "any", lastBackupAt: null });
      const page = (await call("GET", `/api/v1/proxmox/guests?cluster=${unreadable}`)).json as Json;
      expect((page.items as Json[])[0]?.flags).toEqual(["untracked"]);
      expect((await call("GET", `/api/v1/proxmox/guests?cluster=${unreadable}&flag=stale`)).json?.total).toBe(
        0,
      );
    });

    it("filters by type, status, node and text", async () => {
      expect(names(await list("&type=lxc")).sort()).toEqual(["old-test", "stopped-recent"]);
      expect(names(await list("&status=stopped")).sort()).toEqual(["old-test", "stopped-recent", "template"]);
      expect(names(await list("&node=pve2"))).toEqual(["db-01"]);
      expect(names(await list("&q=web"))).toEqual(["web-01"]);
      expect(names(await list("&q=192.0.2.50"))).toEqual(["web-01"]);
      expect(names(await list("&q=101"))).toEqual(["db-01"]);
      expect(names(await list("&q=l26"))).toEqual(["web-01"]);
      expect(names(await list("&q=prod"))).toEqual(["web-01"]);
      expect(names(await list("&q=%25"))).toEqual([]); // a literal percent sign matches nothing
      expect((await call("GET", "/api/v1/proxmox/guests?type=bogus")).status).toBe(422);
    });

    it("sorts by every column in both directions and pages without gaps", async () => {
      const paging = await addCluster({ name: "Paging lab" });
      const now = Date.now();
      for (let i = 1; i <= 30; i++) {
        await addGuest(paging, i, {
          name: `p-${String(i).padStart(2, "0")}`,
          node: `pve${(i % 3) + 1}`,
          status: i % 4 === 0 ? "stopped" : "running",
          cpu: i % 5 === 0 ? null : ((i * 7) % 11) / 10,
          mem: (i * 13) % 17,
          maxDisk: (i * 3) % 7,
          uptime: i % 6 === 0 ? null : i,
          lastBackupAt: i % 3 === 0 ? null : new Date(now - i * DAY),
          oldestSnapshotAt: i % 2 === 0 ? null : new Date(now - i * DAY),
        });
      }
      const everything = Array.from({ length: 30 }, (_, i) => `p-${String(i + 1).padStart(2, "0")}`);
      for (const sort of [
        "name",
        "vmid",
        "node",
        "status",
        "cpu",
        "mem",
        "disk",
        "uptime",
        "lastBackup",
        "snapshot",
      ]) {
        for (const dir of ["asc", "desc"]) {
          const seen: string[] = [];
          let cursor: string | null = null;
          let pages = 0;
          do {
            const page: Json = (
              await call(
                "GET",
                `/api/v1/proxmox/guests?cluster=${paging}&pageSize=25&sort=${sort}&dir=${dir}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
              )
            ).json as Json;
            seen.push(...names(page));
            cursor = page.next;
            pages++;
          } while (cursor);
          expect(pages, `${sort} ${dir}`).toBe(2);
          expect([...seen].sort(), `${sort} ${dir}`).toEqual(everything);
        }
      }
      const byVmid = names(
        (await call("GET", `/api/v1/proxmox/guests?cluster=${paging}&sort=vmid&dir=desc`)).json as Json,
      );
      expect(byVmid.slice(0, 3)).toEqual(["p-30", "p-29", "p-28"]);
      const byName = names((await call("GET", `/api/v1/proxmox/guests?cluster=${paging}`)).json as Json);
      expect(byName.slice(0, 2)).toEqual(["p-01", "p-02"]);
      // Backwards from the second page gives the first again.
      const first: Json = (await call("GET", `/api/v1/proxmox/guests?cluster=${paging}&pageSize=25`))
        .json as Json;
      const second: Json = (
        await call(
          "GET",
          `/api/v1/proxmox/guests?cluster=${paging}&pageSize=25&cursor=${encodeURIComponent(first.next)}`,
        )
      ).json as Json;
      const back: Json = (
        await call(
          "GET",
          `/api/v1/proxmox/guests?cluster=${paging}&pageSize=25&cursor=${encodeURIComponent(second.prev)}`,
        )
      ).json as Json;
      expect(names(back)).toEqual(names(first));
      // The default is ordered by name, the way the database sorts text.
      const small = (await list()).items as Json[];
      expect(small.map((x) => x.name)).toEqual(
        [...small.map((x) => x.name as string)].sort((a, b) => a.localeCompare(b)),
      );
    });

    it("opens one guest, only in its own organisation", async () => {
      const r = await call("GET", `/api/v1/proxmox/guests/${ids.web}`);
      expect(r.status).toBe(200);
      expect(r.json).toMatchObject({
        vmid: 100,
        name: "web-01",
        clusterName: "Guest lab",
        ips: ["192.0.2.50"],
        tags: ["prod", "web"],
      });
      expect((await call("GET", "/api/v1/proxmox/guests/pxg_missing")).status).toBe(404);
    });

    it("sums the connection's figures", async () => {
      await t.db.insert(schema.proxmoxNode).values([
        {
          id: "pxn_sum000000000001",
          organizationId: ORG,
          clusterId: shared,
          name: "pve1",
          online: true,
          pendingUpdates: 3,
          lastSeenAt: new Date(),
        },
        {
          id: "pxn_sum000000000002",
          organizationId: ORG,
          clusterId: shared,
          name: "pve2",
          online: true,
          pendingUpdates: 0,
          lastSeenAt: new Date(),
        },
        {
          id: "pxn_sum000000000003",
          organizationId: ORG,
          clusterId: shared,
          name: "pve3",
          online: false,
          pendingUpdates: null,
          lastSeenAt: new Date(),
        },
      ]);
      const items = (await call("GET", "/api/v1/proxmox/clusters")).json?.items as Json[];
      expect(items.find((x) => x.id === shared)?.counts).toEqual({
        guests: 9,
        running: 6,
        templates: 1,
        stale: 4,
        untracked: 5,
        nodes: 3,
        online: 2,
        withUpdates: 1,
        updates: 3,
      });
      const nodes = (await call("GET", `/api/v1/proxmox/nodes?cluster=${shared}`)).json as Json[];
      expect(nodes.map((x) => [x.name, x.pendingUpdates, x.guests])).toEqual([
        ["pve1", 3, 8],
        ["pve2", 0, 1],
        ["pve3", null, 0],
      ]);
    });
  });

  describe("servers created from a guest", () => {
    let cluster = "";
    beforeAll(async () => {
      cluster = await addCluster({ name: "Link lab" });
      await addGuest(cluster, 500, { name: "link-me" });
      await addGuest(cluster, 501, { name: "link-me-too" });
    });
    const create = (extra: Record<string, unknown>) =>
      call("POST", "/api/v1/hosts", { body: { address: "192.0.2.77", name: "link-me", ...extra } });

    it("links the new server to the guest, and the guest to the server", async () => {
      const r = await create({ source: "proxmox", sourceRef: proxmoxSourceRef(cluster, 500) });
      expect(r.status).toBe(201);
      const [row] = await t.db
        .select()
        .from(schema.host)
        .where(eq(schema.host.id, r.json?.id as string));
      expect(row).toMatchObject({
        source: "proxmox",
        sourceRef: `${cluster}:500`,
        address: "192.0.2.77",
        hostKeyStatus: "pending",
      });
      // The same agentless flow as any server: a host key scan, no command on the node.
      expect(queue.sent.map((j) => j.name)).toEqual(
        expect.arrayContaining(["host.keyscan", "host.access-key"]),
      );
      expect(queue.sent.some((j) => j.name.startsWith("proxmox"))).toBe(false);
      const audit = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.targetId, r.json?.id as string));
      expect(audit[0]?.data).toMatchObject({ source: "proxmox", sourceRef: `${cluster}:500` });

      const guests = (await call("GET", `/api/v1/proxmox/guests?cluster=${cluster}`)).json?.items as Json[];
      expect(guests.find((x) => x.vmid === 500)?.server).toEqual({ id: r.json?.id, name: "link-me" });
      expect(guests.find((x) => x.vmid === 500)?.flags).not.toContain("untracked");
      expect(guests.find((x) => x.vmid === 501)?.flags).toContain("untracked");

      const server = (await call("GET", `/api/v1/hosts/${r.json?.id}`)).json as Json;
      expect(server.proxmox).toMatchObject({
        clusterName: "Link lab",
        vmid: 500,
        name: "link-me",
        type: "qemu",
      });
      const listed = (await call("GET", "/api/v1/hosts?pageSize=100")).json?.items as Json[];
      expect(listed.find((x) => x.id === r.json?.id)?.proxmox).toMatchObject({ vmid: 500 });
      expect(listed.find((x) => x.source === "manual")?.proxmox ?? null).toBeNull();
    });

    it("links a guest to one server only", async () => {
      const again = await call("POST", "/api/v1/hosts", {
        body: { address: "192.0.2.78", source: "proxmox", sourceRef: proxmoxSourceRef(cluster, 500) },
      });
      expect([again.status, problemCode(again)]).toEqual([409, "already-linked"]);
    });

    it("refuses a reference that is not a guest of this organisation", async () => {
      for (const [source, sourceRef] of [
        ["proxmox", proxmoxSourceRef(cluster, 999)],
        ["proxmox", "pxc_doesnotexist00000:500"],
        ["proxmox", "garbage"],
        ["proxmox", undefined],
        [undefined, proxmoxSourceRef(cluster, 501)],
      ] as [string | undefined, string | undefined][]) {
        const r = await call("POST", "/api/v1/hosts", { body: { address: "192.0.2.79", source, sourceRef } });
        expect(r.status, `${source} ${sourceRef}`).toBe(422);
      }
      const other = await call("POST", "/api/v1/hosts", {
        org: OTHER,
        body: { address: "192.0.2.80", source: "proxmox", sourceRef: proxmoxSourceRef(cluster, 501) },
      });
      expect([other.status, other.json?.errors]).toEqual([
        422,
        [{ path: "sourceRef", message: "source_unknown" }],
      ]);
      expect(await t.db.select().from(schema.host).where(eq(schema.host.address, "192.0.2.79"))).toHaveLength(
        0,
      );
    });

    it("does not let the web pick any other source", async () => {
      const r = await call("POST", "/api/v1/hosts", {
        body: { address: "192.0.2.81", source: "wazuh", sourceRef: "x" },
      });
      expect(r.status).toBe(422);
    });
  });
});
