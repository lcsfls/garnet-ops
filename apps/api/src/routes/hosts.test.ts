/**
 * The servers API (ADR 0011) against a throw-away PostgreSQL database on the development
 * server: who may read and change, which actions need a recent sign-in, validation, the host
 * key confirmation, the setup script and its one-time link, and the audit log. Sessions are
 * replaced by a header-driven actor; the queue is a recorder. Skipped without the development
 * PostgreSQL.
 */
import { createHash } from "node:crypto";
import { fingerprint, generateDeployKey } from "@garnetops/core/ssh";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const queue = vi.hoisted(() => ({
  sent: [] as { name: string; data: Record<string, unknown>; options: Record<string, unknown> }[],
  db: null as unknown,
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_hosts");
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
    },
  };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
// Sessions are replaced by a header-driven actor below; the real auth module needs a full configuration.
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

/** A JSON body as the API sent it. The assertions check its shape, so it is typed loosely on purpose. */
// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_a";
const OTHER = "org_b";

describe.skipIf(!adminUrl)("servers API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  /** A request as a signed-in user. `age` is how long ago the strong sign-in was, in seconds. */
  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; age?: number; body?: unknown; ip?: string } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": options.org ?? ORG,
      "x-age": String(options.age ?? 0),
      "x-ip": options.ip ?? "198.51.100.7",
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
      // not JSON (the setup script)
    }
    return { status: res.status, json: json as Json | null, text, headers: res.headers };
  }

  const STALE = 11 * 60; // older than ten minutes
  const problemCode = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();

  async function addHost(overrides: Partial<typeof schema.host.$inferInsert> = {}) {
    const id = `host_t${++counter}`;
    await t.db.insert(schema.host).values({
      id,
      organizationId: ORG,
      name: `server-${counter}`,
      address: `server-${counter}.example.test`,
      ...overrides,
    });
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { hostRoutes } = await import("./hosts.ts");
    const { hostSetupPublicRoutes } = await import("./host-setup.ts");
    // The mocked database module (which creates the throw-away database) loads with the imports above.
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
    v1.route("/hosts", hostRoutes as never);
    app = new Hono()
      .onError(handleError)
      .route("/api/v1/host-setup", hostSetupPublicRoutes)
      .route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  beforeEach(() => {
    queue.sent.length = 0;
  });

  describe("who may do what", () => {
    const writes: [string, string, unknown][] = [
      ["POST", "/api/v1/hosts", { address: "writes.example.test" }],
      ["POST", "/api/v1/hosts/import", { csv: "writes2.example.test" }],
      ["DELETE", "/api/v1/hosts/host_none", undefined],
      ["POST", "/api/v1/hosts/host_none/inventory", undefined],
      ["POST", "/api/v1/hosts/host_none/host-key/scan", undefined],
      ["POST", "/api/v1/hosts/host_none/host-key/confirm", { fingerprint: `SHA256:${"A".repeat(43)}` }],
      ["POST", "/api/v1/hosts/access", undefined],
      ["POST", "/api/v1/hosts/setup-script", { allowedSource: "192.0.2.10" }],
      ["POST", "/api/v1/hosts/setup-links", { allowedSource: "192.0.2.10" }],
    ];

    it("lets every member of the organisation read", async () => {
      const id = await addHost();
      for (const role of ["viewer", "member", "admin", "owner"] as Role[]) {
        for (const path of [
          "/api/v1/hosts",
          "/api/v1/hosts/counts",
          `/api/v1/hosts/${id}`,
          `/api/v1/hosts/${id}/packages`,
          `/api/v1/hosts/${id}/findings`,
          `/api/v1/hosts/${id}/runs`,
          "/api/v1/hosts/access",
        ]) {
          expect((await call("GET", path, { role })).status, `${role} ${path}`).toBe(200);
        }
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
      expect(await t.db.select().from(schema.host)).not.toContainEqual(
        expect.objectContaining({ address: "writes.example.test" }),
      );
    });

    it("lets owners do what admins do", async () => {
      const r = await call("POST", "/api/v1/hosts", {
        role: "owner",
        body: { address: "owner-added.example.test" },
      });
      expect(r.status).toBe(201);
    });

    it("keeps organisations apart: another organisation's server does not exist", async () => {
      const id = await addHost();
      for (const [method, path, body] of [
        ["GET", `/api/v1/hosts/${id}`, undefined],
        ["GET", `/api/v1/hosts/${id}/packages`, undefined],
        ["GET", `/api/v1/hosts/${id}/findings`, undefined],
        ["GET", `/api/v1/hosts/${id}/runs`, undefined],
        ["POST", `/api/v1/hosts/${id}/inventory`, undefined],
        ["POST", `/api/v1/hosts/${id}/host-key/scan`, undefined],
        ["POST", `/api/v1/hosts/${id}/host-key/confirm`, { fingerprint: `SHA256:${"A".repeat(43)}` }],
        ["DELETE", `/api/v1/hosts/${id}`, undefined],
      ] as [string, string, unknown][]) {
        const r = await call(method, path, { org: OTHER, body });
        expect(r.status, `${method} ${path}`).toBe(404);
      }
      const list = await call("GET", "/api/v1/hosts?pageSize=100", { org: OTHER });
      expect(list.json?.total).toBe(0);
      expect((await t.db.select().from(schema.host).where(eq(schema.host.id, id))).length).toBe(1);
    });
  });

  describe("recent sign-in (step-up)", () => {
    it("is needed to add, import, remove and confirm a key, and not for reading or inventories", async () => {
      const id = await addHost({
        candidateKey: "AAAA",
        candidateKeyType: "ssh-ed25519",
        candidateKeyFingerprint: `SHA256:${"B".repeat(43)}`,
      });
      const stale = { age: STALE };
      const add = await call("POST", "/api/v1/hosts", { ...stale, body: { address: "stale.example.test" } });
      expect([add.status, problemCode(add)]).toEqual([403, "step-up-required"]);
      expect(add.json?.maxAgeSeconds).toBe(600);
      const imp = await call("POST", "/api/v1/hosts/import", {
        ...stale,
        body: { csv: "stale2.example.test" },
      });
      expect([imp.status, problemCode(imp)]).toEqual([403, "step-up-required"]);
      const del = await call("DELETE", `/api/v1/hosts/${id}`, stale);
      expect([del.status, problemCode(del)]).toEqual([403, "step-up-required"]);
      const confirm = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        ...stale,
        body: { fingerprint: `SHA256:${"B".repeat(43)}` },
      });
      expect([confirm.status, problemCode(confirm)]).toEqual([403, "step-up-required"]);
      // Nothing happened.
      const rows = await t.db.select().from(schema.host).where(eq(schema.host.id, id));
      expect(rows[0]?.hostKeyStatus).toBe("pending");
      expect(
        await t.db.select().from(schema.host).where(eq(schema.host.address, "stale.example.test")),
      ).toHaveLength(0);

      expect((await call("GET", "/api/v1/hosts", stale)).status).toBe(200);
      expect((await call("POST", `/api/v1/hosts/${id}/host-key/scan`, stale)).status).toBe(202);
      expect(
        (
          await call("POST", "/api/v1/hosts/setup-script", {
            ...stale,
            body: { allowedSource: "192.0.2.10" },
          })
        ).status,
      ).not.toBe(403);

      // With a fresh sign-in the same requests work.
      expect((await call("POST", "/api/v1/hosts", { body: { address: "fresh.example.test" } })).status).toBe(
        201,
      );
    });

    it("answers a bad request with the validation errors, not with the step-up demand", async () => {
      const r = await call("POST", "/api/v1/hosts", { age: STALE, body: { address: "-oProxyCommand=x" } });
      expect(r.status).toBe(422);
    });
  });

  describe("adding a server", () => {
    it("stores it, asks the worker for its host key and audits it", async () => {
      const r = await call("POST", "/api/v1/hosts", {
        body: { address: " Web-1.Example.test ", name: "Web 1", port: "2222" },
      });
      expect(r.status).toBe(201);
      const id = r.json?.id as string;
      const [row] = await t.db.select().from(schema.host).where(eq(schema.host.id, id));
      expect(row).toMatchObject({
        organizationId: ORG,
        name: "Web 1",
        address: "web-1.example.test",
        port: 2222,
        sshUser: "garnetops",
        source: "manual",
        hostKeyStatus: "pending",
        hostKey: null,
        createdBy: "user_a",
      });
      expect(queue.sent.map((j) => [j.name, j.data])).toEqual(
        expect.arrayContaining([
          ["host.keyscan", { hostId: id }],
          ["host.access-key", { organizationId: ORG }],
        ]),
      );
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        action: "host.created",
        actorUserId: "user_a",
        organizationId: ORG,
        ip: "198.51.100.7",
      });
      expect(audit[0]?.data).toEqual({
        name: "Web 1",
        address: "web-1.example.test",
        port: 2222,
        source: "manual",
      });
    });

    it("names every wrong field with a code, and refuses unsafe addresses", async () => {
      const r = await call("POST", "/api/v1/hosts", {
        body: { address: "127.0.0.1", name: "x".repeat(200), port: 70000 },
      });
      expect(r.status).toBe(422);
      expect(r.json?.errors).toEqual([
        { path: "address", message: "address_reserved" },
        { path: "name", message: "name_invalid" },
        { path: "port", message: "port_range" },
      ]);
      for (const address of [
        "-oProxyCommand=id",
        "a b",
        "user@host",
        "169.254.169.254",
        "localhost",
        "127.1",
        "host;id",
        "$(id)",
      ]) {
        expect((await call("POST", "/api/v1/hosts", { body: { address } })).status, address).toBe(422);
      }
      expect((await call("POST", "/api/v1/hosts", { body: {} })).status).toBe(422);
    });

    it("refuses a server that is already there (same address and port) but allows another port", async () => {
      expect((await call("POST", "/api/v1/hosts", { body: { address: "dup.example.test" } })).status).toBe(
        201,
      );
      const again = await call("POST", "/api/v1/hosts", { body: { address: "DUP.example.test", port: 22 } });
      expect([again.status, problemCode(again)]).toEqual([409, "duplicate"]);
      expect(
        (await call("POST", "/api/v1/hosts", { body: { address: "dup.example.test", port: 2200 } })).status,
      ).toBe(201);
    });
  });

  describe("CSV import", () => {
    it("adds the valid rows, skips duplicates and says what is wrong with the others", async () => {
      await call("POST", "/api/v1/hosts", { body: { address: "csv-known.example.test" } });
      queue.sent.length = 0;
      const csv = [
        "address,name,port",
        "csv-a.example.test,Server A,22",
        "csv-b.example.test,,2222",
        "csv-known.example.test,Known,22",
        "csv-a.example.test,Again,22",
        "127.0.0.1,Loopback,22",
        "csv-c.example.test,Bad port,99999",
        ",no address,22",
      ].join("\n");
      const r = await call("POST", "/api/v1/hosts/import", { body: { csv } });
      expect(r.status).toBe(201);
      expect(r.json?.created.map((x: { address: string }) => x.address)).toEqual([
        "csv-a.example.test",
        "csv-b.example.test",
      ]);
      expect(r.json?.skipped).toEqual([
        { line: 4, address: "csv-known.example.test", reason: "duplicate" },
        { line: 5, address: "csv-a.example.test", reason: "duplicate" },
      ]);
      expect(
        r.json?.invalid.map((x: { line: number; errors: { code: string }[] }) => [
          x.line,
          x.errors.map((e) => e.code),
        ]),
      ).toEqual([
        [6, ["address_reserved"]],
        [7, ["port_range"]],
        [8, ["address_empty"]],
      ]);
      const rows = await t.db.select().from(schema.host).where(eq(schema.host.source, "csv"));
      expect(rows.map((x) => [x.address, x.name, x.port]).sort()).toEqual([
        ["csv-a.example.test", "Server A", 22],
        ["csv-b.example.test", "csv-b.example.test", 2222],
      ]);
      expect(queue.sent.filter((j) => j.name === "host.keyscan")).toHaveLength(2);
      const audit = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "host.imported"));
      expect(audit[0]?.data).toEqual({ created: 2, skipped: 2, invalid: 3 });
    });

    it("takes at most 500 rows and refuses an empty or huge file as a whole", async () => {
      const many = Array.from({ length: 501 }, (_, i) => `many-${i}.example.test`).join("\n");
      const r = await call("POST", "/api/v1/hosts/import", { body: { csv: many } });
      expect([r.status, r.json?.errors]).toEqual([422, [{ path: "csv", message: "csv_too_many_rows" }]]);
      expect(
        (await call("POST", "/api/v1/hosts/import", { body: { csv: "address,name\n" } })).json?.errors,
      ).toEqual([{ path: "csv", message: "csv_empty" }]);
      const exactly = Array.from({ length: 500 }, (_, i) => `limit-${i}.example.test`).join("\n");
      const ok = await call("POST", "/api/v1/hosts/import", { body: { csv: exactly } });
      expect(ok.status).toBe(201);
      expect(ok.json?.created).toHaveLength(500);
    });
  });

  describe("host key confirmation", () => {
    const candidate = generateDeployKey("candidate").publicKey.split(" ")[1] as string;
    const candidateFp = fingerprint(candidate);
    const old = generateDeployKey("old").publicKey.split(" ")[1] as string;

    it("pins the key whose fingerprint the admin typed in, audits it and queues the first inventory", async () => {
      const id = await addHost({
        candidateKeyType: "ssh-ed25519",
        candidateKey: candidate,
        candidateKeyFingerprint: candidateFp,
      });
      const wrong = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        body: { fingerprint: `SHA256:${"A".repeat(43)}` },
      });
      expect([wrong.status, problemCode(wrong)]).toEqual([409, "fingerprint-mismatch"]);
      expect((await t.db.select().from(schema.host).where(eq(schema.host.id, id)))[0]?.hostKeyStatus).toBe(
        "pending",
      );

      const bad = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        body: { fingerprint: "not a fingerprint" },
      });
      expect(bad.status).toBe(422);

      const ok = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        body: { fingerprint: candidateFp },
      });
      expect(ok.status).toBe(200);
      const [row] = await t.db.select().from(schema.host).where(eq(schema.host.id, id));
      expect(row).toMatchObject({
        hostKeyStatus: "confirmed",
        hostKeyType: "ssh-ed25519",
        hostKey: candidate,
        hostKeyFingerprint: candidateFp,
        hostKeyConfirmedBy: "user_a",
        candidateKey: null,
        candidateKeyFingerprint: null,
        lastError: null,
      });
      const [run] = await t.db
        .select()
        .from(schema.hostInventoryRun)
        .where(eq(schema.hostInventoryRun.hostId, id));
      expect(run).toMatchObject({ state: "queued", trigger: "setup", requestedBy: "user_a" });
      expect(ok.json?.runId).toBe(run?.id);
      expect(queue.sent.find((j) => j.name === "host.inventory")?.data).toEqual({ runId: run?.id });
      const audit = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "host.key_confirmed"));
      expect(audit.find((a) => a.targetId === id)?.data).toEqual({
        address: row?.address,
        type: "ssh-ed25519",
        fingerprint: candidateFp,
        previous: null,
      });
      // Confirming twice does nothing the second time.
      const again = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        body: { fingerprint: candidateFp },
      });
      expect([again.status, problemCode(again)]).toEqual([409, "no-host-key"]);
    });

    it("replaces a pinned key only when the admin confirms the new fingerprint, and records the old one", async () => {
      const id = await addHost({
        hostKeyStatus: "changed",
        hostKeyType: "ssh-ed25519",
        hostKey: old,
        hostKeyFingerprint: fingerprint(old),
        candidateKeyType: "ssh-ed25519",
        candidateKey: candidate,
        candidateKeyFingerprint: candidateFp,
        lastError:
          "The server's host key changed. An admin must confirm the new fingerprint before the inventory runs again.",
      });
      // Confirming the old fingerprint is not enough.
      const stale = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        body: { fingerprint: fingerprint(old) },
      });
      expect(stale.status).toBe(409);
      expect((await call("POST", `/api/v1/hosts/${id}/inventory`)).status).toBe(409);

      const ok = await call("POST", `/api/v1/hosts/${id}/host-key/confirm`, {
        body: { fingerprint: candidateFp },
      });
      expect(ok.status).toBe(200);
      const [row] = await t.db.select().from(schema.host).where(eq(schema.host.id, id));
      expect(row).toMatchObject({ hostKeyStatus: "confirmed", hostKey: candidate, lastError: null });
      const audit = (await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id))).find(
        (a) => a.action === "host.key_confirmed",
      );
      expect(audit?.data).toMatchObject({ fingerprint: candidateFp, previous: fingerprint(old) });
      const [run] = await t.db
        .select()
        .from(schema.hostInventoryRun)
        .where(eq(schema.hostInventoryRun.hostId, id));
      expect(run?.trigger).toBe("manual");
    });

    it("can ask the worker to look at the host key again", async () => {
      const id = await addHost();
      expect((await call("POST", `/api/v1/hosts/${id}/host-key/scan`)).status).toBe(202);
      expect(queue.sent.map((j) => [j.name, j.data])).toEqual([["host.keyscan", { hostId: id }]]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((a) => a.action)).toContain("host.key_scan_requested");
    });
  });

  describe("inventory", () => {
    it("needs a confirmed host key, is queued once at a time and audited", async () => {
      const pending = await addHost();
      const refused = await call("POST", `/api/v1/hosts/${pending}/inventory`);
      expect([refused.status, problemCode(refused)]).toEqual([409, "host-key-unconfirmed"]);

      const id = await addHost({
        hostKeyStatus: "confirmed",
        hostKeyType: "ssh-ed25519",
        hostKey: "AAAA",
        hostKeyFingerprint: `SHA256:${"C".repeat(43)}`,
      });
      const first = await call("POST", `/api/v1/hosts/${id}/inventory`);
      expect(first.status).toBe(202);
      expect(first.json?.alreadyQueued).toBe(false);
      expect(queue.sent.filter((j) => j.name === "host.inventory")).toHaveLength(1);
      const second = await call("POST", `/api/v1/hosts/${id}/inventory`);
      expect([second.status, second.json?.alreadyQueued, second.json?.runId]).toEqual([
        200,
        true,
        first.json?.runId,
      ]);
      expect(queue.sent.filter((j) => j.name === "host.inventory")).toHaveLength(1);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.filter((a) => a.action === "host.inventory_requested")).toHaveLength(1);
    });
  });

  describe("deleting", () => {
    it("removes the server with its packages and findings, and audits who did it", async () => {
      const id = await addHost({ name: "to delete" });
      await t.db
        .insert(schema.hostPackage)
        .values({ id: "hpk_t1", organizationId: ORG, hostId: id, name: "bash", version: "5", type: "deb" });
      const r = await call("DELETE", `/api/v1/hosts/${id}`);
      expect(r.status).toBe(204);
      expect(await t.db.select().from(schema.host).where(eq(schema.host.id, id))).toHaveLength(0);
      expect(
        await t.db.select().from(schema.hostPackage).where(eq(schema.hostPackage.hostId, id)),
      ).toHaveLength(0);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((a) => [a.action, a.actorUserId])).toEqual([["host.deleted", "user_a"]]);
      expect((await call("DELETE", `/api/v1/hosts/${id}`)).status).toBe(404);
    });
  });

  describe("access key and setup script", () => {
    const key = generateDeployKey("garnetops-host-access");

    it("asks the worker for the key when there is none, and offers no script before", async () => {
      const before = await call("GET", "/api/v1/hosts/access");
      expect(before.json).toEqual({ ready: false });
      const post = await call("POST", "/api/v1/hosts/access");
      expect([post.status, post.json]).toEqual([202, { ready: false }]);
      expect(queue.sent.map((j) => [j.name, j.data])).toEqual([["host.access-key", { organizationId: ORG }]]);
      const script = await call("POST", "/api/v1/hosts/setup-script", {
        body: { allowedSource: "192.0.2.10" },
      });
      expect([script.status, problemCode(script)]).toEqual([409, "access-key-pending"]);
    });

    it("renders the script from the public key with the allowed source, remembers the source and audits", async () => {
      await t.db.insert(schema.hostAccessKey).values({
        id: "hak_t1",
        organizationId: ORG,
        publicKey: key.publicKey,
        fingerprint: fingerprint(key.publicKey.split(" ")[1] as string),
      });
      const access = await call("GET", "/api/v1/hosts/access");
      expect(access.json).toMatchObject({ ready: true, publicKey: key.publicKey, allowedSource: null });
      expect(JSON.stringify(access.json)).not.toContain("PRIVATE");

      const r = await call("POST", "/api/v1/hosts/setup-script", {
        body: { allowedSource: "192.0.2.0/24, 2001:db8::/32" },
      });
      expect(r.status).toBe(200);
      expect(r.json?.script).toContain('ALLOWED_SOURCE="192.0.2.0/24,2001:db8::/32"');
      expect(r.json?.script).toContain(`PUBLIC_KEY="${key.publicKey}"`);
      expect(r.json?.sha256).toBe(createHash("sha256").update(r.json?.script).digest("hex"));
      expect(r.json?.filename).toBe("garnetops-host-setup.sh");
      expect(r.json?.allowedSource).toBe("192.0.2.0/24,2001:db8::/32");
      expect((await call("GET", "/api/v1/hosts/access")).json?.allowedSource).toBe(
        "192.0.2.0/24,2001:db8::/32",
      );
      const audit = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "host.setup_script_created"));
      expect(audit[0]?.data).toMatchObject({
        allowedSource: "192.0.2.0/24,2001:db8::/32",
        sha256: r.json?.sha256,
      });
    });

    it("insists on an allowed source and refuses 'any address'", async () => {
      for (const allowedSource of [
        "",
        "  ",
        "0.0.0.0/0",
        "::/0",
        "*",
        "gateway.example.test",
        '192.0.2.1"; id #',
      ]) {
        const r = await call("POST", "/api/v1/hosts/setup-script", { body: { allowedSource } });
        expect(r.status, allowedSource).toBe(422);
        expect(r.json?.errors?.[0]?.path).toBe("allowedSource");
      }
      expect((await call("POST", "/api/v1/hosts/setup-script", { body: {} })).status).toBe(422);
    });
  });

  describe("one-time setup link", () => {
    async function link(allowedSource = "192.0.2.10") {
      const r = await call("POST", "/api/v1/hosts/setup-links", { body: { allowedSource } });
      expect(r.status).toBe(201);
      const url = new URL(r.json?.url as string);
      return { ...r.json, path: url.pathname, token: url.pathname.split("/").pop() as string } as {
        url: string;
        command: string;
        sha256: string;
        expiresAt: string;
        path: string;
        token: string;
      };
    }
    const download = (path: string, ip = "203.0.113.9") =>
      app.request(path, { headers: { "x-real-ip": ip } });

    it("gives a URL, a command with the checksum and a 60-minute expiry, and stores only a hash", async () => {
      const l = await link();
      expect(l.url).toMatch(/^https:\/\/garnetops\.example\.test\/api\/v1\/host-setup\/[A-Za-z0-9_-]{43}$/);
      expect(l.command).toBe(
        `curl -fsSLo garnetops-host-setup.sh '${l.url}' && echo "${l.sha256}  garnetops-host-setup.sh" | sha256sum -c - && sudo sh garnetops-host-setup.sh`,
      );
      const minutes = (new Date(l.expiresAt).getTime() - Date.now()) / 60_000;
      expect(minutes).toBeGreaterThan(59);
      expect(minutes).toBeLessThanOrEqual(60);
      const rows = await t.db.select().from(schema.hostSetupLink);
      const row = rows.find((x) => x.tokenHash === createHash("sha256").update(l.token).digest("hex"));
      expect(row).toMatchObject({
        organizationId: ORG,
        allowedSource: "192.0.2.10",
        scriptSha256: l.sha256,
        createdBy: "user_a",
        usedAt: null,
      });
      expect(JSON.stringify(rows)).not.toContain(l.token);
      const audit = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "host.setup_link_created"));
      expect(JSON.stringify(audit)).not.toContain(l.token);
    });

    it("serves exactly the script whose checksum was shown, once, without a session, and audits the use", async () => {
      const l = await link("198.51.100.0/24");
      const first = await download(l.path);
      expect(first.status).toBe(200);
      expect(first.headers.get("content-type")).toContain("text/x-shellscript");
      expect(first.headers.get("content-disposition")).toContain("garnetops-host-setup.sh");
      expect(first.headers.get("cache-control")).toBe("no-store");
      const script = await first.text();
      expect(createHash("sha256").update(script).digest("hex")).toBe(l.sha256);
      expect(script).toContain('ALLOWED_SOURCE="198.51.100.0/24"');
      expect(script).not.toContain("PRIVATE KEY");

      const second = await download(l.path);
      expect(second.status).toBe(404);
      const audit = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "host.setup_script_downloaded"));
      const mine = audit.filter((a) => (a.data as { sha256: string }).sha256 === l.sha256);
      expect(mine).toHaveLength(1);
      expect(mine[0]).toMatchObject({ organizationId: ORG, actorUserId: null, ip: "203.0.113.9" });
    });

    it("serves it once even when two servers ask at the same moment", async () => {
      const l = await link();
      const results = await Promise.all(Array.from({ length: 5 }, () => download(l.path)));
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(results.filter((r) => r.status === 404)).toHaveLength(4);
    });

    it("refuses expired, unknown and malformed tokens the same way", async () => {
      const l = await link();
      await t.db.update(schema.hostSetupLink).set({ expiresAt: new Date(Date.now() - 1000) });
      const expired = await download(l.path);
      expect(expired.status).toBe(404);
      for (const token of ["x".repeat(43), "short", `${"A".repeat(42)}$`, "../../etc/passwd"]) {
        const r = await download(`/api/v1/host-setup/${encodeURIComponent(token)}`);
        expect(r.status, token).toBe(404);
      }
      expect(await expired.json()).toEqual({ type: "about:blank", title: "Not found", status: 404 });
    });

    it("does not serve a script that is no longer the one the link was made for", async () => {
      const l = await link();
      await t.db
        .update(schema.hostSetupLink)
        .set({ scriptSha256: "0".repeat(64) })
        .where(eq(schema.hostSetupLink.tokenHash, createHash("sha256").update(l.token).digest("hex")));
      expect((await download(l.path)).status).toBe(410);
      // The link was not used up by the refusal.
      const [row] = await t.db
        .select()
        .from(schema.hostSetupLink)
        .where(eq(schema.hostSetupLink.tokenHash, createHash("sha256").update(l.token).digest("hex")));
      expect(row?.usedAt).toBeNull();
    });

    it("limits how fast one address can try tokens", async () => {
      const statuses: number[] = [];
      for (let i = 0; i < 35; i++)
        statuses.push((await download(`/api/v1/host-setup/${"y".repeat(43)}`, "203.0.113.77")).status);
      expect(statuses.slice(0, 30).every((s) => s === 404)).toBe(true);
      expect(statuses.slice(30).every((s) => s === 429)).toBe(true);
      // Another address is not affected.
      expect((await download(`/api/v1/host-setup/${"y".repeat(43)}`, "203.0.113.78")).status).toBe(404);
    });

    it("lets only admins make links, and limits how many", async () => {
      expect(
        (
          await call("POST", "/api/v1/hosts/setup-links", {
            role: "member",
            body: { allowedSource: "192.0.2.10" },
          })
        ).status,
      ).toBe(403);
      let last = 201;
      for (let i = 0; i < 25; i++)
        last = (
          await call("POST", "/api/v1/hosts/setup-links", { org: ORG, body: { allowedSource: "192.0.2.10" } })
        ).status;
      expect(last).toBe(429);
    });
  });

  describe("lists", () => {
    const org = "org_list";
    const ids: string[] = [];

    async function listAll(query: string): Promise<{ id: string }[]> {
      const seen: { id: string }[] = [];
      let cursor: string | null = null;
      do {
        const r = await call(
          "GET",
          `/api/v1/hosts?pageSize=25${query}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
          { org },
        );
        expect(r.status, query).toBe(200);
        seen.push(...(r.json?.items ?? []));
        cursor = r.json?.next;
      } while (cursor);
      return seen;
    }

    beforeAll(async () => {
      await t.db.insert(schema.organization).values({ id: org, name: "List" });
      for (let i = 1; i <= 60; i++) {
        const id = `host_l${i}`;
        ids.push(id);
        await t.db.insert(schema.host).values({
          id,
          organizationId: org,
          name: `host-${String(i).padStart(2, "0")}`,
          address: `198.51.100.${i}`,
          hostKeyStatus: i % 7 === 0 ? "changed" : "confirmed",
          hostKey: "AAAAC3NzaC1lZDI1NTE5AAAAIsecretkeyblobnotforclients",
          hostKeyType: "ssh-ed25519",
          hostKeyFingerprint: `SHA256:${String(i).padStart(43, "x")}`,
          osName: i % 2 ? "Debian GNU/Linux 12" : "Ubuntu 24.04 LTS",
          packageCount: i % 5 === 0 ? null : 100 + i,
          pendingUpdates: i % 3 === 0 ? null : i,
          lastInventoryAt: i % 4 === 0 ? null : new Date(Date.now() - i * 3600_000),
          lastError: i === 3 ? "The server could not be reached." : null,
        });
      }
      await t.db.insert(schema.vulnerability).values([
        { id: "CVE-2099-2001", severity: "critical", cvssScore: 9.8 },
        { id: "CVE-2099-2002", severity: "high", cvssScore: 7.5 },
        { id: "CVE-2099-2003", severity: "medium", cvssScore: 5 },
      ]);
      let n = 0;
      for (const [host, vuln, severity, rank] of [
        ["host_l1", "CVE-2099-2001", "critical", 5],
        ["host_l1", "CVE-2099-2002", "high", 4],
        ["host_l2", "CVE-2099-2002", "high", 4],
        ["host_l3", "CVE-2099-2003", "medium", 3],
        ["host_l4", "CVE-2099-2001", "critical", 5],
      ] as const) {
        await t.db.insert(schema.hostFinding).values({
          id: `hfn_l${++n}`,
          organizationId: org,
          hostId: host,
          vulnerabilityId: vuln,
          dedupKey: `${host}|${vuln}|deb|libssl3`,
          packageName: "libssl3",
          packageVersion: "3.0.11",
          packageType: "deb",
          severity,
          severityRank: rank,
          state: host === "host_l4" ? "resolved" : "open",
          firstSeenRunId: "hrun_x",
          lastSeenRunId: "hrun_x",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        });
      }
    });

    it("pages through every server exactly once for every sort column and direction", async () => {
      for (const sort of [
        "name",
        "address",
        "os",
        "packages",
        "critical",
        "high",
        "medium",
        "updates",
        "lastInventory",
      ]) {
        for (const dir of ["asc", "desc"]) {
          const seen = await listAll(`&sort=${sort}&dir=${dir}`);
          expect(new Set(seen.map((x) => x.id)).size, `${sort} ${dir}`).toBe(seen.length);
          expect(seen.length, `${sort} ${dir}`).toBe(60);
        }
      }
      expect((await listAll("")).length).toBe(60);
    });

    it("sorts by vulnerabilities worst first and by name", async () => {
      const worst = await listAll("&sort=critical");
      expect(worst[0]?.id).toBe("host_l1"); // the only host with an open critical finding
      const names = (await listAll("&sort=name&dir=desc")).map((x: Json) => x.name);
      expect(names).toEqual([...names].sort().reverse());
    });

    it("counts open findings per severity, never counts resolved ones, and shows the host key state", async () => {
      const r = await call("GET", "/api/v1/hosts?pageSize=100&sort=name", { org });
      const byId = new Map<string, Json>(r.json?.items.map((x: Json) => [x.id, x]));
      expect(byId.get("host_l1")?.open).toEqual({ critical: 1, high: 1 });
      expect(byId.get("host_l4")?.open).toEqual({});
      expect(byId.get("host_l7")?.hostKey).toMatchObject({ status: "changed", type: "ssh-ed25519" });
      expect(byId.get("host_l7")?.hostKey.fingerprint).toMatch(/^SHA256:/);
    });

    it("never sends the key blobs or the SSH account's secrets to the browser", async () => {
      const r = await call("GET", "/api/v1/hosts?pageSize=100", { org });
      expect(r.text).not.toContain("secretkeyblob");
      const detail = await call("GET", "/api/v1/hosts/host_l1", { org });
      expect(detail.text).not.toContain("secretkeyblob");
    });

    it("searches name, address and operating system, with counts for the tabs", async () => {
      expect((await call("GET", "/api/v1/hosts?q=host-0", { org })).json?.total).toBe(9);
      expect((await call("GET", "/api/v1/hosts?q=198.51.100.1", { org })).json?.total).toBe(11); // 1, 10-19
      expect((await call("GET", "/api/v1/hosts?q=ubuntu", { org })).json?.total).toBe(30);
      expect((await call("GET", "/api/v1/hosts?q=%25", { org })).json?.total).toBe(0); // a wildcard is text
      const counts = await call("GET", "/api/v1/hosts/counts", { org });
      // vulnerable: host_l1, host_l2 (open critical or high); attention: changed keys (7, 14, … 56) and host_l3 (error).
      expect(counts.json).toEqual({ all: 60, vulnerable: 2, attention: 9 });
      expect((await call("GET", "/api/v1/hosts?status=vulnerable", { org })).json?.total).toBe(2);
      expect((await call("GET", "/api/v1/hosts?status=attention", { org })).json?.total).toBe(9);
    });

    it("lists packages, findings and runs of a server with the finding's score and exploitation data", async () => {
      await t.db.insert(schema.hostPackage).values([
        {
          id: "hpk_l1",
          organizationId: org,
          hostId: "host_l1",
          name: "libssl3",
          version: "3.0.11",
          type: "deb",
          upgradableTo: "3.0.12",
          securityUpdate: true,
        },
        { id: "hpk_l2", organizationId: org, hostId: "host_l1", name: "bash", version: "5.2", type: "deb" },
      ]);
      const all = await call("GET", "/api/v1/hosts/host_l1/packages", { org });
      expect(all.json?.items.map((p: Json) => p.name)).toEqual(["bash", "libssl3"]);
      const upgradable = await call("GET", "/api/v1/hosts/host_l1/packages?updatable=1", { org });
      expect(upgradable.json?.items.map((p: Json) => [p.name, p.upgradableTo, p.securityUpdate])).toEqual([
        ["libssl3", "3.0.12", true],
      ]);
      expect((await call("GET", "/api/v1/hosts/host_l1/packages?q=BASH", { org })).json?.total).toBe(1);

      const findings = await call("GET", "/api/v1/hosts/host_l1/findings", { org });
      expect(findings.json?.items.map((f: Json) => [f.vulnerabilityId, f.severity, f.cvssScore])).toEqual([
        ["CVE-2099-2001", "critical", 9.8],
        ["CVE-2099-2002", "high", 7.5],
      ]);
      expect((await call("GET", "/api/v1/hosts/host_l4/findings?state=all", { org })).json?.total).toBe(1);
      expect((await call("GET", "/api/v1/hosts/host_l4/findings", { org })).json?.total).toBe(0);
      expect((await call("GET", "/api/v1/hosts/host_l1/findings?severity=high", { org })).json?.total).toBe(
        1,
      );
      expect(
        (await call("GET", "/api/v1/hosts/host_l1/findings?sort=cvss&dir=asc", { org })).json?.items[0]
          ?.vulnerabilityId,
      ).toBe("CVE-2099-2002");

      for (let i = 0; i < 3; i++) {
        await t.db.insert(schema.hostInventoryRun).values({
          id: `hrun_l${i}`,
          organizationId: org,
          hostId: "host_l1",
          state: "succeeded",
          trigger: "schedule",
          createdAt: new Date(Date.now() - i * 60_000),
        });
      }
      const runs = await call("GET", "/api/v1/hosts/host_l1/runs", { org });
      expect(runs.json?.items.map((r: Json) => r.id)).toEqual(["hrun_l0", "hrun_l1", "hrun_l2"]);
      expect(runs.json?.next).toBeNull();
      const detail = await call("GET", "/api/v1/hosts/host_l1", { org });
      expect(detail.json?.run).toMatchObject({ id: "hrun_l0", state: "succeeded" });
      expect(detail.json?.states).toEqual({ open: 2 });
    });
  });
});
