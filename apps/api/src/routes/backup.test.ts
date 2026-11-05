/**
 * Backups (ADR 0046) in the API against a throw-away PostgreSQL database on the development server: only owners, only after a
 * recent sign-in, only with a long passphrase and one organisation; the passphrase reaches the worker only sealed, the job
 * carries ids only; one backup at a time; the download is for the owner who asked, until it expires, audited, and every owner
 * is told. Sessions are replaced by a header-driven actor; the job queue by a stand-in. Skipped without the development PostgreSQL.
 */
import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const shared = vi.hoisted(() => ({ db: null as unknown, sent: [] as unknown[][], privateKeyPem: "" }));
const AUTH = "b".repeat(48);

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  const boss = { send: async (...args: unknown[]) => shared.sent.push(args) };
  const QUEUES = { backupBuild: "backup.build" };
  if (!target) return { db: null, pool: null, boss, QUEUES };
  const t = await create(target, "api_backup");
  shared.db = t;
  return { db: t.db, pool: t.pool, boss, QUEUES };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  const pair = gen();
  shared.privateKeyPem = pair.privateKeyPem;
  return {
    env: { BETTER_AUTH_SECRET: AUTH, PUBLIC_URL: "https://garnetops.example.com" },
    isProduction: false,
    vaultPublicKey: load(pair.publicKeyPem),
  };
});

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_bkp";
const PASSPHRASE = "a long enough passphrase";

describe.skipIf(!adminUrl)("Backups", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(
    method: string,
    path: string,
    opts: { role?: string; user?: string; age?: number; body?: unknown } = {},
  ) {
    const res = await app.request(`/api/v1/backup${path === "/" ? "" : path}`, {
      method,
      headers: {
        "x-role": opts.role ?? "owner",
        "x-user": opts.user ?? "usr_a",
        "x-age": String(opts.age ?? 0),
        ...(opts.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const buffer = Buffer.from(await res.arrayBuffer());
    const json = res.headers.get("content-type")?.includes("json")
      ? (JSON.parse(buffer.toString()) as Json)
      : null;
    return { status: res.status, json, buffer, headers: res.headers };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { backupRoutes } = await import("./backup.ts");
    t = shared.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await t.db.insert(schema.user).values([
      { id: "usr_a", name: "Erika", email: "erika@example.test" },
      { id: "usr_b", name: "Max", email: "max@example.test" },
    ]);
    await t.db.insert(schema.membership).values([
      { organizationId: ORG, userId: "usr_a", role: "owner" },
      { organizationId: ORG, userId: "usr_b", role: "owner" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "someone@example.test",
          name: "Someone",
          organizationId: ORG,
          role: c.req.header("x-role"),
          ip: "198.51.100.7",
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/backup", backupRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  beforeEach(async () => {
    shared.sent.length = 0;
    await t.db.delete(schema.backupRun);
    await t.db.delete(schema.rateLimit);
  });

  afterAll(async () => {
    await t?.drop();
  });

  it("is for owners only, after a recent sign-in, with a long passphrase", async () => {
    expect((await call("POST", "/", { role: "admin", body: { passphrase: PASSPHRASE } })).status).toBe(403);
    expect((await call("GET", "/", { role: "admin" })).status).toBe(403);
    const stale = await call("POST", "/", { age: 11 * 60, body: { passphrase: PASSPHRASE } });
    expect(stale.json?.type).toMatch(/step-up-required/);
    const short = await call("POST", "/", { body: { passphrase: "too short" } });
    expect(short.status).toBe(422);
    expect(shared.sent).toHaveLength(0);
  });

  it("seals the passphrase for the worker and queues ids only", async () => {
    const res = await call("POST", "/", { body: { passphrase: PASSPHRASE } });
    expect(res.status).toBe(202);
    const id = res.json?.id as string;
    expect(shared.sent).toEqual([["backup.build", { runId: id, organizationId: ORG }, { retryLimit: 0 }]]);
    const [run] = await t.db.select().from(schema.backupRun).where(eq(schema.backupRun.id, id));
    expect(run?.state).toBe("pending");
    const [secret] = await t.db
      .select()
      .from(schema.secret)
      .where(eq(schema.secret.id, run?.secretId as string));
    expect(JSON.stringify(secret)).not.toContain(PASSPHRASE);
    const plain = open(
      secret?.sealed,
      { organizationId: ORG, recordId: secret?.id as string, purpose: "backup-request" },
      loadVaultPrivateKey(shared.privateKeyPem),
    ).toString();
    expect(JSON.parse(plain)).toEqual({ passphrase: PASSPHRASE, authSecret: AUTH });
    // One at a time.
    expect((await call("POST", "/", { body: { passphrase: PASSPHRASE } })).json?.type).toMatch(
      /backup-running/,
    );
    const audit = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "backup.requested"));
    expect(audit.length).toBeGreaterThan(0);
  });

  it("lets only the owner who asked download it, until it expires, and tells every owner", async () => {
    const now = new Date();
    await t.db.insert(schema.backupRun).values({
      id: "bkp_ready",
      organizationId: ORG,
      requestedBy: "usr_a",
      state: "ready",
      sizeBytes: 6,
      sha256: "0".repeat(64),
      readyAt: now,
      expiresAt: new Date(now.getTime() + 3600_000),
    });
    await t.db.insert(schema.backupChunk).values([
      { runId: "bkp_ready", seq: 0, data: Buffer.from("abc") },
      { runId: "bkp_ready", seq: 1, data: Buffer.from("def") },
    ]);
    const list = await call("GET", "/", { user: "usr_b" });
    expect(list.json?.items[0]).toMatchObject({ id: "bkp_ready", canDownload: false, requestedBy: "Erika" });
    expect((await call("GET", "/bkp_ready/download", { user: "usr_b" })).status).toBe(404);

    const res = await call("GET", "/bkp_ready/download");
    expect(res.status).toBe(200);
    expect(res.buffer.toString()).toBe("abcdef");
    expect(res.headers.get("content-disposition")).toMatch(/garnetops-backup-\d{4}-\d{2}-\d{2}\.age/);
    const told = await t.db.select().from(schema.userNotification);
    expect(told.map((row) => row.userId).sort()).toEqual(["usr_a", "usr_b"]);

    await t.db.update(schema.backupRun).set({ expiresAt: new Date(now.getTime() - 1000) });
    expect((await call("GET", "/bkp_ready/download")).status).toBe(410);
  });
});
