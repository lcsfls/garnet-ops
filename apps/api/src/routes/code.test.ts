/**
 * The code viewer API (ADR 0048) against a throw-away database on the development server: who may ask, one clone at a time per
 * organisation, the audit entry, and the result handed over once to the person who asked. Sessions are replaced by a
 * header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown, sent: [] as unknown[][] }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_code");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    QUEUES: { codeFetch: "code.fetch" },
    boss: { send: async (...args: unknown[]) => holder.sent.push(args) },
  };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_code_a";

describe.skipIf(!adminUrl)("code viewer API", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(method: string, path: string, opts: { role?: string; user?: string } = {}) {
    const res = await app.request(path, {
      method,
      headers: { "x-org": ORG, "x-role": opts.role ?? "member", "x-user": opts.user ?? "usr_member" },
    });
    const text = await res.text();
    return {
      status: res.status,
      cache: res.headers.get("cache-control"),
      json: (text ? JSON.parse(text) : null) as Json | null,
    };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { codeRoutes } = await import("./code.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db.insert(schema.user).values([
      { id: "usr_member", name: "Member", email: "member@example.com" },
      { id: "usr_other", name: "Other", email: "other@example.com" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/code", codeRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
    await t.db.insert(schema.repository).values([
      {
        id: "repo_shared",
        organizationId: ORG,
        name: "shared",
        url: "https://git.example.lan/shared.git",
        authKind: "none",
      },
      {
        id: "repo_private",
        organizationId: ORG,
        name: "private",
        url: "https://git.example.lan/private.git",
        authKind: "none",
        visibility: "private",
        ownerUserId: "usr_other",
      },
    ]);
    await t.db.insert(schema.scan).values({
      id: "scan_c",
      organizationId: ORG,
      repositoryId: "repo_shared",
      state: "succeeded",
      trigger: "manual",
      commitSha: "a".repeat(40),
    });
    await t.db.insert(schema.vulnerability).values({ id: "GHSA-code-api-0001", severity: "high" });
    const now = new Date();
    const finding = (id: string, repositoryId: string) => ({
      id,
      organizationId: ORG,
      repositoryId,
      vulnerabilityId: "GHSA-code-api-0001",
      dedupKey: id,
      packageName: "lodash",
      packageVersion: "4.17.15",
      packageType: "npm",
      severity: "high",
      severityRank: 4,
      state: "open" as const,
      firstSeenScanId: "scan_c",
      lastSeenScanId: "scan_c",
      firstSeenAt: now,
      lastSeenAt: now,
    });
    await t.db
      .insert(schema.finding)
      .values([finding("fnd_shared", "repo_shared"), finding("fnd_private", "repo_private")]);
  });

  afterAll(async () => {
    await t?.drop();
  });

  it("lets members and above ask for a finding they see, one clone at a time, and audits it", async () => {
    expect((await call("POST", "/api/v1/code/findings/fnd_shared", { role: "viewer" })).status).toBe(403);
    expect((await call("POST", "/api/v1/code/findings/fnd_private")).status).toBe(404);
    const asked = await call("POST", "/api/v1/code/findings/fnd_shared");
    expect(asked.status).toBe(202);
    expect(asked.cache).toBe("no-store");
    expect(holder.sent.at(-1)).toEqual([
      "code.fetch",
      { requestId: asked.json?.id },
      { retryLimit: 0, expireInSeconds: 180 },
    ]);
    // A second request of the organisation waits for the first.
    expect((await call("POST", "/api/v1/code/findings/fnd_shared")).status).toBe(409);
    const [entry] = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "code.viewed"));
    expect(entry).toMatchObject({ targetId: "fnd_shared" });
    expect(entry?.data).toMatchObject({
      repositoryId: "repo_shared",
      package: "lodash",
      commit: "a".repeat(40),
    });
  });

  it("hands the result over once, to the person who asked only", async () => {
    const [row] = await t.db.select().from(schema.codeRequest);
    const path = `/api/v1/code/requests/${row?.id}`;
    expect((await call("GET", path)).json).toEqual({ state: "queued" });
    expect((await call("GET", path, { user: "usr_other" })).status).toBe(404);
    await t.db
      .update(schema.codeRequest)
      .set({ state: "done", result: { commit: "a".repeat(40), declarations: [] } })
      .where(eq(schema.codeRequest.id, row?.id as string));
    const done = await call("GET", path);
    expect(done).toMatchObject({ status: 200, cache: "no-store" });
    expect(done.json).toEqual({ state: "done", result: { commit: "a".repeat(40), declarations: [] } });
    expect((await call("GET", path)).status).toBe(404);
    // With nothing running, the organisation may ask again.
    expect((await call("POST", "/api/v1/code/findings/fnd_shared")).status).toBe(202);
  });
});
