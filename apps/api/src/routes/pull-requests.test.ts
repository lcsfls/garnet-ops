/**
 * The pull request overview (ADR 0032) against a throw-away PostgreSQL database on the development server: the gate
 * result of each head commit (passed, a check waiting, none), filters, and "check now", which queues a check of the
 * pull request's ref like a CI pipeline and reuses one that is waiting. Sessions are replaced by a header-driven actor;
 * the queue is a recorder. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown, sent: [] as { name: string; data: unknown }[] }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_pulls");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: unknown) => {
        holder.sent.push({ name, data });
        return "job";
      },
    },
    QUEUES: { scanRepository: "scan.repository", pullRequestRefresh: "pull-requests.refresh" },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: load(gen().publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_pulls";
const SHA = (c: string) => c.repeat(40);

describe.skipIf(!adminUrl)("pull request overview", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(method: string, path: string, role = "member") {
    const res = await app.request(path, { method, headers: { "x-role": role } });
    const text = await res.text();
    return { status: res.status, json: (text ? JSON.parse(text) : null) as Json | null };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { pullRequestRoutes } = await import("./pull-requests.ts");
    t = holder.db as TestDatabase;
    const d = t.db;
    await d.insert(schema.organization).values({ id: ORG, name: "Example" });
    await d.insert(schema.user).values({ id: "user_a", name: "Alex Example", email: "alex@example.test" });
    await d.insert(schema.repository).values({
      id: "repo_a",
      organizationId: ORG,
      name: "web",
      url: "https://git.example.lan/team/web.git",
      authKind: "none",
      pullRequestsCheckedAt: new Date(),
    });
    const prs = [
      [1, "Passed one", SHA("a")],
      [2, "Being checked", SHA("b")],
      [3, "Never checked", SHA("c")],
    ] as const;
    for (const [number, title, headSha] of prs) {
      await d.insert(schema.pullRequest).values({
        id: `pr_${number}`,
        organizationId: ORG,
        repositoryId: "repo_a",
        number,
        title,
        url: `https://git.example.lan/team/web/pulls/${number}`,
        headSha,
        updatedAt: new Date(Date.now() - number * 60_000),
      });
    }
    await d.insert(schema.scan).values([
      {
        id: "scan_1",
        organizationId: ORG,
        repositoryId: "repo_a",
        state: "succeeded",
        trigger: "ci",
        ref: "refs/pull/1/head",
        commitSha: SHA("a"),
      },
      {
        id: "scan_2",
        organizationId: ORG,
        repositoryId: "repo_a",
        state: "queued",
        trigger: "manual",
        ref: "refs/pull/2/head",
        expectedSha: SHA("b"),
      },
    ]);
    // Another repository with a blocked run for the head commit of pull request 3: it must not count for it.
    await d.insert(schema.repository).values({
      id: "repo_b",
      organizationId: ORG,
      name: "api",
      url: "https://git.example.lan/team/api.git",
      authKind: "none",
    });
    await d.insert(schema.scan).values({
      id: "scan_b",
      organizationId: ORG,
      repositoryId: "repo_b",
      state: "succeeded",
      trigger: "ci",
      commitSha: SHA("c"),
    });
    await d.insert(schema.gateRun).values({
      id: "gate_b",
      organizationId: ORG,
      repositoryId: "repo_b",
      scanId: "scan_b",
      result: "blocked",
      matches: {},
    });
    await d.insert(schema.gateRun).values({
      id: "gate_1",
      organizationId: ORG,
      repositoryId: "repo_a",
      scanId: "scan_1",
      result: "passed",
      matches: {},
    });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: "user_a",
          organizationId: ORG,
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/pull-requests", pullRequestRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  }, 60_000);

  beforeEach(async () => {
    holder.sent.length = 0;
    await t.db.delete(schema.rateLimit);
  });

  it("shows each pull request with the gate result of its head commit", async () => {
    const { json } = await call("GET", "/api/v1/pull-requests");
    expect(json?.items.map((i: Json) => [i.number, i.gate?.result ?? null, i.checking])).toEqual([
      [1, "passed", false],
      [2, null, true],
      [3, null, false],
    ]);
    expect(
      (await call("GET", "/api/v1/pull-requests?gate=none")).json?.items.map((i: Json) => i.number),
    ).toEqual([3]);
    expect(
      (await call("GET", "/api/v1/pull-requests?gate=checking")).json?.items.map((i: Json) => i.number),
    ).toEqual([2]);
    expect(
      (await call("GET", "/api/v1/pull-requests?q=passed")).json?.items.map((i: Json) => i.number),
    ).toEqual([1]);
    expect((await call("GET", "/api/v1/pull-requests/sources")).json).toEqual([
      { id: "repo_b", name: "api", checkedAt: null, problem: null, open: 0 },
      { id: "repo_a", name: "web", checkedAt: expect.any(String), problem: null, open: 3 },
    ]);
  });

  it("checks a pull request's ref and head commit, reusing a check that waits", async () => {
    expect((await call("POST", "/api/v1/pull-requests/pr_3/check", "viewer")).status).toBe(403);
    const first = await call("POST", "/api/v1/pull-requests/pr_3/check");
    expect(first.status).toBe(202);
    const [scan] = await t.db.select().from(schema.scan).where(eq(schema.scan.id, first.json?.scanId));
    expect(scan).toMatchObject({
      ref: "refs/pull/3/head",
      expectedSha: SHA("c"),
      state: "queued",
      trigger: "manual",
    });
    expect((await call("POST", "/api/v1/pull-requests/pr_3/check")).json).toEqual({
      scanId: first.json?.scanId,
      reused: true,
    });
    expect((await call("POST", "/api/v1/pull-requests/pr_missing/check")).status).toBe(404);
  });

  it("asks the worker to read again, for members", async () => {
    expect((await call("POST", "/api/v1/pull-requests/refresh", "viewer")).status).toBe(403);
    expect((await call("POST", "/api/v1/pull-requests/refresh")).json).toEqual({ queued: 2 });
    expect(holder.sent).toEqual([
      {
        name: "pull-requests.refresh",
        data: { organizationId: ORG, repositoryIds: expect.arrayContaining(["repo_a", "repo_b"]) },
      },
    ]);
  });
});
