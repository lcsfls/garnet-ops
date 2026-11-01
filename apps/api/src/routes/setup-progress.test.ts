/**
 * "Getting started" (setup progress) against a throw-away PostgreSQL database on the development server: owners and admins only,
 * and each step is read from what is there in this organisation, not in another. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const shared = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null };
  const t = await create(target, "api_setup_progress");
  shared.db = t;
  return { db: t.db, pool: t.pool };
});

vi.mock("../env.ts", () => ({ env: {}, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_setup_a";
const OTHER = "org_setup_b";

describe.skipIf(!adminUrl)("Setup progress", () => {
  let t: TestDatabase;
  let app: Hono;
  const get = async (role = "admin", org = ORG) => {
    const res = await app.request("/setup", { headers: { "x-role": role, "x-org": org } });
    return { status: res.status, json: (res.status === 200 ? await res.json() : null) as Json };
  };
  const stepsOf = (json: Json) => Object.fromEntries(json.steps.map((s: Json) => [s.id, s.done]));

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { setupProgressRoutes } = await import("./setup-progress.ts");
    t = shared.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    const routes = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        { organizationId: c.req.header("x-org"), role: c.req.header("x-role") } as never,
      );
      await next();
    });
    routes.route("/setup", setupProgressRoutes as never);
    app = new Hono().onError(handleError).route("/", routes) as unknown as Hono;
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });

  it("is for owners and admins", async () => {
    expect((await get("member")).status).toBe(403);
    expect((await get("owner")).status).toBe(200);
  });

  it("starts with nothing done and ticks off what is there, in this organisation only", async () => {
    const first = await get();
    expect(first.json).toMatchObject({ done: 0, total: 6 });
    // Another organisation's repository and channel do not count.
    await t.db.insert(schema.repository).values({
      id: "repo_setup_other",
      organizationId: OTHER,
      name: "x",
      url: "https://git.example.com/x/x.git",
      authKind: "none",
    });
    expect((await get()).json?.done).toBe(0);

    await t.db.insert(schema.repository).values([
      {
        id: "repo_setup_a",
        organizationId: ORG,
        name: "a",
        url: "https://git.example.com/a/a.git",
        authKind: "none",
      },
      {
        id: "repo_setup_b",
        organizationId: ORG,
        name: "b",
        url: "https://git.example.com/a/b.git",
        authKind: "none",
        inactiveAt: new Date(),
      },
    ]);
    await t.db.insert(schema.repositoryWebhook).values({
      id: "hook_setup",
      organizationId: ORG,
      repositoryId: "repo_setup_a",
      pathId: "p".repeat(43),
      secretSealed: "v1.x",
    });
    await t.db.insert(schema.systemReport).values({
      key: "vulndb",
      data: {
        checkedAt: "2026-11-01T00:00:00Z",
        valid: true,
        problem: null,
        schemaVersion: "v6.1.10",
        builtAt: "2026-11-01T00:00:00Z",
        source: "anchore",
        providers: { available: false, items: [] },
      },
    });
    const later = await get();
    expect(stepsOf(later.json)).toEqual({
      forge: false,
      repositories: true,
      scanOnPush: true,
      notifications: false,
      vulnDb: true,
      ciGate: false,
    });
    // The inactive repository is not counted.
    expect(later.json.steps.find((s: { id: string }) => s.id === "scanOnPush")).toMatchObject({
      count: 1,
      total: 1,
    });
    expect(later.json.done).toBe(3);
  });
});
