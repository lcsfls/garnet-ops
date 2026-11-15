/**
 * Deprecated and yanked packages in the API (ADR 0051), against a throw-away database: the settings (admins with a recent sign-in,
 * https registries, excluded names), the Packages filter and its registry message, a repository's list, and nothing while the
 * module is off. Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
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
  const t = await create(target, "api_deprecated");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    QUEUES: { deprecatedCheck: "deprecated.check" },
    boss: { send: async (...args: unknown[]) => holder.sent.push(args) },
  };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_depr_a";

describe.skipIf(!adminUrl)("deprecated packages API", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(
    method: string,
    path: string,
    opts: { role?: string; user?: string; body?: unknown; stale?: boolean } = {},
  ) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-org": ORG,
        "x-role": opts.role ?? "member",
        "x-user": opts.user ?? "usr_member",
        "content-type": "application/json",
        ...(opts.stale ? { "x-stale": "1" } : {}),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const text = await res.text();
    return { status: res.status, json: (text ? JSON.parse(text) : null) as Json | null };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { deprecatedRoutes } = await import("./deprecated.ts");
    const { packageRoutes } = await import("./packages.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db.insert(schema.user).values([
      { id: "usr_member", name: "Member", email: "member@example.com" },
      { id: "usr_admin", name: "Admin", email: "admin@example.com" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: c.req.header("x-stale") ? new Date(0) : new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/deprecated", deprecatedRoutes as never);
    v1.route("/packages", packageRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
    await t.db.insert(schema.repository).values({
      id: "repo_d",
      organizationId: ORG,
      name: "app",
      url: "https://git.example.lan/app.git",
      authKind: "none",
    });
    const pkg = (id: string, type: string, name: string, version: string) => ({
      id,
      organizationId: ORG,
      repositoryId: "repo_d",
      scanId: "scan_x",
      name,
      version,
      type,
    });
    await t.db
      .insert(schema.repositoryPackage)
      .values([
        pkg("pk1", "npm", "rimraf", "2.7.1"),
        pkg("pk2", "npm", "lodash", "4.17.21"),
        pkg("pk3", "python", "requests", "2.0.0"),
      ]);
    const checkedAt = new Date();
    await t.db.insert(schema.packageStatus).values([
      {
        scope: "public",
        ecosystem: "npm",
        name: "rimraf",
        version: "2.7.1",
        state: "deprecated",
        message: "Use v4",
        checkedAt,
      },
      { scope: "public", ecosystem: "npm", name: "lodash", version: "4.17.21", state: "current", checkedAt },
      {
        scope: "public",
        ecosystem: "pypi",
        name: "requests",
        version: "2.0.0",
        state: "yanked",
        message: "Broken",
        checkedAt,
      },
      // What an own registry said is the organisation's; another organisation's never counts here.
      {
        scope: "org_other",
        ecosystem: "npm",
        name: "lodash",
        version: "4.17.21",
        state: "deprecated",
        checkedAt,
      },
    ]);
  });

  afterAll(async () => {
    await t?.drop();
  });

  it("shows nothing while the module is off", async () => {
    expect((await call("GET", "/api/v1/deprecated/repositories/repo_d")).status).toBe(409);
    expect((await call("POST", "/api/v1/deprecated/check")).status).toBe(409);
    const list = await call("GET", "/api/v1/packages?deprecated=1");
    expect(list.json?.items).toEqual([]);
    expect(
      (await call("GET", "/api/v1/packages")).json?.items.every((i: Json) => i.deprecation === null),
    ).toBe(true);
  });

  it("lists deprecated and yanked packages with the registry's message once it is on", async () => {
    await t.db.insert(schema.deprecationSettings).values({ organizationId: ORG, enabled: true });
    const list = await call("GET", "/api/v1/packages?deprecated=1");
    expect(list.json?.items.map((i: Json) => [i.name, i.deprecation])).toEqual([
      ["requests", { state: "yanked", message: "Broken" }],
      ["rimraf", { state: "deprecated", message: "Use v4" }],
    ]);
    const repo = await call("GET", "/api/v1/deprecated/repositories/repo_d");
    expect(repo.json?.items.map((i: Json) => [i.name, i.state])).toEqual([
      ["requests", "yanked"],
      ["rimraf", "deprecated"],
    ]);
    expect((await call("GET", "/api/v1/deprecated/repositories/repo_unknown")).status).toBe(404);
    expect((await call("POST", "/api/v1/deprecated/check")).status).toBe(202);
    expect(holder.sent.at(-1)?.[1]).toEqual({ organizationId: ORG });
    expect((await call("POST", "/api/v1/deprecated/check")).status).toBe(429);
  });

  it("settings: admins with a recent sign-in, https registries, excluded names; an own registry forgets the old answers", async () => {
    const body = {
      registries: { npm: "https://npm.example.lan:8443/repository/npm/" },
      excluded: ["@acme", "acme-*"],
    };
    expect((await call("PUT", "/api/v1/deprecated/settings", { body })).status).toBe(403);
    const stale = await call("PUT", "/api/v1/deprecated/settings", {
      role: "admin",
      user: "usr_admin",
      stale: true,
      body,
    });
    expect(stale.json?.type ?? stale.json?.code).toMatch(/step-up-required/);
    for (const bad of [
      { registries: { npm: "http://npm.example.lan" }, excluded: [] },
      { registries: { npm: "https://user:pw@npm.example.lan" }, excluded: [] },
      { registries: {}, excluded: ["*"] },
    ]) {
      expect(
        (await call("PUT", "/api/v1/deprecated/settings", { role: "admin", user: "usr_admin", body: bad }))
          .status,
      ).toBe(422);
    }
    await t.db.insert(schema.packageStatus).values({
      scope: ORG,
      ecosystem: "npm",
      name: "x",
      version: "1.0.0",
      state: "current",
      checkedAt: new Date(),
    });
    const saved = await call("PUT", "/api/v1/deprecated/settings", {
      role: "admin",
      user: "usr_admin",
      body,
    });
    expect(saved.json).toMatchObject({
      enabled: true,
      registries: { npm: "https://npm.example.lan:8443/repository/npm", pypi: null, crates: null },
      excluded: ["@acme", "acme-*"],
    });
    expect(await t.db.select().from(schema.packageStatus).where(eq(schema.packageStatus.scope, ORG))).toEqual(
      [],
    );
    // With an own npm registry, the public npm answers no longer count for this organisation.
    const list = await call("GET", "/api/v1/packages?deprecated=1");
    expect(list.json?.items.map((i: Json) => i.name)).toEqual(["requests"]);
    const [entry] = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "deprecated.settings_changed"));
    expect(entry?.data).toMatchObject({
      registries: { npm: "npm.example.lan:8443" },
      excluded: ["@acme", "acme-*"],
    });
  });
});
