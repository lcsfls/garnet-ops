/**
 * Switching a module on and off (ADR 0033) against a throw-away PostgreSQL database: only owners and admins may, both directions
 * are audited, `GET /me` tells the web app, and switching website monitoring off also switches stage 2 off and drops what
 * was waiting. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_modules");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: { send: async () => "job" }, QUEUES: {} };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

const ORG = "org_mod_a";
const modulesOf = (json: Record<string, unknown> | null) =>
  (json?.organization as { modules?: Record<string, boolean> } | undefined)?.modules;

describe.skipIf(!adminUrl)("modules (ADR 0033)", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(method: string, path: string, role = "admin", body?: unknown, stale = false) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-role": role,
        ...(stale ? { "x-stale": "1" } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, json: text ? (JSON.parse(text) as Record<string, unknown>) : null };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { organizationRoutes } = await import("./organization.ts");
    const { meRoutes } = await import("./me.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db
      .insert(schema.user)
      .values({ id: "user_mod", name: "Alex Example", email: "alex@example.test" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: "user_mod",
          email: "alex@example.test",
          name: "Alex Example",
          organizationId: ORG,
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: c.req.header("x-stale") ? new Date(0) : new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/organization", organizationRoutes as never);
    v1.route("/me", meRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("is off by default, and only owners and admins switch it", async () => {
    expect((await call("GET", "/api/v1/organization/modules", "viewer")).json).toEqual({
      websites: false,
      hosts: false,
    });
    expect(modulesOf((await call("GET", "/api/v1/me", "viewer")).json)).toEqual({
      websites: false,
      hosts: false,
    });
    for (const role of ["viewer", "member"]) {
      expect(
        (await call("PUT", "/api/v1/organization/modules/websites", role, { enabled: true })).status,
      ).toBe(403);
    }
    expect(
      (await call("PUT", "/api/v1/organization/modules/unknown", "admin", { enabled: true })).status,
    ).toBe(404);
    const on = await call("PUT", "/api/v1/organization/modules/websites", "admin", { enabled: true });
    expect(on).toEqual({ status: 200, json: { websites: true, hosts: false } });
    expect(modulesOf((await call("GET", "/api/v1/me", "viewer")).json)).toEqual({
      websites: true,
      hosts: false,
    });
    const audits = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.organizationId, ORG));
    expect(audits.map((a) => [a.action, a.data])).toEqual([
      ["organization.module_enabled", { module: "websites" }],
    ]);
  });

  it("adds a public DNS resolver only with an acknowledgement and a recent sign-in, audited both ways", async () => {
    const dns = "/api/v1/organization/dns";
    const off = await call("GET", dns, "viewer");
    expect(off.json).toMatchObject({ provider: null, enabledBy: null });
    expect(((off.json?.providers ?? []) as { id: string }[]).map((p) => p.id)).toEqual([
      "cloudflare",
      "google",
      "quad9",
    ]);
    expect((await call("PUT", dns, "member", { provider: "quad9", acknowledged: true })).status).toBe(403);
    expect((await call("PUT", dns, "admin", { provider: "quad9" })).status).toBe(422);
    expect((await call("PUT", dns, "admin", { provider: "quad9", acknowledged: true }, true)).status).toBe(
      403,
    );
    expect((await call("PUT", dns, "admin", { provider: "8.8.8.8", acknowledged: true })).status).toBe(422);
    const on = await call("PUT", dns, "admin", { provider: "quad9", acknowledged: true });
    expect(on.json).toMatchObject({ provider: "quad9", enabledBy: "Alex Example" });
    // Switching it off needs neither: it is the safe direction.
    const back = await call("PUT", dns, "admin", { provider: null }, true);
    expect(back.json).toMatchObject({ provider: null, enabledAt: null });
    const audits = await t.db
      .select({ action: schema.auditLog.action, data: schema.auditLog.data })
      .from(schema.auditLog)
      .where(eq(schema.auditLog.organizationId, ORG));
    expect(audits.filter((a) => a.action.startsWith("organization.public_dns"))).toEqual([
      {
        action: "organization.public_dns_enabled",
        data: { provider: "quad9", servers: ["9.9.9.9", "149.112.112.112"] },
      },
      { action: "organization.public_dns_disabled", data: { previous: "quad9" } },
    ]);
  });

  it("switching website monitoring off switches stage 2 off and drops waiting runs", async () => {
    await t.db.insert(schema.exposureAsset).values({
      id: "exa_mod1",
      organizationId: ORG,
      kind: "domain",
      value: "www.example.com",
      verifyToken: "M".repeat(43),
      verifyState: "verified",
      stage2Enabled: true,
      stage2AcknowledgedBy: "user_mod",
      stage2AcknowledgedAt: new Date(),
    });
    await t.db.insert(schema.exposureRun).values({
      id: "exr_mod1",
      organizationId: ORG,
      assetId: "exa_mod1",
      stage: "active",
      state: "queued",
      trigger: "schedule",
    });
    const off = await call("PUT", "/api/v1/organization/modules/websites", "owner", { enabled: false });
    expect(off).toEqual({ status: 200, json: { websites: false, hosts: false } });
    const [asset] = await t.db
      .select()
      .from(schema.exposureAsset)
      .where(eq(schema.exposureAsset.id, "exa_mod1"));
    expect(asset).toMatchObject({
      stage2Enabled: false,
      stage2AcknowledgedBy: null,
      verifyState: "verified",
    });
    const [run] = await t.db.select().from(schema.exposureRun).where(eq(schema.exposureRun.id, "exr_mod1"));
    expect(run).toMatchObject({ state: "failed", error: "moduleOff" });
    const actions = (await t.db.select().from(schema.auditLog)).map((a) => a.action);
    expect(actions).toContain("organization.module_disabled");
  });
});
