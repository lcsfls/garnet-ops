/**
 * The exposure API (ADR 0023) against a throw-away PostgreSQL database on the development server: who may read and change, which
 * actions need a recent sign-in and an acknowledgement, asset validation (public addresses only, RFC 1123 names, 200 per organisation,
 * no duplicates), the proof of control and its effect on stage 2, the Certificate Transparency opt-in, the audit trail, organisation
 * isolation and the rate limit. Sessions are replaced by a header-driven actor; the queue is a recorder. Skipped without the
 * development PostgreSQL.
 */

import { ACTIVE_LIMITS, STAGE2_ACKNOWLEDGEMENT_ID, verifyRecordValue } from "@garnetops/core/exposure";
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
  const t = await create(target, "api_exposure");
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
    QUEUES: { exposureVerify: "exposure.verify", exposureRun: "exposure.run" },
  };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_ex_a";
const OTHER = "org_ex_b";
const STALE = 11 * 60;
const HOUR = 3_600_000;

describe.skipIf(!adminUrl)("Exposure API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;
  let policy: { allowTestRanges: boolean };

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
  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog)).filter((row) => row.action === action);

  async function addAsset(over: Partial<typeof schema.exposureAsset.$inferInsert> = {}) {
    const n = ++counter;
    const id = `exa_apitest${String(n).padStart(10, "0")}`;
    await t.db.insert(schema.exposureAsset).values({
      id,
      organizationId: ORG,
      kind: "domain",
      value: `asset${n}.example.com`,
      verifyToken: `T${String(n).padStart(2, "0")}${"x".repeat(40)}`,
      ...over,
    });
    return id;
  }
  const row = async (id: string) =>
    (
      await t.db.select().from(schema.exposureAsset).where(eq(schema.exposureAsset.id, id))
    )[0] as typeof schema.exposureAsset.$inferSelect;
  const verified = (extra: Partial<typeof schema.exposureAsset.$inferInsert> = {}) =>
    addAsset({
      verifyState: "verified",
      verifyMethod: "dns",
      verifiedAt: new Date(),
      verifyCheckedAt: new Date(),
      ...extra,
    });
  const stage2Body = (extra: Record<string, unknown> = {}) => ({
    enabled: true,
    schedule: "daily",
    acknowledgement: STAGE2_ACKNOWLEDGEMENT_ID,
    confirmed: true,
    ...extra,
  });

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { exposureRoutes } = await import("./exposure.ts");
    const { exposurePolicy } = await import("../lib/exposure-policy.ts");
    policy = exposurePolicy;
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
    v1.route("/exposure", exposureRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(() => {
    queue.sent.length = 0;
    policy.allowTestRanges = false;
  });

  describe("who may do what", () => {
    it("lets every member of the organisation read, and shows the proof only to owners and admins", async () => {
      const id = await addAsset();
      for (const role of ["viewer", "member", "admin", "owner"] as Role[]) {
        for (const path of [
          "/api/v1/exposure",
          "/api/v1/exposure/counts",
          "/api/v1/exposure/settings",
          `/api/v1/exposure/${id}`,
        ]) {
          expect((await call("GET", path, { role })).status, `${role} ${path}`).toBe(200);
        }
        const detail = await call("GET", `/api/v1/exposure/${id}`, { role });
        const admin = role === "admin" || role === "owner";
        expect(detail.json?.instructions !== null, role).toBe(admin);
        if (admin) {
          expect(detail.json?.instructions.value).toBe(verifyRecordValue((await row(id)).verifyToken));
          expect(detail.json?.instructions.dns.name).toBe(`_garnetops-challenge.${(await row(id)).value}`);
        }
      }
    });

    it("lets only owners and admins change anything", async () => {
      const id = await addAsset();
      const writes: [string, string, unknown][] = [
        ["POST", "/api/v1/exposure", { value: "new.example.com" }],
        ["PATCH", `/api/v1/exposure/${id}`, { includeSubdomains: true }],
        ["DELETE", `/api/v1/exposure/${id}`, undefined],
        ["POST", `/api/v1/exposure/${id}/verify`, undefined],
        ["POST", `/api/v1/exposure/${id}/verify/rotate`, undefined],
        ["POST", `/api/v1/exposure/${id}/run`, undefined],
        ["PUT", `/api/v1/exposure/${id}/stage2`, stage2Body()],
        ["POST", `/api/v1/exposure/${id}/stage2/run`, undefined],
        ["PUT", "/api/v1/exposure/settings", { ct: { enabled: true, acknowledged: true } }],
        ["POST", "/api/v1/exposure/discoveries/exd_none/add", undefined],
        ["POST", "/api/v1/exposure/discoveries/exd_none/dismiss", undefined],
      ];
      for (const role of ["viewer", "member"] as Role[]) {
        for (const [method, path, body] of writes) {
          const r = await call(method, path, { role, body });
          expect(r.status, `${role} ${method} ${path}`).toBe(403);
          expect(problemCode(r)).toBe("forbidden");
        }
      }
      expect(queue.sent).toEqual([]);
      expect(await row(id)).toMatchObject({ includeSubdomains: false, stage2Enabled: false });
    });

    it("keeps organisations apart", async () => {
      const id = await addAsset();
      for (const [method, path, body] of [
        ["GET", `/api/v1/exposure/${id}`, undefined],
        ["PATCH", `/api/v1/exposure/${id}`, { includeSubdomains: true }],
        ["DELETE", `/api/v1/exposure/${id}`, undefined],
        ["POST", `/api/v1/exposure/${id}/verify`, undefined],
        ["POST", `/api/v1/exposure/${id}/verify/rotate`, undefined],
        ["POST", `/api/v1/exposure/${id}/run`, undefined],
        ["PUT", `/api/v1/exposure/${id}/stage2`, stage2Body()],
        ["POST", `/api/v1/exposure/${id}/stage2/run`, undefined],
      ] as [string, string, unknown][]) {
        expect((await call(method, path, { org: OTHER, body })).status, `${method} ${path}`).toBe(404);
      }
      expect(((await call("GET", "/api/v1/exposure", { org: OTHER })).json as Json).items).toEqual([]);
      expect((await call("GET", "/api/v1/exposure/counts", { org: OTHER })).json).toMatchObject({ all: 0 });
      expect(queue.sent).toEqual([]);
      expect(await row(id)).toMatchObject({ organizationId: ORG });
    });

    it("does not let one organisation's suggestions be added by another", async () => {
      const id = await addAsset();
      await t.db.insert(schema.exposureDiscovery).values({
        id: "exd_apitest0000000001",
        organizationId: ORG,
        assetId: id,
        name: "found.example.com",
        source: "ct",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
      expect(
        (await call("POST", "/api/v1/exposure/discoveries/exd_apitest0000000001/add", { org: OTHER })).status,
      ).toBe(404);
      expect(
        (await call("POST", "/api/v1/exposure/discoveries/exd_apitest0000000001/dismiss", { org: OTHER }))
          .status,
      ).toBe(404);
    });
  });

  describe("adding an asset", () => {
    it("normalises the name, creates a proof token, audits and queues a first look and a proof check", async () => {
      const r = await call("POST", "/api/v1/exposure", { body: { value: "  WWW.Example.COM. " } });
      expect(r.status).toBe(201);
      const created = await row(r.json?.id);
      expect(created).toMatchObject({
        organizationId: ORG,
        kind: "domain",
        value: "www.example.com",
        verifyState: "unverified",
        stage2Enabled: false,
        includeSubdomains: false,
        passiveEnabled: true,
        createdBy: "user_a",
      });
      expect(created.verifyToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const added = (await audits("exposure.asset_added")).find((a) => a.targetId === created.id);
      expect(added?.data).toMatchObject({ value: "www.example.com", kind: "domain", source: "manual" });
      expect(queue.sent.map((s) => s.name).sort()).toEqual(["exposure.run", "exposure.verify"]);
      const run = queue.sent.find((s) => s.name === "exposure.run");
      expect(run?.options).toMatchObject({ retryLimit: 0, singletonKey: `${created.id}:passive` });
      const [queued] = await t.db
        .select()
        .from(schema.exposureRun)
        .where(eq(schema.exposureRun.assetId, created.id));
      expect(queued).toMatchObject({
        stage: "passive",
        state: "queued",
        trigger: "manual",
        requestedBy: "user_a",
      });
    });

    it("does not need a recent sign-in: adding only starts a look any browser could make", async () => {
      const r = await call("POST", "/api/v1/exposure", {
        age: STALE,
        body: { value: "stale-session.example.com" },
      });
      expect(r.status).toBe(201);
    });

    it("refuses what is not a public host name or address, with a code per reason", async () => {
      const cases: [string, string][] = [
        ["", "empty"],
        ["https://example.com", "url"],
        ["example.com/x", "url"],
        ["*.example.com", "wildcard"],
        ["intranet", "singleLabel"],
        ["bad_label.example.com", "label"],
        ["router.lan", "reservedName"],
        ["host.internal", "reservedName"],
        ["127.1", "numericTld"],
        ["10.0.0.1", "notPublic"],
        ["192.168.1.1", "notPublic"],
        ["169.254.169.254", "notPublic"],
        ["127.0.0.1", "notPublic"],
        ["::1", "notPublic"],
        ["192.0.2.10", "notPublic"],
        ["198.51.100.10", "notPublic"],
        ["2001:db8::1", "notPublic"],
        ["fd00::1", "notPublic"],
      ];
      const before = (await t.db.select().from(schema.exposureAsset)).length;
      for (const [value, code] of cases) {
        const r = await call("POST", "/api/v1/exposure", { body: { value } });
        expect([r.status, r.json?.errors?.[0]?.message], value).toEqual([422, code]);
      }
      expect((await t.db.select().from(schema.exposureAsset)).length).toBe(before);
      expect(queue.sent).toEqual([]);
    });

    it("accepts a public address, and the documentation ranges only under the test hook", async () => {
      expect((await call("POST", "/api/v1/exposure", { body: { value: "93.184.216.34" } })).status).toBe(201);
      expect((await call("POST", "/api/v1/exposure", { body: { value: "192.0.2.77" } })).status).toBe(422);
      policy.allowTestRanges = true;
      expect((await call("POST", "/api/v1/exposure", { body: { value: "192.0.2.77" } })).status).toBe(201);
      // Link-local and metadata addresses stay refused, whatever the hook says.
      expect((await call("POST", "/api/v1/exposure", { body: { value: "169.254.169.254" } })).status).toBe(
        422,
      );
      // Outside the test runner the hook means nothing.
      const mode = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";
      try {
        expect((await call("POST", "/api/v1/exposure", { body: { value: "192.0.2.78" } })).status).toBe(422);
      } finally {
        process.env.NODE_ENV = mode as string;
      }
    });

    it("refuses a duplicate, also in another notation", async () => {
      expect((await call("POST", "/api/v1/exposure", { body: { value: "dup.example.com" } })).status).toBe(
        201,
      );
      for (const again of ["DUP.example.com", "dup.example.com.", " dup.example.com "]) {
        const r = await call("POST", "/api/v1/exposure", { body: { value: again } });
        expect([r.status, problemCode(r)], again).toEqual([409, "duplicate"]);
      }
      // Another organisation may watch the same name.
      expect(
        (await call("POST", "/api/v1/exposure", { org: OTHER, body: { value: "dup.example.com" } })).status,
      ).toBe(201);
    });

    it("stops at 200 assets per organisation", async () => {
      const org = "org_ex_full";
      await t.db.insert(schema.organization).values({ id: org, name: "Full" });
      await t.db.insert(schema.exposureAsset).values(
        Array.from({ length: 200 }, (_, i) => ({
          id: `exa_full${String(i).padStart(12, "0")}`,
          organizationId: org,
          kind: "domain" as const,
          value: `full${i}.example.com`,
          verifyToken: `F${String(i).padStart(3, "0")}${"y".repeat(39)}`,
        })),
      );
      const r = await call("POST", "/api/v1/exposure", { org, body: { value: "one-too-many.example.com" } });
      expect([r.status, problemCode(r)]).toEqual([409, "limit-reached"]);
      expect((await call("GET", "/api/v1/exposure/counts", { org })).json).toMatchObject({
        all: 200,
        limit: 200,
      });
    });

    it("rate limits adding", async () => {
      const org = "org_ex_rate";
      await t.db.insert(schema.organization).values({ id: org, name: "Rate" });
      let last = 0;
      for (let i = 0; i < 62; i++) {
        last = (await call("POST", "/api/v1/exposure", { org, body: { value: `r${i}.example.com` } })).status;
        if (last === 429) break;
      }
      expect(last).toBe(429);
    });
  });

  describe("the proof of control", () => {
    it("queues a check, at most twelve an hour per asset", async () => {
      const id = await addAsset();
      for (let i = 0; i < 12; i++) {
        expect((await call("POST", `/api/v1/exposure/${id}/verify`)).status, String(i)).toBe(202);
      }
      expect((await call("POST", `/api/v1/exposure/${id}/verify`)).status).toBe(429);
      expect(queue.sent.filter((s) => s.name === "exposure.verify")).toHaveLength(12);
      expect(queue.sent[0]?.data).toEqual({ assetId: id });
    });

    it("a new token voids the proof, switches stage 2 off and needs a recent sign-in", async () => {
      const id = await verified({
        stage2Enabled: true,
        stage2AcknowledgedBy: "user_a",
        stage2AcknowledgedAt: new Date(),
      });
      const before = (await row(id)).verifyToken;
      const stale = await call("POST", `/api/v1/exposure/${id}/verify/rotate`, { age: STALE });
      expect([stale.status, problemCode(stale)]).toEqual([403, "step-up-required"]);
      expect((await row(id)).verifyToken).toBe(before);
      expect((await call("POST", `/api/v1/exposure/${id}/verify/rotate`)).status).toBe(204);
      const after = await row(id);
      expect(after.verifyToken).not.toBe(before);
      expect(after).toMatchObject({
        verifyState: "unverified",
        verifyMethod: null,
        stage2Enabled: false,
        stage2AcknowledgedAt: null,
      });
      expect((await audits("exposure.verification_reset")).some((a) => a.targetId === id)).toBe(true);
    });

    it("never shows the token of one asset in the list", async () => {
      const id = await addAsset();
      const token = (await row(id)).verifyToken;
      const list = await call("GET", "/api/v1/exposure?pageSize=100");
      expect(list.text).not.toContain(token);
    });
  });

  describe("stage 2", () => {
    it("needs a recent sign-in, the acknowledgement and a verified asset", async () => {
      const unverified = await addAsset();
      const ok = await verified();
      // Stale session.
      const stale = await call("PUT", `/api/v1/exposure/${ok}/stage2`, { age: STALE, body: stage2Body() });
      expect([stale.status, problemCode(stale)]).toEqual([403, "step-up-required"]);
      // No acknowledgement, a wrong one, or not confirmed.
      for (const bad of [
        { enabled: true, schedule: "daily" },
        stage2Body({ acknowledgement: "something-else" }),
        stage2Body({ confirmed: false }),
        stage2Body({ schedule: "hourly" }),
      ]) {
        expect((await call("PUT", `/api/v1/exposure/${ok}/stage2`, { body: bad })).status).toBe(422);
      }
      // Not verified.
      const refused = await call("PUT", `/api/v1/exposure/${unverified}/stage2`, { body: stage2Body() });
      expect([refused.status, problemCode(refused)]).toEqual([409, "not-verified"]);
      expect(await row(unverified)).toMatchObject({ stage2Enabled: false });
      expect(await row(ok)).toMatchObject({ stage2Enabled: false });
      expect(queue.sent).toEqual([]);
    });

    it("switches on with the acknowledgement written to the audit log, and queues the first run", async () => {
      const id = await verified();
      const r = await call("PUT", `/api/v1/exposure/${id}/stage2`, {
        role: "owner",
        body: stage2Body({ schedule: "weekly" }),
      });
      expect(r.status).toBe(200);
      const after = await row(id);
      expect(after).toMatchObject({
        stage2Enabled: true,
        stage2Schedule: "weekly",
        stage2AcknowledgedBy: "user_a",
      });
      expect(after.stage2AcknowledgedAt).not.toBeNull();
      const entry = (await audits("exposure.stage2_enabled")).find((a) => a.targetId === id);
      expect(entry).toMatchObject({ actorUserId: "user_a" });
      expect(entry?.data).toMatchObject({
        value: after.value,
        schedule: "weekly",
        acknowledgement: STAGE2_ACKNOWLEDGEMENT_ID,
        verifiedVia: "self",
        ports: 30,
      });
      const [queued] = await t.db.select().from(schema.exposureRun).where(eq(schema.exposureRun.assetId, id));
      expect(queued).toMatchObject({ stage: "active", state: "queued", trigger: "enable" });
      expect(queue.sent.map((s) => s.name)).toEqual(["exposure.run"]);
    });

    it("does not queue a run when the asset was checked in the last day", async () => {
      const id = await verified({ lastActiveAt: new Date(Date.now() - 2 * HOUR) });
      expect((await call("PUT", `/api/v1/exposure/${id}/stage2`, { body: stage2Body() })).status).toBe(200);
      expect(queue.sent).toEqual([]);
    });

    it("switches off without a recent sign-in and forgets the acknowledgement", async () => {
      const id = await verified({
        stage2Enabled: true,
        stage2AcknowledgedBy: "user_a",
        stage2AcknowledgedAt: new Date(),
      });
      const r = await call("PUT", `/api/v1/exposure/${id}/stage2`, { age: STALE, body: { enabled: false } });
      expect(r.status).toBe(200);
      expect(await row(id)).toMatchObject({
        stage2Enabled: false,
        stage2AcknowledgedBy: null,
        stage2AcknowledgedAt: null,
      });
      expect((await audits("exposure.stage2_disabled")).some((a) => a.targetId === id)).toBe(true);
    });

    it("covers a subdomain through a verified parent that includes subdomains, and stops it when that is switched off", async () => {
      const parent = await verified({ value: "parent.example.com", includeSubdomains: true });
      const child = await addAsset({ value: "app.parent.example.com" });
      const detail = await call("GET", `/api/v1/exposure/${child}`);
      expect(detail.json?.verification).toMatchObject({
        state: "unverified",
        effective: true,
        via: "parent",
        parent: { id: parent, value: "parent.example.com" },
      });
      expect((await call("PUT", `/api/v1/exposure/${child}/stage2`, { body: stage2Body() })).status).toBe(
        200,
      );
      expect(
        (await call("PATCH", `/api/v1/exposure/${parent}`, { body: { includeSubdomains: false } })).status,
      ).toBe(204);
      expect(await row(child)).toMatchObject({ stage2Enabled: false, stage2AcknowledgedAt: null });
      expect((await audits("exposure.stage2_stopped")).some((a) => a.targetId === child)).toBe(true);
      expect((await audits("exposure.include_subdomains_changed")).some((a) => a.targetId === parent)).toBe(
        true,
      );
    });

    it("does not cover a subdomain when the parent does not include subdomains (the default)", async () => {
      await verified({ value: "closed.example.com" });
      const child = await addAsset({ value: "app.closed.example.com" });
      expect((await call("GET", `/api/v1/exposure/${child}`)).json?.verification).toMatchObject({
        effective: false,
        via: null,
      });
      const r = await call("PUT", `/api/v1/exposure/${child}/stage2`, { body: stage2Body() });
      expect([r.status, problemCode(r)]).toEqual([409, "not-verified"]);
    });

    it("stops the subdomains of a removed parent", async () => {
      const parent = await verified({ value: "gone.example.com", includeSubdomains: true });
      const child = await addAsset({ value: "app.gone.example.com" });
      await call("PUT", `/api/v1/exposure/${child}/stage2`, { body: stage2Body() });
      expect((await call("DELETE", `/api/v1/exposure/${parent}`)).status).toBe(204);
      expect(await row(child)).toMatchObject({ stage2Enabled: false });
      expect((await audits("exposure.asset_removed")).some((a) => a.targetId === parent)).toBe(true);
    });

    it("runs by hand at most once a day, with a recent sign-in", async () => {
      const id = await verified({
        stage2Enabled: true,
        stage2AcknowledgedBy: "user_a",
        stage2AcknowledgedAt: new Date(),
      });
      const stale = await call("POST", `/api/v1/exposure/${id}/stage2/run`, { age: STALE });
      expect([stale.status, problemCode(stale)]).toEqual([403, "step-up-required"]);
      const ok = await call("POST", `/api/v1/exposure/${id}/stage2/run`);
      expect(ok.status).toBe(202);
      expect(queue.sent.map((s) => s.name)).toEqual(["exposure.run"]);
      expect((await audits("exposure.stage2_run_requested")).some((a) => a.targetId === id)).toBe(true);

      const recent = await verified({
        stage2Enabled: true,
        stage2AcknowledgedBy: "user_a",
        stage2AcknowledgedAt: new Date(),
        lastActiveAt: new Date(Date.now() - 3 * HOUR),
      });
      queue.sent.length = 0;
      const tooSoon = await call("POST", `/api/v1/exposure/${recent}/stage2/run`);
      expect([tooSoon.status, problemCode(tooSoon)]).toEqual([409, "too-soon"]);
      expect(new Date(tooSoon.json?.nextAt).getTime()).toBeGreaterThan(
        Date.now() + (ACTIVE_LIMITS.minIntervalHours - 4) * HOUR,
      );
      expect(queue.sent).toEqual([]);

      const off = await verified();
      expect(problemCode(await call("POST", `/api/v1/exposure/${off}/stage2/run`))).toBe("stage2-off");
    });
  });

  describe("stage 1", () => {
    it("queues a run once and reports a run that is already waiting", async () => {
      const id = await addAsset();
      const first = await call("POST", `/api/v1/exposure/${id}/run`);
      expect([first.status, first.json?.alreadyQueued]).toEqual([202, false]);
      const second = await call("POST", `/api/v1/exposure/${id}/run`);
      expect([second.status, second.json?.alreadyQueued, second.json?.runId]).toEqual([
        200,
        true,
        first.json?.runId,
      ]);
      expect(queue.sent.filter((s) => s.name === "exposure.run")).toHaveLength(1);
    });

    it("pauses and resumes the daily look", async () => {
      const id = await addAsset();
      expect(
        (await call("PATCH", `/api/v1/exposure/${id}`, { body: { passiveEnabled: false } })).status,
      ).toBe(204);
      expect((await row(id)).passiveEnabled).toBe(false);
      expect((await call("PATCH", `/api/v1/exposure/${id}`, { body: {} })).status).toBe(422);
    });

    it("refuses subdomains for an address", async () => {
      policy.allowTestRanges = true;
      const created = await call("POST", "/api/v1/exposure", {
        body: { value: "192.0.2.50", includeSubdomains: true },
      });
      expect((await row(created.json?.id)).includeSubdomains).toBe(false);
      const r = await call("PATCH", `/api/v1/exposure/${created.json?.id}`, {
        body: { includeSubdomains: true },
      });
      expect(r.status).toBe(422);
    });
  });

  describe("Certificate Transparency", () => {
    it("is off by default and shows the exact request and its provider", async () => {
      const r = await call("GET", "/api/v1/exposure/settings", { org: "org_ex_ct0" });
      expect(r.json?.certificateTransparency).toMatchObject({
        enabled: false,
        enabledAt: null,
        provider: {
          id: "crtsh",
          name: "crt.sh",
          urlTemplate: "https://crt.sh/?q=%25.{domain}&output=json&exclude=expired",
        },
        dailyBudget: 100,
      });
    });

    it("needs the acknowledgement and a recent sign-in to switch on, and audits both directions", async () => {
      const noAck = await call("PUT", "/api/v1/exposure/settings", { body: { ct: { enabled: true } } });
      expect([noAck.status, noAck.json?.errors?.[0]?.message]).toEqual([422, "acknowledgement_required"]);
      const stale = await call("PUT", "/api/v1/exposure/settings", {
        age: STALE,
        body: { ct: { enabled: true, acknowledged: true } },
      });
      expect([stale.status, problemCode(stale)]).toEqual([403, "step-up-required"]);
      expect((await call("GET", "/api/v1/exposure/settings")).json?.certificateTransparency.enabled).toBe(
        false,
      );

      expect(
        (
          await call("PUT", "/api/v1/exposure/settings", {
            body: { ct: { enabled: true, acknowledged: true } },
          })
        ).status,
      ).toBe(200);
      const on = await call("GET", "/api/v1/exposure/settings");
      expect(on.json?.certificateTransparency).toMatchObject({ enabled: true, enabledBy: "Erika" });
      expect(on.json?.certificateTransparency.enabledAt).not.toBeNull();
      expect((await audits("exposure.ct_enabled"))[0]?.data).toMatchObject({ provider: "crtsh" });

      // Switching off needs no recent sign-in.
      expect(
        (await call("PUT", "/api/v1/exposure/settings", { age: STALE, body: { ct: { enabled: false } } }))
          .status,
      ).toBe(200);
      expect((await call("GET", "/api/v1/exposure/settings")).json?.certificateTransparency.enabled).toBe(
        false,
      );
      expect(await audits("exposure.ct_disabled")).toHaveLength(1);
    });

    it("keeps each organisation's choice to itself", async () => {
      await call("PUT", "/api/v1/exposure/settings", {
        org: OTHER,
        body: { ct: { enabled: true, acknowledged: true } },
      });
      expect(
        (await call("GET", "/api/v1/exposure/settings", { org: ORG })).json?.certificateTransparency.enabled,
      ).toBe(false);
      await call("PUT", "/api/v1/exposure/settings", { org: OTHER, body: { ct: { enabled: false } } });
    });
  });

  describe("suggestions", () => {
    it("adds a suggested name as an asset, or dismisses it", async () => {
      const parent = await addAsset({ value: "sug.example.com" });
      for (const name of ["a.sug.example.com", "b.sug.example.com"]) {
        await t.db.insert(schema.exposureDiscovery).values({
          id: `exd_${name.slice(0, 1)}apitest00000`,
          organizationId: ORG,
          assetId: parent,
          name,
          source: "ct",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        });
      }
      const detail = await call("GET", `/api/v1/exposure/${parent}`);
      expect(detail.json?.suggestions.map((s: Json) => s.name)).toEqual([
        "a.sug.example.com",
        "b.sug.example.com",
      ]);
      const added = await call("POST", "/api/v1/exposure/discoveries/exd_aapitest00000/add");
      expect(added.status).toBe(201);
      expect((await row(added.json?.id)).value).toBe("a.sug.example.com");
      expect(
        (await audits("exposure.asset_added")).find((a) => a.targetId === added.json?.id)?.data,
      ).toMatchObject({ source: "discovery" });
      expect((await call("POST", "/api/v1/exposure/discoveries/exd_bapitest00000/dismiss")).status).toBe(204);
      expect((await call("GET", `/api/v1/exposure/${parent}`)).json?.suggestions).toEqual([]);
    });
  });

  describe("lists", () => {
    it("pages, searches, filters and sorts, with counts", async () => {
      const org = "org_ex_list";
      await t.db.insert(schema.organization).values({ id: org, name: "List" });
      const mk = async (value: string, over: Partial<typeof schema.exposureAsset.$inferInsert> = {}) => {
        const id = `exa_list${String(++counter).padStart(12, "0")}`;
        await t.db.insert(schema.exposureAsset).values({
          id,
          organizationId: org,
          kind: "domain",
          value,
          verifyToken: `L${String(counter).padStart(3, "0")}${"z".repeat(39)}`,
          ...over,
        });
        return id;
      };
      const crit = await mk("a-critical.example.com", { verifyState: "verified", verifiedAt: new Date() });
      await mk("b-lost.example.com", { verifyState: "lost" });
      const clean = await mk("c-clean.example.com", {
        verifyState: "verified",
        verifiedAt: new Date(),
        stage2Enabled: true,
      });
      await mk("d-failed.example.com", { passiveError: "unexpected" });
      await t.db.insert(schema.exposureFinding).values([
        {
          id: "exf_list000000000001",
          organizationId: org,
          assetId: crit,
          stage: "active",
          rule: "portExposed",
          subject: "3389",
          severity: "high",
          severityRank: 3,
          state: "open",
          params: {},
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
        {
          id: "exf_list000000000002",
          organizationId: org,
          assetId: crit,
          stage: "passive",
          rule: "httpCspMissing",
          subject: "",
          severity: "low",
          severityRank: 1,
          state: "open",
          params: {},
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
        {
          id: "exf_list000000000003",
          organizationId: org,
          assetId: clean,
          stage: "passive",
          rule: "httpCspMissing",
          subject: "",
          severity: "low",
          severityRank: 1,
          state: "resolved",
          params: {},
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
      ]);
      const items = async (query: string) =>
        (((await call("GET", `/api/v1/exposure${query}`, { org })).json as Json).items as Json[]).map(
          (x) => x.value,
        );
      expect(await items("")).toEqual([
        "a-critical.example.com",
        "b-lost.example.com",
        "c-clean.example.com",
        "d-failed.example.com",
      ]);
      expect(await items("?q=lost")).toEqual(["b-lost.example.com"]);
      expect(await items("?q=%25")).toEqual([]);
      expect(await items("?status=attention")).toEqual([
        "a-critical.example.com",
        "b-lost.example.com",
        "d-failed.example.com",
      ]);
      expect(await items("?status=unverified")).toEqual(["b-lost.example.com", "d-failed.example.com"]);
      expect(await items("?status=stage2")).toEqual(["c-clean.example.com"]);
      expect(await items("?sort=high&dir=desc")).toEqual([
        "a-critical.example.com",
        // The rest tie on zero and come in reverse order of their ids.
        "d-failed.example.com",
        "c-clean.example.com",
        "b-lost.example.com",
      ]);
      expect((await items("?sort=verification"))[0]).toBe("b-lost.example.com");
      expect((await items("?sort=stage2"))[0]).toBe("c-clean.example.com");
      // Cursor paging with a sort.
      const first = (await call("GET", "/api/v1/exposure?pageSize=25&sort=value&dir=desc", { org }))
        .json as Json;
      expect(first.items.map((x: Json) => x.value)).toEqual([
        "d-failed.example.com",
        "c-clean.example.com",
        "b-lost.example.com",
        "a-critical.example.com",
      ]);
      expect(first.total).toBe(4);
      expect((await call("GET", "/api/v1/exposure?pageSize=7", { org })).status).toBe(422);
      expect((await call("GET", "/api/v1/exposure?cursor=nonsense", { org })).status).toBe(400);
      const counts = (await call("GET", "/api/v1/exposure/counts", { org })).json as Json;
      expect(counts).toMatchObject({
        all: 4,
        attention: 3,
        unverified: 2,
        stage2: 1,
        open: { critical: 0, high: 1, medium: 0, low: 1 },
      });
      const crits = ((await call("GET", "/api/v1/exposure", { org })).json as Json).items[0];
      expect(crits.open).toEqual({ critical: 0, high: 1, medium: 0, low: 1 });
    });

    it("pages through the list with a cursor", async () => {
      const org = "org_ex_pages";
      await t.db.insert(schema.organization).values({ id: org, name: "Pages" });
      await t.db.insert(schema.exposureAsset).values(
        Array.from({ length: 30 }, (_, i) => ({
          id: `exa_page${String(i).padStart(12, "0")}`,
          organizationId: org,
          kind: "domain" as const,
          value: `p${String(i).padStart(2, "0")}.example.com`,
          verifyToken: `P${String(i).padStart(3, "0")}${"q".repeat(39)}`,
        })),
      );
      const one = (await call("GET", "/api/v1/exposure?pageSize=25", { org })).json as Json;
      expect(one.items).toHaveLength(25);
      expect(one.next).not.toBeNull();
      const two = (
        await call("GET", `/api/v1/exposure?pageSize=25&cursor=${encodeURIComponent(one.next)}`, { org })
      ).json as Json;
      expect(two.items.map((x: Json) => x.value)).toEqual([
        "p25.example.com",
        "p26.example.com",
        "p27.example.com",
        "p28.example.com",
        "p29.example.com",
      ]);
      expect(two.next).toBeNull();
      expect(two.prev).not.toBeNull();
    });
  });

  describe("what the page gets to see", () => {
    it("holds the snapshots of both stages, the ports, the findings and the history", async () => {
      const id = await verified({
        passive: {
          version: 1,
          takenAt: "2026-10-22T10:00:00.000Z",
          addresses: ["93.184.216.34"],
          resolves: true,
          httpsOpen: true,
          tls: [{ cert: { validTo: "2027-01-01T00:00:00.000Z" } }],
          http: { status: 200 },
          geo: [{ country: "DE", asn: 64500, org: "Example AS" }],
        },
        active: { version: 1, takenAt: "2026-10-22T10:05:00.000Z", open: [{ port: 22 }], checked: 30 },
        lastPassiveAt: new Date(),
      });
      await t.db.insert(schema.exposurePort).values({
        assetId: id,
        organizationId: ORG,
        address: "93.184.216.34",
        port: 22,
        service: "ssh",
        banner: "SSH-2.0-Test",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
      await t.db.insert(schema.exposureRun).values({
        id: "exr_apitest0000000001",
        organizationId: ORG,
        assetId: id,
        stage: "passive",
        state: "succeeded",
        trigger: "schedule",
        createdAt: new Date(),
      });
      const r = await call("GET", `/api/v1/exposure/${id}`);
      expect(r.json?.stage1.summary).toMatchObject({
        addresses: ["93.184.216.34"],
        certificateExpires: "2027-01-01T00:00:00.000Z",
        httpStatus: 200,
        country: "DE",
        asn: 64500,
      });
      expect(r.json?.stage2.summary).toMatchObject({ open: 1, checked: 30 });
      expect(r.json?.ports).toEqual([expect.objectContaining({ port: 22, banner: "SSH-2.0-Test" })]);
      expect(r.json?.runs[0]).toMatchObject({ stage: "passive", state: "succeeded" });
      expect(r.json?.stage1.run).toMatchObject({ id: "exr_apitest0000000001" });
      expect(r.json?.limits.ports).toBe(30);
    });
  });
});
