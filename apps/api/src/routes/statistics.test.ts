/**
 * The statistics API against a throw-away PostgreSQL database on the development server: the
 * allowed ranges and time zones, the rankings of today's open findings (worst first, accepted and
 * resolved left out), the oldest open critical and high findings, and organisation isolation.
 * The time series themselves are tested in packages/db (statistics.test.ts). Sessions are
 * replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null };
  const t = await create(target, "api_statistics");
  holder.db = t;
  return { db: t.db, pool: t.pool };
});

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_st_a";
const OTHER = "org_st_b";
const DAY = 24 * 3600 * 1000;

describe.skipIf(!adminUrl)("statistics API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function get(path: string, org = ORG) {
    const res = await app.request(path, { headers: { "x-org": org } });
    const text = await res.text();
    return { status: res.status, json: (text ? JSON.parse(text) : null) as Json | null };
  }

  async function repo(name: string, org = ORG) {
    const id = `repo_st${++counter}`;
    await t.db.insert(schema.repository).values({
      id,
      organizationId: org,
      name,
      url: `https://git.example.lan/${name}.git`,
      authKind: "none",
    });
    return id;
  }

  async function finding(
    repositoryId: string,
    severity: string,
    options: { pkg?: string; state?: "open" | "accepted" | "resolved"; ageDays?: number; org?: string } = {},
  ) {
    const id = `fnd_st${++counter}`;
    const seen = new Date(Date.now() - (options.ageDays ?? 1) * DAY);
    await t.db.insert(schema.finding).values({
      id,
      organizationId: options.org ?? ORG,
      repositoryId,
      vulnerabilityId: "CVE-2099-0001",
      dedupKey: id,
      packageName: options.pkg ?? `pkg-${counter}`,
      packageVersion: "1.0.0",
      packageType: "npm",
      severity,
      severityRank: 1,
      state: options.state ?? "open",
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: seen,
      lastSeenAt: seen,
      resolvedAt: options.state === "resolved" ? new Date() : null,
    });
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { statisticsRoutes } = await import("./statistics.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2099-0001", severity: "high" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        { userId: "u", organizationId: c.req.header("x-org"), role: "viewer" } as never,
      );
      await next();
    });
    v1.route("/statistics", statisticsRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;

    const web = await repo("web");
    const api = await repo("api");
    const docs = await repo("docs");
    await finding(web, "high", { pkg: "lodash" });
    await finding(web, "high", { pkg: "lodash" });
    await finding(web, "medium", { pkg: "minimist" });
    await finding(api, "critical", { pkg: "lodash", ageDays: 40 });
    await finding(api, "low", { pkg: "debug" });
    await finding(api, "critical", { pkg: "old", state: "resolved" });
    await finding(docs, "critical", { pkg: "accepted", state: "accepted" });
    await finding(docs, "negligible", { pkg: "tiny" });
    const elsewhere = await repo("secret", OTHER);
    await finding(elsewhere, "critical", { pkg: "lodash", org: OTHER, ageDays: 400 });
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("answers the three ranges in the viewer's zone and refuses anything else", async () => {
    for (const days of [30, 90, 365]) {
      const res = await get(`/api/v1/statistics?days=${days}&tz=Europe%2FBerlin`);
      expect(res.status).toBe(200);
      expect(res.json?.range).toMatchObject({ days, timeZone: "Europe/Berlin" });
    }
    expect((await get("/api/v1/statistics?days=7")).status).toBe(422);
    expect((await get("/api/v1/statistics?tz=Mars%2FBase")).status).toBe(422);
    expect((await get("/api/v1/statistics")).json?.range).toMatchObject({ days: 30, timeZone: "UTC" });
  });

  it("ranks repositories and packages by their worst open findings, without accepted or resolved ones", async () => {
    const { json } = await get("/api/v1/statistics");
    expect(json?.repositories.map((r: Json) => [r.name, r.critical, r.high, r.open])).toEqual([
      ["api", 1, 0, 2],
      ["web", 0, 2, 3],
    ]);
    expect(json?.packages[0]).toMatchObject({
      name: "lodash",
      type: "npm",
      repositories: 2,
      critical: 1,
      high: 2,
      open: 3,
    });
    expect(json?.packages.map((p: Json) => p.name)).not.toContain("accepted");
    expect(json?.packages.map((p: Json) => p.name)).not.toContain("tiny");
  });

  it("lists the oldest open critical and high findings first, of this organisation only", async () => {
    const { json } = await get("/api/v1/statistics");
    expect(json?.oldest.map((o: Json) => [o.repositoryName, o.severity, o.packageName])).toEqual([
      ["api", "critical", "lodash"],
      ["web", "high", "lodash"],
      ["web", "high", "lodash"],
    ]);
    const other = await get("/api/v1/statistics", OTHER);
    expect(other.json?.oldest).toHaveLength(1);
    expect(other.json?.repositories.map((r: Json) => r.name)).toEqual(["secret"]);
  });

  it("counts what was found in the range", async () => {
    const { json } = await get("/api/v1/statistics?days=30");
    // Found in the last 30 days: everything above except the 40-day-old critical and the negligible one.
    expect(json?.totals.opened).toBe(6);
    expect(json?.totals.resolved).toBe(1);
  });
});
