/**
 * Early warnings (ADR 0029) against a throw-away PostgreSQL database on the development server: open ones
 * worst first, closed ones of the last 30 days, the repository filter and organisation isolation.
 * Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const state = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_early_warnings");
  state.db = t;
  return { db: t.db, pool: t.pool, boss: { send: async () => "job" }, QUEUES: {} };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_ew_a";
const OTHER = "org_ew_b";
const DAY = 24 * 3600 * 1000;

describe.skipIf(!adminUrl)("early warnings API", () => {
  let t: TestDatabase;
  let app: Hono;

  async function get(path: string, org = ORG) {
    const res = await app.request(path, { headers: { "x-org": org } });
    return { status: res.status, json: (await res.json()) as Json };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { earlyWarningRoutes } = await import("./early-warnings.ts");
    t = state.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.repository).values(
      [
        ["repo_a1", ORG, "app"],
        ["repo_a2", ORG, "site"],
        ["repo_b1", OTHER, "theirs"],
      ].map(([id, organizationId, name]) => ({
        id: id as string,
        organizationId: organizationId as string,
        name: name as string,
        url: `https://git.example.test/team/${name}.git`,
        authKind: "none" as const,
      })),
    );
    await t.db.insert(schema.vulnerability).values([
      { id: "GHSA-ew-crit", severity: "critical", knownExploited: true },
      { id: "GHSA-ew-low", severity: "low" },
    ]);
    const warning = (
      id: string,
      organizationId: string,
      repositoryId: string,
      vulnerabilityId: string,
      severity: string,
      rank: number,
      extra: Partial<typeof schema.earlyWarning.$inferInsert> = {},
    ) => ({
      id,
      organizationId,
      repositoryId,
      vulnerabilityId,
      packageName: "lodash",
      packageVersion: "4.17.20",
      packageType: "npm",
      severity,
      severityRank: rank,
      fixedIn: ["4.17.21"],
      ...extra,
    });
    await t.db.insert(schema.earlyWarning).values([
      warning("ewn_low", ORG, "repo_a1", "GHSA-ew-low", "low", 2),
      warning("ewn_crit", ORG, "repo_a2", "GHSA-ew-crit", "critical", 5),
      warning("ewn_confirmed", ORG, "repo_a1", "GHSA-ew-crit", "critical", 5, {
        packageVersion: "4.17.19",
        state: "confirmed",
        closedAt: new Date(Date.now() - DAY),
      }),
      warning("ewn_old", ORG, "repo_a1", "GHSA-ew-low", "low", 2, {
        packageVersion: "4.17.18",
        state: "cleared",
        closedAt: new Date(Date.now() - 40 * DAY),
      }),
      warning("ewn_other", OTHER, "repo_b1", "GHSA-ew-crit", "critical", 5),
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: "user_a",
          email: "viewer@example.test",
          name: "Viewer",
          organizationId: c.req.header("x-org"),
          role: "viewer",
          ip: "198.51.100.7",
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/early-warnings", earlyWarningRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("lists the open ones worst first, with the advisory's facts, for every member", async () => {
    const r = await get("/api/v1/early-warnings");
    expect(r.status).toBe(200);
    expect(r.json.items.map((x: Json) => x.id)).toEqual(["ewn_crit", "ewn_low"]);
    expect(r.json.items[0]).toMatchObject({
      repositoryName: "site",
      vulnerabilityId: "GHSA-ew-crit",
      knownExploited: true,
      fixedIn: ["4.17.21"],
      state: "open",
    });
    expect(r.json.truncated).toBe(false);
  });

  it("shows closed ones of the last 30 days and filters by repository", async () => {
    expect((await get("/api/v1/early-warnings?state=closed")).json.items.map((x: Json) => x.id)).toEqual([
      "ewn_confirmed",
    ]);
    expect(
      (await get("/api/v1/early-warnings?repositoryId=repo_a1")).json.items.map((x: Json) => x.id),
    ).toEqual(["ewn_low"]);
  });

  it("never shows another organisation's early warnings", async () => {
    expect((await get("/api/v1/early-warnings", OTHER)).json.items.map((x: Json) => x.id)).toEqual([
      "ewn_other",
    ]);
    expect((await get("/api/v1/early-warnings?repositoryId=repo_b1")).json.items).toEqual([]);
  });

  it("says what the last check looked at, counting only this organisation's packages", async () => {
    const before = (await get("/api/v1/early-warnings")).json;
    expect(before).toMatchObject({ lastCheck: null, packages: 0, repositories: 0, closedRecently: 1 });
    await t.db.insert(schema.repositoryPackage).values([
      {
        id: "rpk_a",
        organizationId: ORG,
        scanId: "scan_a",
        repositoryId: "repo_a1",
        name: "lodash",
        version: "4.17.20",
        type: "npm",
        purl: "pkg:npm/lodash@4.17.20",
      },
      {
        id: "rpk_b",
        organizationId: OTHER,
        scanId: "scan_b",
        repositoryId: "repo_b1",
        name: "left-pad",
        version: "1.0.0",
        type: "npm",
        purl: "pkg:npm/left-pad@1.0.0",
      },
    ]);
    await t.db.insert(schema.systemReport).values({
      key: "early_warning",
      data: {
        checkedAt: "2026-10-30T06:00:00.000Z",
        dbBuiltAt: "2026-10-30T04:00:00Z",
        warnings: 0,
        packages: 9,
      },
      reportedAt: new Date(),
    });
    const after = (await get("/api/v1/early-warnings")).json;
    expect(after).toMatchObject({
      lastCheck: { checkedAt: "2026-10-30T06:00:00.000Z", dbBuiltAt: "2026-10-30T04:00:00Z" },
      packages: 1,
      repositories: 1,
    });
    // The installation-wide count of the report is never passed on.
    expect(JSON.stringify(after)).not.toContain('"packages":9');
  });

  it("lists what a newer database brought for running hosts and images, and distributions near or past their end (ADR 0041)", async () => {
    expect((await get("/api/v1/early-warnings/hosts")).json).toMatchObject({ enabled: false, items: [] });
    await t.db.insert(schema.hostSettings).values([
      { organizationId: ORG, enabled: true },
      { organizationId: OTHER, enabled: true },
    ]);
    await t.db.insert(schema.agentHost).values([
      {
        id: "hst_ew_a",
        organizationId: ORG,
        name: "web-1",
        hostname: "web-1.example.lan",
        publicKey: "k".repeat(43),
        enrolledAt: new Date(),
        // Debian 11 lost regular security support on 2026-08-31.
        hostPackagesDistro: "debian 11",
      },
      {
        id: "hst_ew_b",
        organizationId: OTHER,
        name: "theirs",
        hostname: "theirs.example.lan",
        publicKey: "k".repeat(43),
        enrolledAt: new Date(),
        hostPackagesDistro: "debian 11",
      },
    ]);
    await t.db.insert(schema.containerImage).values({
      organizationId: ORG,
      imageId: "b".repeat(64),
      tags: ["nginx:1.27"],
      distro: "debian 13",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    const runtime = (
      id: string,
      organizationId: string,
      hostId: string,
      state: "open" | "cleared" = "open",
    ) => ({
      id,
      organizationId,
      kind: "kernel" as const,
      subjectId: hostId,
      hostId,
      vulnerabilityId: "GHSA-ew-crit",
      packageName: `linux-${id}`,
      packageVersion: "6.1.0",
      packageType: "deb",
      severity: "critical",
      severityRank: 5,
      state,
      ...(state === "cleared" ? { closedAt: new Date() } : {}),
    });
    await t.db
      .insert(schema.runtimeEarlyWarning)
      .values([
        runtime("rew_a", ORG, "hst_ew_a"),
        runtime("rew_closed", ORG, "hst_ew_a", "cleared"),
        runtime("rew_b", OTHER, "hst_ew_b"),
      ]);
    const r = (await get("/api/v1/early-warnings/hosts")).json;
    expect(r.items.map((x: Json) => [x.id, x.kind, x.subjectName, x.knownExploited])).toEqual([
      ["rew_a", "kernel", "web-1", true],
    ]);
    expect(r.closedRecently).toBe(1);
    expect(r.distributions).toHaveLength(1);
    expect(r.distributions[0]).toMatchObject({
      kind: "host",
      id: "hst_ew_a",
      name: "web-1",
      distribution: { name: "Debian", cycle: "11", status: "endOfLife" },
    });
    expect(
      (await get("/api/v1/early-warnings/hosts?state=closed")).json.items.map((x: Json) => x.id),
    ).toEqual(["rew_closed"]);
    expect(JSON.stringify((await get("/api/v1/early-warnings/hosts")).json)).not.toContain("theirs");
  });

  it("lists website software whose line ends within 90 days (ADR 0041)", async () => {
    expect((await get("/api/v1/early-warnings/websites")).json).toEqual({ enabled: false, items: [] });
    await t.db.insert(schema.exposureSettings).values({ organizationId: ORG, enabled: true });
    const { EOL_DATA } = await import("@garnetops/core/eol-data");
    const line = EOL_DATA.php?.find((c) => typeof c.eol === "string" && c.latest) as {
      cycle: string;
      eol: string;
      latest: string;
    };
    await t.db.insert(schema.exposureAsset).values({
      id: "exa_ew_a",
      organizationId: ORG,
      kind: "domain",
      value: "shop.example.com",
      verifyToken: "T".repeat(43),
      passive: {
        http: {
          status: 200,
          headers: { "x-powered-by": `PHP/${line.latest}` },
          generators: [],
          url: "https://shop.example.com/",
          finalUrl: null,
          address: null,
          redirects: [],
          error: null,
        },
      },
    });
    // Thirty days before the line ends.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(Date.parse(`${line.eol}T00:00:00Z`) - 30 * 86_400_000));
    try {
      const r = (await get("/api/v1/early-warnings/websites")).json;
      expect(r.items).toEqual([
        {
          assetId: "exa_ew_a",
          asset: "shop.example.com",
          name: "PHP",
          version: line.latest,
          cycle: line.cycle,
          eol: line.eol,
        },
      ]);
      // Another organisation does not see it.
      expect((await get("/api/v1/early-warnings/websites", OTHER)).json.items).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses an unknown state", async () => {
    expect((await get("/api/v1/early-warnings?state=all")).status).toBe(422);
  });
});
