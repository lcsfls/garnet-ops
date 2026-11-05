/**
 * The overview (0.1.1) against a throw-away PostgreSQL database on the development server: the top statement's facts,
 * "Fix first" grouped by upgrade with the fix proposals that carry it out, and the activity feed with scans and gate
 * runs. Everything follows the overview's visibility: another member's private repository and repositories set aside
 * never count. Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
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
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_overview");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: { send: async () => "job" }, QUEUES: {} };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_ov";
/** Alex owns a private repository; Sam is another member and must never see it. */
const ALEX = "user_ov_alex";
const SAM = "user_ov_sam";
const HOUR = 3600_000;
const ago = (hours: number) => new Date(Date.now() - hours * HOUR);
const RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2 };

describe.skipIf(!adminUrl)("overview", () => {
  let t: TestDatabase;
  let app: Hono;

  async function overview(user: string): Promise<Json> {
    const res = await app.request("/api/v1/overview", { headers: { "x-user": user } });
    expect(res.status).toBe(200);
    return (await res.json()) as Json;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { overviewRoutes } = await import("./overview.ts");
    t = holder.db as TestDatabase;
    const d = t.db;
    await d.insert(schema.organization).values({ id: ORG, name: "Example" });
    await d.insert(schema.user).values([
      { id: ALEX, name: "Alex Example", email: "alex@example.test" },
      { id: SAM, name: "Sam Example", email: "sam@example.test" },
    ]);
    await d.insert(schema.membership).values([
      { organizationId: ORG, userId: ALEX, role: "member" },
      { organizationId: ORG, userId: SAM, role: "member" },
    ]);
    await d.insert(schema.vulnerability).values([
      { id: "CVE-2099-1000", severity: "critical" },
      { id: "CVE-2099-2001", severity: "high" },
      { id: "CVE-2099-2002", severity: "high" },
      { id: "CVE-2099-2003", severity: "high" },
      { id: "CVE-2099-2004", severity: "medium" },
      { id: "CVE-2099-3000", severity: "low" },
    ]);
    const repos = [
      { id: "repo_ov_api", name: "api", visibility: "organization" as const, inactiveAt: null },
      { id: "repo_ov_billing", name: "billing", visibility: "organization" as const, inactiveAt: null },
      { id: "repo_ov_secret", name: "secret-app", visibility: "private" as const, inactiveAt: null },
      { id: "repo_ov_old", name: "old-app", visibility: "organization" as const, inactiveAt: ago(48) },
    ];
    for (const r of repos) {
      await d.insert(schema.repository).values({
        ...r,
        organizationId: ORG,
        url: `https://git.example.lan/team/${r.name}.git`,
        authKind: "none",
        ownerUserId: ALEX,
        lastScanAt: ago(2),
      });
      // The scan the findings come from: manual, by Alex, two hours ago, with its gate run.
      await d.insert(schema.scan).values({
        id: `scan_${r.id}`,
        organizationId: ORG,
        repositoryId: r.id,
        state: "succeeded",
        trigger: "manual",
        requestedBy: ALEX,
        newFindings: 1,
        resolvedFindings: 0,
        createdAt: ago(2.1),
        finishedAt: ago(2),
      });
      await d.insert(schema.gateRun).values({
        id: `gate_${r.id}`,
        organizationId: ORG,
        repositoryId: r.id,
        scanId: `scan_${r.id}`,
        result: "blocked",
        matches: {},
        createdAt: ago(2),
      });
    }
    let n = 0;
    const finding = async (
      repositoryId: string,
      vulnerabilityId: string,
      pkg: string,
      version: string,
      fixedIn: string[],
    ) => {
      n++;
      const severity = vulnerabilityId.startsWith("CVE-2099-1")
        ? "critical"
        : vulnerabilityId === "CVE-2099-2004"
          ? "medium"
          : vulnerabilityId.startsWith("CVE-2099-2")
            ? "high"
            : "low";
      await d.insert(schema.finding).values({
        id: `fnd_ov_${n}`,
        organizationId: ORG,
        repositoryId,
        vulnerabilityId,
        dedupKey: `ov-${n}`,
        packageName: pkg,
        packageVersion: version,
        packageType: "npm",
        severity,
        severityRank: RANK[severity] ?? 0,
        state: "open",
        fixedIn,
        firstSeenScanId: `scan_${repositoryId}`,
        lastSeenScanId: `scan_${repositoryId}`,
        firstSeenAt: ago(2),
        lastSeenAt: ago(2),
      });
    };
    // Two criticals from minimist 1.2.0, one upgrade fixes both; the private and the inactive repository have it too.
    for (const repo of ["repo_ov_api", "repo_ov_billing", "repo_ov_secret", "repo_ov_old"])
      await finding(repo, "CVE-2099-1000", "minimist", "1.2.0", ["1.2.6"]);
    // lodash 4.17.15: four advisories, the highest fix needed is 4.18.0.
    await finding("repo_ov_api", "CVE-2099-2001", "lodash", "4.17.15", ["4.17.19"]);
    await finding("repo_ov_api", "CVE-2099-2002", "lodash", "4.17.15", ["4.17.21"]);
    await finding("repo_ov_api", "CVE-2099-2003", "lodash", "4.17.15", ["4.17.23"]);
    await finding("repo_ov_api", "CVE-2099-2004", "lodash", "4.17.15", ["4.18.0"]);
    // No fix known: open, but no upgrade closes it.
    await finding("repo_ov_billing", "CVE-2099-3000", "left-pad", "1.0.0", []);

    // A pipeline's gate check in billing, an hour ago: shows as the gate run.
    await d.insert(schema.scan).values({
      id: "scan_ov_ci",
      organizationId: ORG,
      repositoryId: "repo_ov_billing",
      state: "succeeded",
      trigger: "ci",
      createdAt: ago(1.1),
      finishedAt: ago(1),
    });
    await d.insert(schema.gateRun).values({
      id: "gate_ov_ci",
      organizationId: ORG,
      repositoryId: "repo_ov_billing",
      scanId: "scan_ov_ci",
      result: "passed",
      matches: {},
      createdAt: ago(1),
    });
    // A nightly scan that changed nothing (summed up in its run), and one that failed (on its own).
    await d.insert(schema.scan).values([
      {
        id: "scan_ov_nightly_quiet",
        organizationId: ORG,
        repositoryId: "repo_ov_api",
        state: "succeeded",
        trigger: "schedule",
        newFindings: 0,
        resolvedFindings: 0,
        createdAt: ago(0.6),
        finishedAt: ago(0.5),
      },
      {
        id: "scan_ov_nightly_failed",
        organizationId: ORG,
        repositoryId: "repo_ov_billing",
        state: "failed",
        trigger: "schedule",
        error: "clone-failed",
        createdAt: ago(0.6),
        finishedAt: ago(0.4),
      },
    ]);
    await d.insert(schema.scanScheduleRun).values({
      organizationId: ORG,
      localDate: "2099-01-01",
      queuedScans: 2,
      createdAt: ago(0.7),
    });

    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "someone@example.test",
          name: "Someone",
          organizationId: ORG,
          role: "member",
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/overview", overviewRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  }, 60_000);

  it("states the worst open severity, where it comes from and the one upgrade that fixes it", async () => {
    const body = await overview(SAM);
    expect(body.headline).toEqual({
      level: "critical",
      count: 2,
      repositories: 2,
      package: { name: "minimist", version: "1.2.0" },
      packages: 1,
      oneUpgrade: {
        remedyKey: "npm\u001fminimist\u001f1.2.0",
        packageName: "minimist",
        fromVersion: "1.2.0",
        toVersion: "1.2.6",
        // One fix proposal per repository: api and billing, not the private or the inactive one.
        proposals: { count: 2, key: null, repositoryId: null },
      },
      fixable: 2,
      upgrades: 1,
      knownExploited: 0,
      scanned: true,
    });
    // The owner of the private repository counts it as well.
    expect((await overview(ALEX)).headline).toMatchObject({ count: 3, repositories: 3 });
  });

  it("groups Fix first by upgrade, worst first, with the highest fixed version needed", async () => {
    const body = await overview(SAM);
    expect(body.remedies.map((r: Json) => `${r.packageName} ${r.fromVersion} → ${r.toVersion}`)).toEqual([
      "minimist 1.2.0 → 1.2.6",
      "lodash 4.17.15 → 4.18.0",
    ]);
    const [minimist, lodash] = body.remedies;
    expect(minimist).toMatchObject({
      complete: true,
      closes: { total: 2, bySeverity: { critical: 2 }, knownExploited: 0 },
      repositoryCount: 2,
      repositories: [
        { id: "repo_ov_api", name: "api" },
        { id: "repo_ov_billing", name: "billing" },
      ],
    });
    expect(lodash).toMatchObject({
      complete: true,
      closes: { total: 4, bySeverity: { high: 3, medium: 1 } },
      repositoryCount: 1,
      proposals: { count: 1, repositoryId: "repo_ov_api" },
    });
    expect(lodash.proposals.key).toMatch(/^[0-9a-f]{24}$/);
    // Two upgrades close 6 of the 7 open findings Sam sees; left-pad has no fix.
    expect(body.remedySummary).toEqual({ upgrades: 2, closes: 6, open: 7 });
    expect(JSON.stringify(body)).not.toContain("secret-app");
    expect(JSON.stringify(body)).not.toContain("old-app");
  });

  it("lists scans and gate runs in the activity, newest first, within the viewer's repositories", async () => {
    const body = await overview(SAM);
    const lines = body.activity.map((a: Json) =>
      `${a.kind} ${a.subject ?? a.count} ${a.status ?? ""}`.trim(),
    );
    expect(lines).toEqual([
      "scan billing failed",
      "schedule.run 2",
      "gate billing passed",
      // Both two hours ago; billing's was written a moment later.
      "scan billing succeeded",
      "scan api succeeded",
    ]);
    const manual = body.activity.find((a: Json) => a.kind === "scan" && a.subject === "api");
    expect(manual).toMatchObject({ trigger: "manual", actorName: "Alex Example", added: 1, resolved: 0 });
    expect(manual.repositoryId).toBe("repo_ov_api");
    // Alex sees the scan of the private repository, never the one set aside.
    const own = (await overview(ALEX)).activity.map((a: Json) => a.subject);
    expect(own).toContain("secret-app");
    expect(own).not.toContain("old-app");
  });
});
