/**
 * The findings list's date filters against a throw-away PostgreSQL database on the development server:
 * first seen and resolved on calendar days of the viewer's zone, as the statistics charts link to them; the severity
 * counts of the filter toggles; and the detail's "Also in" and fix proposal (0.1.1), within the viewer's repositories.
 * Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
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
  const t = await create(target, "api_findings");
  holder.db = t;
  return { db: t.db, pool: t.pool };
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
const ORG = "org_fd_a";

describe.skipIf(!adminUrl)("findings API date filters", () => {
  let t: TestDatabase;
  let app: Hono;

  async function ids(query: string) {
    const res = await app.request(`/api/v1/findings?state=all&${query}`, { headers: { "x-org": ORG } });
    const json = (await res.json()) as Json;
    return { status: res.status, ids: res.status === 200 ? json.items.map((i: Json) => i.id).sort() : [] };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { findingRoutes } = await import("./findings.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2099-0001", severity: "high" });
    await t.db.insert(schema.repository).values({
      id: "repo_fd",
      organizationId: ORG,
      name: "web",
      url: "https://git.example.lan/web.git",
      authKind: "none",
    });
    const finding = (id: string, firstSeenAt: string, resolvedAt: string | null) => ({
      id,
      organizationId: ORG,
      repositoryId: "repo_fd",
      vulnerabilityId: "CVE-2099-0001",
      dedupKey: id,
      packageName: id,
      packageVersion: "1.0.0",
      packageType: "npm",
      severity: "high",
      severityRank: 4,
      state: resolvedAt ? ("resolved" as const) : ("open" as const),
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: new Date(firstSeenAt),
      lastSeenAt: new Date(firstSeenAt),
      resolvedAt: resolvedAt ? new Date(resolvedAt) : null,
    });
    await t.db.insert(schema.finding).values([
      // 12 Oct 00:30 in Berlin (summer time), still 11 Oct in UTC.
      finding("fnd_early", "2026-10-11T22:30:00Z", null),
      finding("fnd_noon", "2026-10-12T12:00:00Z", "2026-10-14T09:00:00Z"),
      // 13 Oct 00:30 in Berlin: the day after.
      finding("fnd_late", "2026-10-12T22:30:00Z", null),
      // Across the end of summer time (25 Oct): 26 Oct 00:30 in Berlin is 25 Oct 23:30 UTC.
      finding("fnd_winter", "2026-10-25T23:30:00Z", "2026-10-25T23:30:00Z"),
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user") ?? "u",
          organizationId: c.req.header("x-org"),
          role: "viewer",
        } as never,
      );
      await next();
    });
    v1.route("/findings", findingRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("finds what was first seen on the viewer's calendar days", async () => {
    const berlin = "tz=Europe%2FBerlin";
    expect(await ids(`firstSeenFrom=2026-10-12&firstSeenTo=2026-10-12&${berlin}`)).toEqual({
      status: 200,
      ids: ["fnd_early", "fnd_noon"],
    });
    expect((await ids("firstSeenFrom=2026-10-12&firstSeenTo=2026-10-12")).ids).toEqual([
      "fnd_late",
      "fnd_noon",
    ]);
    expect((await ids(`firstSeenFrom=2026-10-26&firstSeenTo=2026-10-26&${berlin}`)).ids).toEqual([
      "fnd_winter",
    ]);
    expect((await ids(`firstSeenFrom=2026-10-13&${berlin}`)).ids).toEqual(["fnd_late", "fnd_winter"]);
  });

  it("finds what was resolved on the viewer's calendar days", async () => {
    expect((await ids("resolvedFrom=2026-10-12&resolvedTo=2026-10-18&tz=Europe%2FBerlin")).ids).toEqual([
      "fnd_noon",
    ]);
    expect((await ids("resolvedFrom=2026-10-25&resolvedTo=2026-10-25&tz=UTC")).ids).toEqual(["fnd_winter"]);
  });

  describe("counts and the detail (0.1.1)", () => {
    const B = "org_fd_b";
    const get = async (path: string, user = "user_fd_sam") => {
      const res = await app.request(`/api/v1/findings${path}`, { headers: { "x-org": B, "x-user": user } });
      return { status: res.status, json: (await res.json()) as Json };
    };

    beforeAll(async () => {
      await t.db.insert(schema.organization).values({ id: B, name: "B" });
      await t.db.insert(schema.user).values([
        { id: "user_fd_sam", name: "Sam Example", email: "sam@example.test" },
        { id: "user_fd_alex", name: "Alex Example", email: "alex@example.test" },
      ]);
      await t.db.insert(schema.vulnerability).values([
        { id: "CVE-2099-0101", severity: "critical" },
        { id: "CVE-2099-0102", severity: "low" },
      ]);
      const repos = [
        { id: "repo_fd_api", name: "api", visibility: "organization" as const, inactiveAt: null },
        { id: "repo_fd_billing", name: "billing", visibility: "organization" as const, inactiveAt: null },
        { id: "repo_fd_secret", name: "secret-app", visibility: "private" as const, inactiveAt: null },
        { id: "repo_fd_old", name: "old-app", visibility: "organization" as const, inactiveAt: new Date() },
      ];
      await t.db.insert(schema.repository).values(
        repos.map((r) => ({
          ...r,
          organizationId: B,
          url: `https://git.example.lan/team/${r.name}.git`,
          authKind: "none" as const,
          ownerUserId: "user_fd_alex",
        })),
      );
      const at = new Date("2026-10-20T08:00:00Z");
      const finding = (
        id: string,
        repositoryId: string,
        vulnerabilityId: string,
        severity: string,
        state = "open",
      ) => ({
        id,
        organizationId: B,
        repositoryId,
        vulnerabilityId,
        dedupKey: id,
        packageName: "minimist",
        packageVersion: "1.2.0",
        packageType: "npm",
        severity,
        severityRank: severity === "critical" ? 5 : 2,
        state: state as "open" | "accepted" | "resolved",
        fixedIn: ["1.2.6"],
        firstSeenScanId: "scan_x",
        lastSeenScanId: "scan_x",
        firstSeenAt: at,
        lastSeenAt: at,
      });
      await t.db
        .insert(schema.finding)
        .values([
          finding("fnd_b_api", "repo_fd_api", "CVE-2099-0101", "critical"),
          finding("fnd_b_api_low", "repo_fd_api", "CVE-2099-0102", "low", "accepted"),
          finding("fnd_b_billing", "repo_fd_billing", "CVE-2099-0101", "critical"),
          finding("fnd_b_secret", "repo_fd_secret", "CVE-2099-0101", "critical"),
          finding("fnd_b_old", "repo_fd_old", "CVE-2099-0101", "critical"),
        ]);
    });

    it("counts every severity per state without the severity filter, for the toggles", async () => {
      const { json } = await get("/counts?severity=critical");
      // The state tabs follow the severity filter; the toggles do not.
      expect(json.states).toEqual({ open: 2, accepted: 0, resolved: 0 });
      expect(json.severities).toEqual({ open: { critical: 2 }, accepted: { low: 1 }, resolved: {} });
      // The owner of the private repository counts it too.
      expect((await get("/counts", "user_fd_alex")).json.severities.open).toEqual({ critical: 3 });
    });

    it("names the other repositories with the same finding the viewer may see, and its fix proposal", async () => {
      const { status, json } = await get("/fnd_b_api");
      expect(status).toBe(200);
      expect(json.alsoIn).toEqual([
        {
          id: "fnd_b_billing",
          repositoryId: "repo_fd_billing",
          repositoryName: "billing",
          packageVersion: "1.2.0",
          state: "open",
        },
      ]);
      expect(json.fixProposal).toMatchObject({ repositoryId: "repo_fd_api", targetVersion: "1.2.6" });
      expect(json.fixProposal.key).toMatch(/^[0-9a-f]{24}$/);
      expect(JSON.stringify(json)).not.toContain("secret-app");
      // An accepted finding has no proposal to open.
      expect((await get("/fnd_b_api_low")).json.fixProposal).toBeNull();
      // Alex also sees the private repository, never the one set aside.
      const own = (await get("/fnd_b_api", "user_fd_alex")).json.alsoIn.map((x: Json) => x.repositoryName);
      expect(own).toEqual(["billing", "secret-app"]);
    });
  });

  it("refuses days that do not exist and unknown zones", async () => {
    expect((await ids("firstSeenFrom=2026-02-30")).status).toBe(422);
    expect((await ids("firstSeenFrom=12.10.2026")).status).toBe(422);
    expect((await ids("firstSeenFrom=2026-10-12&tz=Mars%2FBase")).status).toBe(422);
  });
});
