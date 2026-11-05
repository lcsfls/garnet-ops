/**
 * The organisation report's reads against a real PostgreSQL (ADR 0047): the period is the reader's calendar days, cut with
 * `AT TIME ZONE` (2026-10-25 has 25 hours in Berlin: 03:00 CEST -> 02:00 CET at 01:00 UTC); another member's private
 * repository and inactive repositories never count; hosts and websites only while their module is on. All instants are fixed
 * and in UTC. Skipped without the development PostgreSQL.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { organizationReport, websitesOverview } from "./reports.ts";
import * as schema from "./schema.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";

const adminUrl = devDatabaseUrl();
const ORG = "org_rpt";
const NOW = new Date("2026-11-02T08:00:00Z");
/** Berlin's week of 26 October to 1 November 2026. */
const WEEK = { from: "2026-10-26", to: "2026-11-01", days: 7, timeZone: "Europe/Berlin" };

describe.skipIf(!adminUrl)("organisation report", () => {
  let t: TestDatabase;
  let counter = 0;

  async function repo(name: string, patch: Partial<typeof schema.repository.$inferInsert> = {}) {
    const id = `repo_rpt${++counter}`;
    await t.db.insert(schema.repository).values({
      id,
      organizationId: ORG,
      name,
      url: `https://git.example.lan/${name}.git`,
      authKind: "none",
      ...patch,
    });
    return id;
  }

  async function finding(
    repositoryId: string,
    firstSeen: string,
    patch: Partial<typeof schema.finding.$inferInsert> = {},
  ) {
    const id = `fnd_rpt${++counter}`;
    await t.db.insert(schema.finding).values({
      id,
      organizationId: ORG,
      repositoryId,
      vulnerabilityId: "CVE-2099-0401",
      dedupKey: id,
      packageName: id,
      packageVersion: "1",
      packageType: "npm",
      severity: "high",
      severityRank: 4,
      state: "open",
      firstSeenScanId: "s",
      lastSeenScanId: "s",
      firstSeenAt: new Date(firstSeen),
      lastSeenAt: new Date(firstSeen),
      ...patch,
    });
  }

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "reports_test");
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example" });
    await t.db.insert(schema.user).values([
      { id: "u_rpt_a", name: "A", email: "a@example.test" },
      { id: "u_rpt_b", name: "B", email: "b@example.test" },
    ]);
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2099-0401", severity: "high" });
    const shared = await repo("shared");
    const mine = await repo("a-private", { visibility: "private", ownerUserId: "u_rpt_a" });
    const idle = await repo("set-aside", { inactiveAt: new Date("2026-10-01T00:00:00Z") });
    // 23:30 UTC on 25 October is 00:30 on 26 October in Berlin: inside the week there, the day before in UTC.
    await finding(shared, "2026-10-25T23:30:00Z");
    // 22:30 UTC on 1 November is 23:30 in Berlin: still inside the week.
    await finding(shared, "2026-11-01T22:30:00Z", { severity: "critical", severityRank: 5 });
    // 23:30 UTC on 1 November is 00:30 on 2 November in Berlin: after the week.
    await finding(shared, "2026-11-01T23:30:00Z");
    // Fixed inside the week.
    await finding(shared, "2026-09-01T00:00:00Z", {
      state: "resolved",
      resolvedAt: new Date("2026-10-30T12:00:00Z"),
    });
    // Accepted, and the acceptance has run out.
    await finding(shared, "2026-09-01T00:00:00Z", {
      state: "accepted",
      acceptedUntil: new Date("2026-10-31T00:00:00Z"),
    });
    await finding(mine, "2026-10-28T12:00:00Z", { severity: "critical", severityRank: 5 });
    await finding(idle, "2026-10-28T12:00:00Z", { severity: "critical", severityRank: 5 });
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("counts the reader's calendar days, and only what the reader sees", async () => {
    const b = await organizationReport(t.db, {
      organizationId: ORG,
      userId: "u_rpt_b",
      period: WEEK,
      now: NOW,
    });
    expect(b.findings.open).toEqual({ critical: 1, high: 2, medium: 0, low: 0 });
    expect(b.findings.opened).toEqual({ critical: 1, high: 1, medium: 0, low: 0 });
    expect(b.findings.fixed.high).toBe(1);
    expect(b.accepted).toEqual({ total: 1, expired: 1, endingSoon: 0 });
    expect(b.repositories.total).toBe(1);
    expect(JSON.stringify(b)).not.toContain("a-private");
    expect(JSON.stringify(b)).not.toContain("set-aside");
    expect(b.hosts).toBeNull();
    expect(b.websites).toBeNull();

    const a = await organizationReport(t.db, {
      organizationId: ORG,
      userId: "u_rpt_a",
      period: WEEK,
      now: NOW,
    });
    expect(a.findings.open.critical).toBe(2);
    expect(a.top.repositories.map((r) => r.name)).toEqual(["shared", "a-private"]);
  });

  it("the same instants fall on other days in UTC", async () => {
    const utc = await organizationReport(t.db, {
      organizationId: ORG,
      userId: "u_rpt_b",
      period: { ...WEEK, timeZone: "UTC" },
      now: NOW,
    });
    // 25 October 23:30 UTC is before the week in UTC; 1 November 23:30 UTC is inside it.
    expect(utc.findings.opened).toEqual({ critical: 1, high: 1, medium: 0, low: 0 });
    const day = await organizationReport(t.db, {
      organizationId: ORG,
      userId: "u_rpt_b",
      period: { from: "2026-10-26", to: "2026-10-26", days: 1, timeZone: "Europe/Berlin" },
      now: NOW,
    });
    expect(day.findings.opened.high).toBe(1);
  });

  it("refuses an unknown zone", async () => {
    await expect(
      organizationReport(t.db, {
        organizationId: ORG,
        userId: "u_rpt_b",
        period: { ...WEEK, timeZone: "Mars/Base" },
        now: NOW,
      }),
    ).rejects.toThrow(RangeError);
  });

  it("includes hosts and websites while their modules are on", async () => {
    await t.db.insert(schema.hostSettings).values({ organizationId: ORG, enabled: true });
    await t.db.insert(schema.exposureSettings).values({ organizationId: ORG, enabled: true });
    await t.db.insert(schema.agentHost).values({
      id: "agh_rpt",
      organizationId: ORG,
      name: "edge-01",
      hostname: "edge-01.example.lan",
      publicKey: "A".repeat(43),
      enrolledAt: new Date("2026-10-01T00:00:00Z"),
      lastInventoryAt: new Date("2026-10-30T00:00:00Z"),
    });
    await t.db.insert(schema.exposureAsset).values({
      id: "exa_rpt",
      organizationId: ORG,
      kind: "domain",
      value: "www.example.com",
      verifyToken: "t".repeat(32),
      uptimeEnabled: true,
      uptimeState: "down",
    });
    const report = await organizationReport(t.db, {
      organizationId: ORG,
      userId: "u_rpt_b",
      period: WEEK,
      now: NOW,
    });
    expect(report.hosts).toEqual({
      total: 1,
      notReporting: [{ id: "agh_rpt", name: "edge-01", lastReportAt: "2026-10-30T00:00:00.000Z" }],
    });
    expect(report.websites?.[0]).toMatchObject({ value: "www.example.com", worst: "high", worstRule: null });
    expect(report.nextSteps.map((s) => s.code)).toEqual(
      expect.arrayContaining(["hostsNotReporting", "websitesDown", "acceptedExpired"]),
    );
    expect((await websitesOverview(t.db, ORG, NOW)).map((w) => w.value)).toEqual(["www.example.com"]);
  });
});
