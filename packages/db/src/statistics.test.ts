/**
 * The statistics page's reads against a real PostgreSQL (AGENTS.md: time zones, dates and
 * DST transitions get explicit tests). Calendar days are Europe/Berlin; 2026-10-25 is a
 * 25-hour day there (03:00 CEST -> 02:00 CET at 01:00 UTC). All instants are fixed and in UTC.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as schema from "./schema.ts";
import { organizationStatistics } from "./statistics.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";

const adminUrl = devDatabaseUrl();
const tz = "Europe/Berlin";

describe.skipIf(!adminUrl)("organisation statistics", () => {
  let t: TestDatabase;
  let counter = 0;

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "statistics_test");
    await t.db.insert(schema.vulnerability).values({ id: "CVE-S", severity: "high" });
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });

  async function org() {
    const id = `org_stat${++counter}`;
    await t.db.insert(schema.organization).values({ id, name: id });
    await t.db
      .insert(schema.repository)
      .values({ id: `${id}_r`, organizationId: id, name: "r", url: "https://x.test/r", authKind: "none" });
    return id;
  }

  async function finding(
    orgId: string,
    firstSeen: string,
    options: { resolved?: string; severity?: string } = {},
  ) {
    const id = `${orgId}_f${++counter}`;
    const severity = options.severity ?? "high";
    await t.db.insert(schema.finding).values({
      id,
      organizationId: orgId,
      repositoryId: `${orgId}_r`,
      vulnerabilityId: "CVE-S",
      dedupKey: id,
      packageName: id,
      packageVersion: "1",
      packageType: "npm",
      severity,
      severityRank: { critical: 5, high: 4, medium: 3, low: 2 }[severity] ?? 1,
      state: options.resolved ? "resolved" : "open",
      firstSeenScanId: "s",
      lastSeenScanId: "s",
      firstSeenAt: new Date(firstSeen),
      lastSeenAt: new Date(firstSeen),
      resolvedAt: options.resolved ? new Date(options.resolved) : null,
    });
  }

  async function scan(orgId: string, at: string, state: "succeeded" | "failed", gate?: string) {
    const id = `${orgId}_s${++counter}`;
    await t.db.insert(schema.scan).values({
      id,
      organizationId: orgId,
      repositoryId: `${orgId}_r`,
      state,
      trigger: "manual",
      createdAt: new Date(at),
      finishedAt: new Date(at),
    });
    if (gate) {
      await t.db.insert(schema.gateRun).values({
        id: `${id}_g`,
        organizationId: orgId,
        repositoryId: `${orgId}_r`,
        scanId: id,
        result: gate as "passed" | "notes" | "blocked",
        matches: {},
        createdAt: new Date(at),
      });
    }
  }

  it("cuts 30 days into the viewer's calendar days, the 25-hour day counted once", async () => {
    const id = await org();
    // 2026-10-25 00:30 UTC is 02:30 CEST, 01:30 UTC is 02:30 CET: both on the 25th in Berlin.
    await finding(id, "2026-10-25T00:30:00Z");
    await finding(id, "2026-10-25T01:30:00Z");
    // 22:30 UTC on the 25th is still the 25th in Berlin (23:30 CET); 23:30 UTC is the 26th.
    await finding(id, "2026-10-25T22:30:00Z");
    await finding(id, "2026-10-25T23:30:00Z", { resolved: "2026-10-27T10:00:00Z" });
    const s = await organizationStatistics(t.db, {
      organizationId: id,
      timeZone: tz,
      days: 30,
      asOf: new Date("2026-10-28T12:00:00Z"),
    });
    expect(s.range).toMatchObject({ from: "2026-09-29", to: "2026-10-28", granularity: "day" });
    expect(s.buckets).toHaveLength(30);
    const day = (d: string) => s.buckets.find((b) => b.start === d);
    expect(day("2026-10-25")).toMatchObject({ end: "2026-10-25", opened: { high: 3 }, open: { high: 3 } });
    expect(day("2026-10-26")).toMatchObject({ opened: { high: 1 }, open: { high: 4 } });
    expect(day("2026-10-27")).toMatchObject({ resolved: { high: 1 }, open: { high: 3 } });
    expect(day("2026-10-24")?.open).toEqual({});
    expect(s.totals).toMatchObject({ opened: 4, resolved: 1 });
  });

  it("uses Monday weeks for 90 days, the first and last cut to the range", async () => {
    const id = await org();
    const s = await organizationStatistics(t.db, {
      organizationId: id,
      timeZone: tz,
      days: 90,
      asOf: new Date("2026-10-28T12:00:00Z"), // a Wednesday
    });
    expect(s.range).toMatchObject({ from: "2026-07-31", to: "2026-10-28", granularity: "week" });
    // 2026-07-31 is a Friday: the first bucket covers Friday to Sunday only.
    expect(s.buckets[0]).toMatchObject({ start: "2026-07-31", end: "2026-08-02" });
    expect(s.buckets[1]).toMatchObject({ start: "2026-08-03", end: "2026-08-09" });
    expect(s.buckets.at(-1)).toMatchObject({ start: "2026-10-26", end: "2026-10-28" });
    expect(s.buckets).toHaveLength(14);
  });

  it("counts gates, scans, fix pull requests, the previous range and the median time to fix", async () => {
    const id = await org();
    const asOf = new Date("2026-10-28T12:00:00Z");
    // Resolved in the range after 2 and 4 days (median 3); one resolved before the range.
    await finding(id, "2026-10-01T10:00:00Z", { resolved: "2026-10-03T10:00:00Z", severity: "critical" });
    await finding(id, "2026-10-05T10:00:00Z", { resolved: "2026-10-09T10:00:00Z", severity: "critical" });
    await finding(id, "2026-09-01T10:00:00Z", { resolved: "2026-09-10T10:00:00Z", severity: "critical" });
    await finding(id, "2026-10-10T10:00:00Z", { severity: "negligible" }); // not counted
    await scan(id, "2026-10-20T10:00:00Z", "succeeded", "passed");
    await scan(id, "2026-10-21T10:00:00Z", "succeeded", "blocked");
    await scan(id, "2026-10-22T10:00:00Z", "failed");
    await scan(id, "2026-08-01T10:00:00Z", "succeeded", "passed"); // before the range
    await t.db.insert(schema.fixPr).values({
      id: `${id}_pr`,
      organizationId: id,
      repositoryId: `${id}_r`,
      proposalKey: "k",
      ecosystem: "npm",
      packageName: "a",
      fromVersion: "1",
      toVersion: "2",
      manifestPath: "package.json",
      expectedBlobSha: "0",
      severity: "high",
      vulnerabilityIds: ["CVE-S"],
      state: "merged",
      openedAt: new Date("2026-10-11T10:00:00Z"),
      closedAt: new Date("2026-10-12T10:00:00Z"),
    });
    const s = await organizationStatistics(t.db, { organizationId: id, timeZone: tz, days: 30, asOf });
    expect(s.totals).toMatchObject({
      opened: 2,
      resolved: 2,
      previous: { opened: 1, resolved: 1 },
      gates: { passed: 1, notes: 0, blocked: 1 },
      scans: { succeeded: 2, failed: 1 },
      fixPrs: { opened: 1, merged: 1 },
    });
    expect(s.timeToFix.find((r) => r.severity === "critical")).toEqual({
      severity: "critical",
      resolved: 2,
      medianDays: 3,
    });
    expect(s.timeToFix.find((r) => r.severity === "low")).toEqual({
      severity: "low",
      resolved: 0,
      medianDays: null,
    });
  });

  it("refuses an unknown time zone", async () => {
    await expect(
      organizationStatistics(t.db, { organizationId: "x", timeZone: "Mars/Base", days: 30 }),
    ).rejects.toThrow(RangeError);
  });
});
