/**
 * Time handling against a real PostgreSQL (AGENTS.md: time zones, dates and
 * DST transitions get explicit tests). Uses a throw-away database on the
 * development server from `pnpm dev`; skipped when that is not set up.
 *
 * Instants are fixed and written in UTC. 2026 transitions in Europe/Berlin:
 * spring forward 2026-03-29 01:00 UTC (02:00 -> 03:00 local, a 23-hour day),
 * fall back 2026-10-25 01:00 UTC (03:00 -> 02:00 local, a 25-hour day).
 */
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb, type Database, openFindingsTrend, runMigrations, schema } from "./index.ts";

function devDatabaseUrl(): string | null {
  try {
    const line = readFileSync(new URL("../../../.data/dev.env", import.meta.url), "utf8")
      .split("\n")
      .find((l) => l.startsWith("DATABASE_URL="));
    return line ? line.slice("DATABASE_URL=".length).trim() : null;
  } catch {
    return null;
  }
}

const adminUrl = devDatabaseUrl();
const dbName = `garnetops_test_${process.pid}`;

describe.skipIf(!adminUrl)("time handling in the database", () => {
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let db: Database;
  const org = "org_time";
  const repo = "repo_time";

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    conn = createDb(url.toString(), { max: 2 });
    db = conn.db;
    await runMigrations(db);
    await db.insert(schema.organization).values({ id: org, name: "Time" });
    await db
      .insert(schema.repository)
      .values({ id: repo, organizationId: org, name: "r", url: "https://x.test/r", authKind: "none" });
    await db.insert(schema.vulnerability).values({ id: "CVE-T", severity: "high" });
  }, 60_000);

  afterAll(async () => {
    await conn?.pool.end();
    await admin?.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin?.pool.end();
  });

  async function finding(id: string, firstSeen: string, resolved: string | null = null) {
    await db.insert(schema.finding).values({
      id,
      organizationId: org,
      repositoryId: repo,
      vulnerabilityId: "CVE-T",
      dedupKey: id,
      packageName: id,
      packageVersion: "1",
      packageType: "npm",
      severity: "high",
      severityRank: 4,
      state: resolved ? "resolved" : "open",
      firstSeenScanId: "s",
      lastSeenScanId: "s",
      firstSeenAt: new Date(firstSeen),
      lastSeenAt: new Date(firstSeen),
      resolvedAt: resolved ? new Date(resolved) : null,
    });
  }

  it("runs every session in UTC, whatever the server's zone is", async () => {
    const { rows } = await conn.pool.query("show timezone");
    expect(rows[0].TimeZone).toBe("UTC");
  });

  it("returns SQL dates as plain strings, not shifted Date objects", async () => {
    const { rows } = await conn.pool.query("select '2026-10-25'::date as d");
    expect(rows[0].d).toBe("2026-10-25");
  });

  it("stores and returns instants unchanged across the autumn switch", async () => {
    const before = new Date("2026-10-25T00:30:00Z"); // 02:30 CEST, first pass
    const after = new Date("2026-10-25T01:30:00Z"); // 02:30 CET, second pass
    const { rows } = await conn.pool.query("select $1::timestamptz as a, $2::timestamptz as b", [
      before,
      after,
    ]);
    expect(rows[0].a.toISOString()).toBe(before.toISOString());
    expect(rows[0].b.toISOString()).toBe(after.toISOString());
    expect(rows[0].b.getTime() - rows[0].a.getTime()).toBe(3600_000);
  });

  it("counts each calendar day exactly once over the 25-hour autumn day", async () => {
    // First seen 2026-10-24 22:30 UTC = 2026-10-25 00:30 in Berlin (still CEST).
    await finding("f_autumn", "2026-10-24T22:30:00Z");
    const asOf = new Date("2026-10-26T12:00:00Z");

    const berlin = await openFindingsTrend(db, {
      organizationId: org,
      timeZone: "Europe/Berlin",
      days: 4,
      asOf,
    });
    expect(berlin).toEqual([
      { day: "2026-10-25", severity: "high", n: 1 },
      { day: "2026-10-26", severity: "high", n: 1 },
    ]);

    // The same instant is still 2026-10-24 in UTC.
    const utc = await openFindingsTrend(db, { organizationId: org, timeZone: "UTC", days: 4, asOf });
    expect(utc.map((p) => p.day)).toEqual(["2026-10-24", "2026-10-25", "2026-10-26"]);
  });

  it("does not skip the 23-hour spring day", async () => {
    // First seen 2026-03-29 00:30 UTC = 01:30 CET, before the jump; resolved 03:30 CEST the same day.
    await finding("f_spring", "2026-03-29T00:30:00Z", "2026-03-29T01:30:00Z");
    // Seen on 2026-03-28, resolved on 2026-03-30 local time.
    await finding("f_spring_long", "2026-03-28T12:00:00Z", "2026-03-30T08:00:00Z");
    const asOf = new Date("2026-03-30T12:00:00Z");

    const days = await openFindingsTrend(db, {
      organizationId: org,
      timeZone: "Europe/Berlin",
      days: 4,
      asOf,
    });
    // f_spring is resolved on its first day, so it is never open at the end of a day.
    // f_spring_long is open at the end of 03-28 and 03-29 (the short day), resolved on 03-30.
    expect(days).toEqual([
      { day: "2026-03-28", severity: "high", n: 1 },
      { day: "2026-03-29", severity: "high", n: 1 },
    ]);
  });

  it("limits the trend to one repository when asked", async () => {
    await finding("f_repo", "2026-05-10T12:00:00Z");
    const asOf = new Date("2026-05-11T12:00:00Z");
    const all = await openFindingsTrend(db, { organizationId: org, timeZone: "UTC", days: 2, asOf });
    const mine = await openFindingsTrend(db, {
      organizationId: org,
      repositoryId: repo,
      timeZone: "UTC",
      days: 2,
      asOf,
    });
    const other = await openFindingsTrend(db, {
      organizationId: org,
      repositoryId: "repo_other",
      timeZone: "UTC",
      days: 2,
      asOf,
    });
    expect(mine).toEqual(all);
    expect(mine.length).toBeGreaterThan(0);
    expect(other).toEqual([]);
  });

  it("refuses unknown time zones before they reach SQL", async () => {
    await expect(openFindingsTrend(db, { organizationId: org, timeZone: "Europe/Atlantis" })).rejects.toThrow(
      RangeError,
    );
    await expect(
      openFindingsTrend(db, { organizationId: org, timeZone: "UTC'; drop table finding; --" }),
    ).rejects.toThrow(RangeError);
  });
});
