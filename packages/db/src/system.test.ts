/**
 * The reads of the System status page (ADR 0024) against a real PostgreSQL: the next nightly
 * run in the organisation's zone across daylight-saving changes (ADR 0005), and the migration
 * state. The test organisation runs at 02:30 Europe/Berlin on purpose: that local time happens
 * twice on 2026-10-25 and not at all on 2026-03-29. All instants are fixed and written in UTC.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as schema from "./schema.ts";
import { databaseState, nextNightlyRun } from "./system.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";

const adminUrl = devDatabaseUrl();

describe.skipIf(!adminUrl)("system status reads", () => {
  let t: TestDatabase;
  let counter = 0;

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "system_test");
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });

  async function org(options: { time?: string; zone?: string; enabled?: boolean } = {}) {
    const id = `org_sys${++counter}`;
    await t.db.insert(schema.organization).values({
      id,
      name: id,
      scanLocalTime: options.time ?? "02:30:00",
      scanTimeZone: options.zone ?? "Europe/Berlin",
      scanScheduleEnabled: options.enabled ?? true,
    });
    return id;
  }
  const next = async (id: string, asOf: string) =>
    (await nextNightlyRun(t.db, id, new Date(asOf)))?.at?.toISOString();

  it("is today at the scheduled local time before it, and due once it has passed without a run", async () => {
    const id = await org();
    expect(await next(id, "2026-10-24T00:00:00Z")).toBe("2026-10-24T00:30:00.000Z"); // 02:30 CEST today
    // 02:45 CEST and no run yet: the instant lies in the past, the next tick starts it.
    expect(await next(id, "2026-10-24T00:45:00Z")).toBe("2026-10-24T00:30:00.000Z");
  });

  it("is tomorrow once today's run exists", async () => {
    const id = await org();
    await t.db
      .insert(schema.scanScheduleRun)
      .values({ organizationId: id, localDate: "2026-10-24", queuedScans: 0 });
    // 25 October is the 25-hour day: 02:30 is read twice, and PostgreSQL picks the second (CET) one,
    // so the answer can be an hour later than the real run (documented in docs/system-status.md).
    expect(await next(id, "2026-10-24T08:00:00Z")).toBe("2026-10-25T01:30:00.000Z");
  });

  it("follows the zone across the autumn change: the day after the 25-hour day is at 02:30 CET", async () => {
    const id = await org();
    await t.db
      .insert(schema.scanScheduleRun)
      .values({ organizationId: id, localDate: "2026-10-25", queuedScans: 0 });
    // 2026-10-25 has 25 hours; the next run is the 26th at 02:30 CET (01:30 UTC).
    expect(await next(id, "2026-10-25T12:00:00Z")).toBe("2026-10-26T01:30:00.000Z");
    // The repeated hour does not start a second run on the same date.
    expect(await next(id, "2026-10-25T01:40:00Z")).toBe("2026-10-26T01:30:00.000Z");
  });

  it("moves the nonexistent spring time and keeps the date", async () => {
    const id = await org();
    await t.db
      .insert(schema.scanScheduleRun)
      .values({ organizationId: id, localDate: "2026-03-28", queuedScans: 0 });
    const at = await next(id, "2026-03-28T05:00:00Z"); // 06:00 CET on the 28th, the 29th is next
    // 02:30 does not exist on 2026-03-29; PostgreSQL reads it with the offset before the jump (03:30 CEST).
    expect(at).toBe("2026-03-29T01:30:00.000Z");
  });

  it("gives nothing for a switched-off schedule and for a zone the database does not know", async () => {
    const off = await org({ enabled: false });
    expect(await nextNightlyRun(t.db, off, new Date("2026-10-24T00:00:00Z"))).toMatchObject({
      enabled: false,
      at: null,
      timeZone: "Europe/Berlin",
    });
    const odd = await org({ zone: "Mars/Olympus" });
    expect(await nextNightlyRun(t.db, odd, new Date("2026-10-24T00:00:00Z"))).toMatchObject({ at: null });
    expect(await nextNightlyRun(t.db, "org_missing")).toBeNull();
  });

  it("reports the database size and that every shipped migration is applied", async () => {
    const state = await databaseState(t.db);
    expect(state.sizeBytes).toBeGreaterThan(0);
    expect(state.migrations.expected).toBeGreaterThan(20);
    expect(state.migrations.applied).toBe(state.migrations.expected);
    expect(state.migrations.latest).toMatch(/^\d{4}_/);
  });
});
