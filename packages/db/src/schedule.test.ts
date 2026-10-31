/**
 * Nightly runs across daylight-saving changes (ADR 0005), against a real
 * PostgreSQL. The test organisation is scheduled at 02:30 Europe/Berlin on
 * purpose: that local time happens twice on 2026-10-25 and not at all on
 * 2026-03-29. All instants are fixed and written in UTC.
 */
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startDueNightlyRuns, strandedQueuedScans } from "./schedule.ts";
import * as schema from "./schema.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";

const adminUrl = devDatabaseUrl();

describe.skipIf(!adminUrl)("nightly scan schedule", () => {
  let t: TestDatabase;

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "schedule_test");
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });

  let counter = 0;
  /** A fresh organisation with two repositories, so tests do not see each other's runs. */
  async function org(options: { time?: string; zone?: string; enabled?: boolean } = {}) {
    const id = `org_s${++counter}`;
    await t.db.insert(schema.organization).values({
      id,
      name: id,
      scanLocalTime: options.time ?? "02:30:00",
      scanTimeZone: options.zone ?? "Europe/Berlin",
      scanScheduleEnabled: options.enabled ?? true,
    });
    for (const n of [1, 2]) {
      await t.db.insert(schema.repository).values({
        id: `${id}_r${n}`,
        organizationId: id,
        name: `r${n}`,
        url: `https://x.test/${id}/${n}`,
        authKind: "none",
      });
    }
    return id;
  }
  const runsOf = async (id: string, asOf: string) =>
    (await startDueNightlyRuns(t.db, new Date(asOf))).filter((r) => r.organizationId === id);
  const finishScans = (id: string) =>
    t.db.update(schema.scan).set({ state: "succeeded" }).where(eq(schema.scan.organizationId, id));

  it("does not run before the scheduled local time and runs once it is reached", async () => {
    const id = await org();
    expect(await runsOf(id, "2026-10-24T00:20:00Z")).toEqual([]); // 02:20 CEST
    const [run] = await runsOf(id, "2026-10-24T00:30:00Z"); // 02:30 CEST
    expect(run).toMatchObject({ localDate: "2026-10-24" });
    expect(run?.scans).toHaveLength(2);

    const scans = await t.db.select().from(schema.scan).where(eq(schema.scan.organizationId, id));
    expect(scans.map((s) => [s.trigger, s.state])).toEqual([
      ["schedule", "queued"],
      ["schedule", "queued"],
    ]);
  });

  it("runs once on the 25-hour autumn day, although 02:30 happens twice", async () => {
    const id = await org();
    const first = await runsOf(id, "2026-10-25T00:30:00Z"); // 02:30 CEST, first pass
    expect(first.map((r) => r.localDate)).toEqual(["2026-10-25"]);
    await finishScans(id);
    expect(await runsOf(id, "2026-10-25T01:30:00Z")).toEqual([]); // 02:30 CET, second pass
    expect(await runsOf(id, "2026-10-25T22:59:00Z")).toEqual([]); // 23:59 CET, same day
    const next = await runsOf(id, "2026-10-26T01:30:00Z"); // 02:30 CET, next day
    expect(next.map((r) => r.localDate)).toEqual(["2026-10-26"]);
  });

  it("catches up on the 23-hour spring day, when 02:30 does not exist", async () => {
    const id = await org();
    expect(await runsOf(id, "2026-03-29T00:59:00Z")).toEqual([]); // 01:59 CET
    const [run] = await runsOf(id, "2026-03-29T01:00:00Z"); // 03:00 CEST, right after the jump
    expect(run?.localDate).toBe("2026-03-29");
  });

  it("uses the organisation's zone, not the database's", async () => {
    const id = await org({ time: "04:00:00", zone: "UTC" });
    expect(await runsOf(id, "2026-10-25T03:59:00Z")).toEqual([]);
    expect((await runsOf(id, "2026-10-25T04:00:00Z")).map((r) => r.localDate)).toEqual(["2026-10-25"]);

    const ny = await org({ time: "04:00:00", zone: "America/New_York" });
    // 04:00 UTC is 00:00 in New York (EDT): not due yet there.
    expect(await runsOf(ny, "2026-10-25T04:00:00Z")).toEqual([]);
    expect((await runsOf(ny, "2026-10-25T08:00:00Z")).map((r) => r.localDate)).toEqual(["2026-10-25"]);
  });

  it("starts each run exactly once when several workers tick at the same moment", async () => {
    const id = await org();
    const asOf = "2026-06-10T00:45:00Z"; // 02:45 CEST
    const results = await Promise.all(Array.from({ length: 4 }, () => runsOf(id, asOf)));
    expect(results.flat()).toHaveLength(1);
    const scans = await t.db.select().from(schema.scan).where(eq(schema.scan.organizationId, id));
    expect(scans).toHaveLength(2);
  });

  it("does not queue a second scan for a repository that is already being scanned", async () => {
    const id = await org();
    await t.db.insert(schema.scan).values({
      id: `${id}_busy`,
      organizationId: id,
      repositoryId: `${id}_r1`,
      state: "running",
      trigger: "manual",
      createdAt: new Date(),
    });
    const [run] = await runsOf(id, "2026-06-11T00:45:00Z");
    expect(run?.scans.map((s) => s.repositoryId)).toEqual([`${id}_r2`]);
    const [row] = await t.db
      .select()
      .from(schema.scanScheduleRun)
      .where(eq(schema.scanScheduleRun.organizationId, id));
    expect(row?.queuedScans).toBe(1);
  });

  it("does not scan a repository that is set aside (ADR 0043)", async () => {
    const id = await org();
    await t.db
      .update(schema.repository)
      .set({ inactiveAt: new Date() })
      .where(eq(schema.repository.id, `${id}_r1`));
    const [run] = await runsOf(id, "2026-06-11T00:45:00Z");
    expect(run?.scans.map((s) => s.repositoryId)).toEqual([`${id}_r2`]);
  });

  it("skips disabled organisations and unknown zones without failing the others", async () => {
    const off = await org({ enabled: false });
    const broken = await org({ zone: "Europe/Atlantis" });
    const fine = await org();
    const all = await startDueNightlyRuns(t.db, new Date("2026-06-12T00:45:00Z"));
    const ids = all.map((r) => r.organizationId);
    expect(ids).toContain(fine);
    expect(ids).not.toContain(off);
    expect(ids).not.toContain(broken);
  });

  it("finds queued scans whose job may have been lost", async () => {
    const id = await org();
    await t.db.insert(schema.scan).values({
      id: `${id}_old`,
      organizationId: id,
      repositoryId: `${id}_r1`,
      state: "queued",
      trigger: "schedule",
      createdAt: new Date(Date.now() - 20 * 60_000),
    });
    const stranded = await strandedQueuedScans(t.db);
    expect(stranded).toContainEqual({ scanId: `${id}_old`, repositoryId: `${id}_r1` });
  });

  it("runs once even when several workers tick together", async () => {
    const id = await org();
    const results = await Promise.all(Array.from({ length: 4 }, () => runsOf(id, "2026-06-15T00:45:00Z")));
    expect(results.flat()).toHaveLength(1);
    const scans = await t.db.select().from(schema.scan).where(eq(schema.scan.organizationId, id));
    expect(scans).toHaveLength(2);
  });
});
