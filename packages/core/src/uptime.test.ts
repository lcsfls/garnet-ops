import { describe, expect, it } from "vitest";
import { nextUptimeState, type UptimeCheck, uptimeHours, uptimeIncidents, uptimeStats } from "./uptime.ts";

const check = (minute: number, up: boolean, extra: Partial<UptimeCheck> = {}): UptimeCheck => ({
  checkedAt: new Date(Date.UTC(2026, 9, 30, 12, minute)).toISOString(),
  up,
  status: up ? 200 : null,
  responseMs: up ? 100 + minute : null,
  error: up ? null : "timeout",
  ...extra,
});

describe("availability of websites (ADR 0040)", () => {
  it("turns down only after three failures in a row, and up with the first success", () => {
    let s = nextUptimeState({ state: null, failures: 0 }, true);
    expect(s).toEqual({ state: "up", failures: 0, changed: null });
    s = nextUptimeState(s, false);
    s = nextUptimeState(s, false);
    expect(s).toMatchObject({ state: "up", failures: 2, changed: null });
    s = nextUptimeState(s, false);
    expect(s).toMatchObject({ state: "down", failures: 3, changed: "down" });
    s = nextUptimeState(s, false);
    expect(s.changed).toBeNull();
    expect(nextUptimeState(s, true)).toEqual({ state: "up", failures: 0, changed: "up" });
  });

  it("adds up the share of good checks and their average answer time", () => {
    const checks = [check(0, true), check(5, true), check(10, false), check(15, true)];
    expect(uptimeStats(checks, new Date(Date.UTC(2026, 9, 30)))).toEqual({
      percent: 75,
      averageMs: 107,
      checks: 4,
    });
    expect(uptimeStats(checks, new Date(Date.UTC(2026, 10, 1))).percent).toBeNull();
  });

  it("finds outages of three failures or more, with their first reason, and one that still lasts", () => {
    const checks = [
      check(0, true),
      check(1, false, { error: "status", status: 502 }),
      check(2, false),
      check(3, false),
      check(4, true),
      check(5, false),
      check(6, true),
      check(7, false, { error: "tls" }),
      check(8, false),
      check(9, false),
    ];
    expect(uptimeIncidents(checks)).toEqual([
      { from: checks[1]?.checkedAt, to: checks[4]?.checkedAt, error: "status", status: 502 },
      { from: checks[7]?.checkedAt, to: null, error: "tls", status: null },
    ]);
  });

  it("groups the last 24 hours into hourly buckets, oldest first", () => {
    const now = new Date(Date.UTC(2026, 9, 30, 13, 0));
    const hours = uptimeHours(
      [
        check(-1500, true),
        check(5, true),
        check(10, false, { error: "status", status: 503 }),
        check(30, true),
      ],
      now,
    );
    expect(hours).toHaveLength(24);
    expect(hours[0]?.from).toBe("2026-10-29T13:00:00.000Z");
    // 12:05 to 12:30 fall into the last hour; the check of the day before is outside.
    expect(hours[23]).toMatchObject({ checks: 3, failures: 1, error: "status", status: 503, averageMs: 118 });
    expect(hours.slice(0, 23).every((h) => h.checks === 0)).toBe(true);
  });
});
