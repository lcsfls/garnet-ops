import { describe, expect, it } from "vitest";
import {
  backoffMs,
  type Cursor,
  isLiveInterval,
  isLiveLevel,
  LIVE_BACKOFF_CAP_MS,
  LIVE_CATCH_UP_DELAY_MS,
  LIVE_CATCH_UP_POLLS,
  LIVE_MAX_LOOKBACK_MS,
  LIVE_START_LOOKBACK_MS,
  type LiveStatusInput,
  liveChannel,
  liveStatus,
  nextCursor,
  nextDelayMs,
  pollSince,
} from "./attack-live.ts";

const t = (iso: string) => new Date(iso);

describe("cursor", () => {
  const now = t("2026-10-21T08:00:00.000Z");

  it("starts five minutes back on the first poll: no backfill flood", () => {
    expect(pollSince(null, now).toISOString()).toBe("2026-10-21T07:55:00.000Z");
    expect(LIVE_START_LOOKBACK_MS).toBe(5 * 60_000);
  });

  it("continues at the cursor, but never reaches back more than fifteen minutes", () => {
    expect(pollSince(t("2026-10-21T07:59:30.000Z"), now).toISOString()).toBe("2026-10-21T07:59:30.000Z");
    expect(pollSince(t("2026-10-21T03:00:00.000Z"), now).toISOString()).toBe("2026-10-21T07:45:00.000Z");
    expect(LIVE_MAX_LOOKBACK_MS).toBe(15 * 60_000);
  });

  it("moves to the newest alert read, with its id", () => {
    const read = [
      { at: t("2026-10-21T07:59:01.000Z"), docId: "a" },
      { at: t("2026-10-21T07:59:05.000Z"), docId: "b" },
      { at: t("2026-10-21T07:59:05.000Z"), docId: "c" },
    ];
    const cursor = nextCursor(t("2026-10-21T07:59:00.000Z"), read, t("2026-10-21T07:59:05.000Z"), false);
    expect(cursor).toEqual({ at: t("2026-10-21T07:59:05.000Z"), id: "c" });
  });

  it("stays where it is when nothing new was read, and never moves backwards", () => {
    const current = t("2026-10-21T07:59:05.000Z");
    expect(nextCursor(current, [], null, false)).toEqual({ at: current, id: null });
    expect(nextCursor(current, [{ at: t("2026-10-21T07:58:00.000Z"), docId: "old" }], null, false)).toEqual({
      at: current,
      id: null,
    });
    expect(nextCursor(null, [], null, false)).toBeNull();
  });

  it("follows a dropped alert too, so a hit that cannot be stored does not block the feed", () => {
    const cursor = nextCursor(t("2026-10-21T07:59:00.000Z"), [], t("2026-10-21T07:59:30.000Z"), false);
    expect(cursor).toEqual({ at: t("2026-10-21T07:59:30.000Z"), id: null });
  });

  it("steps one millisecond past a full page that shares one time, so the feed cannot stall", () => {
    const at = t("2026-10-21T07:59:05.000Z");
    const read = Array.from({ length: 50 }, (_, i) => ({ at, docId: `x${i}` }));
    const cursor = nextCursor(at, read, at, true) as Cursor;
    expect(cursor.at.toISOString()).toBe("2026-10-21T07:59:05.001Z");
    // A full page that did move forward is left alone.
    const moved = nextCursor(
      at,
      [{ at: t("2026-10-21T07:59:09.000Z"), docId: "n" }],
      t("2026-10-21T07:59:09.000Z"),
      true,
    );
    expect(moved?.at.toISOString()).toBe("2026-10-21T07:59:09.000Z");
  });
});

describe("rhythm", () => {
  it("polls at the interval, and sooner (a few times in a row) after a full page", () => {
    expect(nextDelayMs(30, false, 0)).toBe(30_000);
    expect(nextDelayMs(30, true, 0)).toBe(LIVE_CATCH_UP_DELAY_MS);
    expect(nextDelayMs(300, true, LIVE_CATCH_UP_POLLS - 1)).toBe(LIVE_CATCH_UP_DELAY_MS);
    expect(nextDelayMs(30, true, LIVE_CATCH_UP_POLLS)).toBe(30_000);
    // Catching up is never slower than the interval itself.
    expect(nextDelayMs(15, true, 0)).toBe(LIVE_CATCH_UP_DELAY_MS);
  });

  it("backs off after errors: doubling, capped at ten minutes, never faster than the interval", () => {
    expect(backoffMs(30, 1)).toBe(60_000);
    expect(backoffMs(30, 2)).toBe(120_000);
    expect(backoffMs(30, 3)).toBe(240_000);
    expect(backoffMs(30, 4)).toBe(480_000);
    expect(backoffMs(30, 5)).toBe(LIVE_BACKOFF_CAP_MS);
    expect(backoffMs(300, 1)).toBe(LIVE_BACKOFF_CAP_MS);
    expect(backoffMs(15, 0)).toBe(30_000);
    expect(backoffMs(15, 10_000)).toBe(LIVE_BACKOFF_CAP_MS);
  });
});

describe("bounds and channel", () => {
  it("accepts an interval of 15 to 300 seconds and a level of 3 to 15, whole numbers only", () => {
    for (const ok of [15, 30, 300]) expect(isLiveInterval(ok)).toBe(true);
    for (const bad of [14, 301, 30.5, "30", null, Number.NaN]) expect(isLiveInterval(bad)).toBe(false);
    for (const ok of [3, 7, 15]) expect(isLiveLevel(ok)).toBe(true);
    for (const bad of [2, 16, 7.5, "7", undefined]) expect(isLiveLevel(bad)).toBe(false);
  });

  it("makes a per-organisation channel name that is a plain identifier", () => {
    expect(liveChannel("org_ABC123")).toBe("attack_live_org_abc123");
    expect(liveChannel("org_a")).not.toBe(liveChannel("org_b"));
    expect(liveChannel('x"; drop table y; --')).toMatch(/^[a-z][a-z0-9_]{0,62}$/);
    expect(liveChannel("o".repeat(200))).toHaveLength(63);
  });
});

describe("status", () => {
  const now = t("2026-10-21T08:00:00.000Z");
  const base: LiveStatusInput = {
    feedEnabled: true,
    connectionEnabled: true,
    certificatesOk: true,
    privilegesOk: true,
    adapterKnown: true,
    lastPollAt: t("2026-10-21T07:59:50.000Z"),
    lastError: null,
    intervalSeconds: 30,
    now,
  };
  const status = (over: Partial<LiveStatusInput>) => liveStatus({ ...base, ...over });

  it("is live while polls succeed", () => {
    expect(status({})).toEqual({ state: "live", reason: null, error: null });
  });
  it("is off when an admin switched the feed off, whatever else is true", () => {
    expect(status({ feedEnabled: false, certificatesOk: false }).state).toBe("off");
  });
  it("is paused, with the reason, when the connection is blocked", () => {
    expect(status({ connectionEnabled: false })).toMatchObject({ state: "paused", reason: "disabled" });
    expect(status({ certificatesOk: false })).toMatchObject({ state: "paused", reason: "certificate" });
    expect(status({ privilegesOk: false })).toMatchObject({ state: "paused", reason: "privileges" });
  });
  it("is waiting before the first sync or poll, after a failed poll, and when the worker went quiet", () => {
    expect(status({ adapterKnown: false }).state).toBe("waiting");
    expect(status({ lastPollAt: null }).state).toBe("waiting");
    expect(status({ lastError: "unreachable" })).toEqual({
      state: "waiting",
      reason: null,
      error: "unreachable",
    });
    // Three intervals and a minute without a poll.
    expect(status({ lastPollAt: t("2026-10-21T07:58:00.000Z") }).state).toBe("live");
    expect(status({ lastPollAt: t("2026-10-21T07:57:00.000Z") }).state).toBe("waiting");
  });
});
