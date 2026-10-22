import { describe, expect, it } from "vitest";
import { ageOf, freshnessOf, mergeEvent } from "./attack-feed.ts";
import type { AttackEvent, AttackLiveInfo } from "./types.ts";

const event = (seq: number, over: Partial<AttackEvent> = {}): AttackEvent => ({
  seq,
  at: "2026-10-21T08:00:00.000Z",
  ip: "198.51.100.1",
  scope: "public",
  country: "DE",
  asn: null,
  ruleId: "5710",
  level: 10,
  description: "x",
  groups: [],
  agentId: "001",
  agentName: "web-01",
  score: null,
  source: "wazuh",
  action: null,
  destPort: null,
  ...over,
});
const live = (over: Partial<AttackLiveInfo> = {}): AttackLiveInfo => ({
  enabled: true,
  intervalSeconds: 30,
  minLevel: 7,
  state: "live",
  reason: null,
  error: null,
  lastEventAt: null,
  lastPollAt: null,
  ...over,
});

describe("merging a new event into the list", () => {
  it("puts it on top, newest first", () => {
    const merged = mergeEvent([event(3), event(2)], event(4));
    expect(merged.map((e) => e.seq)).toEqual([4, 3, 2]);
  });
  it("ignores an event that is there already (a replay after a reconnect)", () => {
    expect(mergeEvent([event(3), event(2)], event(3)).map((e) => e.seq)).toEqual([3, 2]);
  });
  it("keeps the newest 50 and orders a late arrival by its number", () => {
    const list = Array.from({ length: 50 }, (_, i) => event(100 - i));
    const merged = mergeEvent(list, event(101));
    expect(merged).toHaveLength(50);
    expect(merged[0]?.seq).toBe(101);
    expect(merged.at(-1)?.seq).toBe(52);
    expect(mergeEvent([event(5), event(3)], event(4)).map((e) => e.seq)).toEqual([5, 4, 3]);
    // An event older than the whole full list does not get in.
    expect(mergeEvent(list, event(1)).some((e) => e.seq === 1)).toBe(false);
  });
});

describe("what the page says about freshness", () => {
  it("live with the time of the last event", () => {
    expect(freshnessOf(live({ lastEventAt: "2026-10-21T08:00:00.000Z" }))).toEqual({
      kind: "live",
      lastEventAt: "2026-10-21T08:00:00.000Z",
    });
    expect(freshnessOf(live())).toEqual({ kind: "live", lastEventAt: null });
  });
  it("waiting for Wazuh, with the reason if the last poll failed, and before anything is known", () => {
    expect(freshnessOf(live({ state: "waiting" }))).toEqual({ kind: "waiting", error: null });
    expect(freshnessOf(live({ state: "waiting", error: "unreachable" }))).toEqual({
      kind: "waiting",
      error: "unreachable",
    });
    expect(freshnessOf(null)).toEqual({ kind: "waiting", error: null });
    expect(freshnessOf(undefined)).toEqual({ kind: "waiting", error: null });
  });
  it("paused when the connection is blocked, off when an admin switched it off", () => {
    expect(freshnessOf(live({ state: "paused", reason: "certificate" }))).toEqual({
      kind: "paused",
      reason: "certificate",
    });
    expect(freshnessOf(live({ state: "off" }))).toEqual({ kind: "off" });
  });
});

describe("age", () => {
  const now = Date.parse("2026-10-21T08:10:00.000Z");
  it("counts seconds, then minutes, hours and days", () => {
    expect(ageOf("2026-10-21T08:09:48.000Z", now)).toEqual({ value: -12, unit: "second" });
    expect(ageOf("2026-10-21T08:07:00.000Z", now)).toEqual({ value: -3, unit: "minute" });
    expect(ageOf("2026-10-21T05:10:00.000Z", now)).toEqual({ value: -3, unit: "hour" });
    expect(ageOf("2026-10-19T08:10:00.000Z", now)).toEqual({ value: -2, unit: "day" });
  });
  it("never shows a time in the future", () => {
    expect(ageOf("2026-10-21T08:11:00.000Z", now)).toEqual({ value: -0, unit: "second" });
  });
});
