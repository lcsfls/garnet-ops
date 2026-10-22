import { describe, expect, it } from "vitest";
import { eventMessageKey, groupByDay, newestId, unreadBadge } from "./notifications.ts";

const at = (createdAt: string) => ({ createdAt });

describe("unread badge", () => {
  it("shows the number and caps it at 99+", () => {
    expect([0, 1, 9, 99, 100, 1000].map(unreadBadge)).toEqual(["0", "1", "9", "99", "99+", "99+"]);
  });
});

describe("grouping by day in the user's zone", () => {
  it("names today and yesterday and the other days by date", () => {
    const now = new Date("2026-10-26T09:00:00Z"); // Monday in Berlin
    const groups = groupByDay(
      [
        at("2026-10-26T08:30:00Z"),
        at("2026-10-26T06:00:00Z"),
        at("2026-10-25T20:00:00Z"),
        at("2026-10-22T10:00:00Z"),
        at("2026-10-22T09:00:00Z"),
      ],
      now,
      "Europe/Berlin",
    );
    expect(groups.map((g) => [g.key, g.items.length])).toEqual([
      ["today", 2],
      ["yesterday", 1],
      ["2026-10-22", 2],
    ]);
  });

  it("uses the zone, not the browser: late evening UTC is already tomorrow in Berlin", () => {
    const now = new Date("2026-10-26T10:00:00Z");
    const berlin = groupByDay([at("2026-10-25T23:30:00Z")], now, "Europe/Berlin");
    expect(berlin[0]?.key).toBe("today"); // 00:30 on the 26th in Berlin (CET)
    const la = groupByDay([at("2026-10-25T23:30:00Z")], now, "America/Los_Angeles");
    expect(la[0]?.key).toBe("yesterday"); // 16:30 on the 25th in Los Angeles
  });

  it("calls the day before a daylight-saving switch 'yesterday'", () => {
    // Berlin falls back on 2026-10-25 (25 hours): Saturday 12:00 CEST is 25 hours before Sunday 12:00 CET.
    const now = new Date("2026-10-25T11:00:00Z");
    expect(groupByDay([at("2026-10-24T10:00:00Z")], now, "Europe/Berlin")[0]?.key).toBe("yesterday");
    // Spring: Saturday 12:00 CET is 23 hours before Sunday 12:00 CEST.
    const spring = new Date("2026-03-29T10:00:00Z");
    expect(groupByDay([at("2026-03-28T11:00:00Z")], spring, "Europe/Berlin")[0]?.key).toBe("yesterday");
    // Yesterday across a month change.
    expect(groupByDay([at("2026-09-30T12:00:00Z")], new Date("2026-10-01T12:00:00Z"), "UTC")[0]?.key).toBe(
      "yesterday",
    );
  });

  it("gives nothing for no notifications", () => {
    expect(groupByDay([], new Date(), "UTC")).toEqual([]);
  });
});

describe("helpers", () => {
  it("finds the newest id across pages", () => {
    const page = (ids: number[]) => ({
      items: ids.map((id) => ({
        id,
        event: "",
        titleKey: "",
        params: {},
        link: "/",
        createdAt: "",
        readAt: null,
      })),
      unread: 0,
      next: null,
    });
    expect(newestId([page([5, 3]), page([2, 1])])).toBe(5);
    expect(newestId(undefined)).toBe(0);
    expect(newestId([])).toBe(0);
  });

  it("turns event names into message keys", () => {
    expect(eventMessageKey("finding.new_critical")).toBe("findingNewCritical");
    expect(eventMessageKey("fix_pr.merged")).toBe("fixPrMerged");
    expect(eventMessageKey("infra.host_key_changed")).toBe("infraHostKeyChanged");
    expect(eventMessageKey("gate.blocked")).toBe("gateBlocked");
  });
});
