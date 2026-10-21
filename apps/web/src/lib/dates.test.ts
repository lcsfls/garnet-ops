/**
 * Calendar arithmetic under real time zones (AGENTS.md: DST transitions get
 * explicit tests). Node applies a changed process.env.TZ immediately, so each
 * test pins the zone it simulates; all instants are written in UTC.
 *
 * Europe/Berlin 2026: spring forward 2026-03-29 02:00 -> 03:00 (23-hour day),
 * fall back 2026-10-25 03:00 -> 02:00 (25-hour day).
 * America/Santiago 2026: clocks jump at midnight, 2026-09-06 00:00 -> 01:00,
 * so that local midnight does not exist.
 */
import { afterEach, describe, expect, it } from "vitest";
import { addLocalDays, endOfLocalDay, localDateInput, relativeTime } from "./dates.ts";

const originalTz = process.env.TZ;
afterEach(() => {
  process.env.TZ = originalTz;
});
const inZone = (tz: string) => {
  process.env.TZ = tz;
};

describe("localDateInput", () => {
  it("uses the local calendar day, not the UTC one", () => {
    inZone("Europe/Berlin");
    // 00:30 on 25 October in Berlin is still 24 October in UTC.
    expect(localDateInput(new Date("2026-10-24T22:30:00Z"))).toBe("2026-10-25");
    inZone("America/New_York");
    // 21:00 on 24 October in New York is already 25 October in UTC.
    expect(localDateInput(new Date("2026-10-25T01:00:00Z"))).toBe("2026-10-24");
  });
});

describe("addLocalDays", () => {
  it("keeps the wall-clock time across the autumn switch (25-hour day)", () => {
    inZone("Europe/Berlin");
    const sat = new Date("2026-10-24T10:00:00Z"); // 12:00 CEST
    const sun = addLocalDays(sat, 1); // 12:00 CET
    expect(sun.toISOString()).toBe("2026-10-25T11:00:00.000Z");
    expect(sun.getTime() - sat.getTime()).toBe(25 * 3600_000);
  });

  it("keeps the wall-clock time across the spring switch (23-hour day)", () => {
    inZone("Europe/Berlin");
    const sat = new Date("2026-03-28T11:00:00Z"); // 12:00 CET
    const sun = addLocalDays(sat, 1); // 12:00 CEST
    expect(sun.toISOString()).toBe("2026-03-29T10:00:00.000Z");
    expect(sun.getTime() - sat.getTime()).toBe(23 * 3600_000);
  });
});

describe("endOfLocalDay", () => {
  it("ends the 25-hour autumn day at the next local midnight", () => {
    inZone("Europe/Berlin");
    expect(endOfLocalDay("2026-10-25").toISOString()).toBe("2026-10-25T23:00:00.000Z"); // 26 Oct 00:00 CET
  });

  it("ends the 23-hour spring day at the next local midnight", () => {
    inZone("Europe/Berlin");
    expect(endOfLocalDay("2026-03-29").toISOString()).toBe("2026-03-29T22:00:00.000Z"); // 30 Mar 00:00 CEST
  });

  it("is the same calendar day for a user in UTC and a later instant for a user west of it", () => {
    inZone("UTC");
    expect(endOfLocalDay("2027-01-19").toISOString()).toBe("2027-01-20T00:00:00.000Z");
    inZone("America/Los_Angeles");
    expect(endOfLocalDay("2027-01-19").toISOString()).toBe("2027-01-20T08:00:00.000Z");
  });

  it("uses the first existing time when local midnight is skipped", () => {
    inZone("America/Santiago");
    // 6 September 2026 00:00 does not exist; the day starts at 01:00 (UTC-3).
    expect(endOfLocalDay("2026-09-05").toISOString()).toBe("2026-09-06T04:00:00.000Z");
  });

  it("rejects anything that is not a calendar date", () => {
    expect(() => endOfLocalDay("25.10.2026")).toThrow(RangeError);
  });
});

describe("relativeTime", () => {
  it("calls the previous calendar day 'yesterday' even when it had 23 hours", () => {
    inZone("Europe/Berlin");
    const now = new Date("2026-03-29T10:00:00Z"); // Sunday 12:00 CEST
    const sat = new Date("2026-03-28T11:00:00Z"); // Saturday 12:00 CET, 23 hours earlier
    expect(relativeTime(sat, now)).toEqual({ value: -1, unit: "day" });
  });

  it("calls the previous calendar day 'yesterday' when it had 25 hours", () => {
    inZone("Europe/Berlin");
    const now = new Date("2026-10-25T11:00:00Z"); // Sunday 12:00 CET
    const sat = new Date("2026-10-24T10:00:00Z"); // Saturday 12:00 CEST, 25 hours earlier
    expect(relativeTime(sat, now)).toEqual({ value: -1, unit: "day" });
  });

  it("counts the repeated autumn hour as real elapsed time", () => {
    inZone("Europe/Berlin");
    const first = new Date("2026-10-25T00:30:00Z"); // 02:30 CEST
    const second = new Date("2026-10-25T01:30:00Z"); // 02:30 CET, same wall-clock time
    expect(relativeTime(first, second)).toEqual({ value: -1, unit: "hour" });
  });

  it("uses minutes and hours for recent times, even just after midnight", () => {
    inZone("Europe/Berlin");
    const now = new Date("2026-10-26T23:10:00Z"); // 00:10 CET
    expect(relativeTime(new Date("2026-10-26T22:50:00Z"), now)).toEqual({ value: -20, unit: "minute" });
    expect(relativeTime(new Date("2026-10-26T20:10:00Z"), now)).toEqual({ value: -3, unit: "hour" });
  });
});
