import { afterEach, describe, expect, it } from "vitest";
import {
  browserTimeZone,
  displayTimeZone,
  formatInstant,
  formatShortDate,
  isKnownZone,
  setPreferredTimeZone,
  timeZoneChoices,
} from "./time-zone.svelte.ts";

afterEach(() => setPreferredTimeZone(null));

describe("display time zone", () => {
  it("follows the browser until the user chooses one", () => {
    expect(displayTimeZone()).toBe(browserTimeZone());
    setPreferredTimeZone("Asia/Tokyo");
    expect(displayTimeZone()).toBe("Asia/Tokyo");
    setPreferredTimeZone(null);
    expect(displayTimeZone()).toBe(browserTimeZone());
  });

  it("ignores a name the browser does not know", () => {
    setPreferredTimeZone("Mars/Olympus");
    expect(displayTimeZone()).toBe(browserTimeZone());
  });

  it("offers UTC first, once, and always the zone that is set", () => {
    const zones = timeZoneChoices("Europe/Berlin");
    expect(zones[0]).toBe("UTC");
    expect(zones.filter((z) => z === "UTC")).toHaveLength(1);
    expect(zones).toContain("Europe/Berlin");
    expect(isKnownZone("Europe/Berlin")).toBe(true);
  });
});

describe("formatInstant around daylight saving (ADR 0005)", () => {
  // Europe/Berlin falls back on 2026-10-25 at 01:00 UTC: 02:30 happens twice, an hour apart.
  it("shows the repeated autumn hour with the same wall clock for two different instants", () => {
    const first = formatInstant("2026-10-25T00:30:00Z", "en-US", "Europe/Berlin");
    const second = formatInstant("2026-10-25T01:30:00Z", "en-US", "Europe/Berlin");
    expect(first).toContain("2:30");
    expect(second).toContain("2:30");
    expect(first).toBe(second);
    expect(formatInstant("2026-10-25T02:30:00Z", "en-US", "Europe/Berlin")).toContain("3:30");
  });

  // It springs forward on 2026-03-29 at 01:00 UTC: 02:xx does not exist.
  it("skips the missing spring hour", () => {
    expect(formatInstant("2026-03-29T00:30:00Z", "en-US", "Europe/Berlin")).toContain("1:30");
    expect(formatInstant("2026-03-29T01:30:00Z", "en-US", "Europe/Berlin")).toContain("3:30");
  });

  it("does not depend on the zone of the machine", () => {
    expect(formatInstant("2026-01-15T23:30:00Z", "en-US", "Asia/Tokyo")).toContain("Jan 16, 2026");
    expect(formatInstant("2026-01-15T23:30:00Z", "en-US", "UTC")).toContain("Jan 15, 2026");
    expect(formatInstant("2026-01-15T23:30:00Z", "en-US", "America/Los_Angeles")).toContain("3:30");
  });

  it("formats only the date when asked, in the language given", () => {
    expect(formatInstant("2026-01-15T23:30:00Z", "de-DE", "Europe/Berlin", "date")).toBe("16.01.2026");
  });
});

describe("short dates in a list row", () => {
  const now = new Date("2026-11-05T12:00:00Z");

  it("leaves out the year of the current year and names it for earlier ones", () => {
    expect(formatShortDate("2026-10-20T08:00:00Z", "en", "Europe/Berlin", now)).toBe("Oct 20");
    expect(formatShortDate("2025-10-20T08:00:00Z", "en", "Europe/Berlin", now)).toBe("Oct 20, 2025");
    expect(formatShortDate("2026-10-20T08:00:00Z", "de", "Europe/Berlin", now)).toBe("20. Okt.");
  });

  it("takes the day of the display zone, not of UTC", () => {
    // 23:30 UTC on 25 October is already the 26th in Berlin (after the switch back to CET) and still the 25th in New York.
    expect(formatShortDate("2026-10-25T23:30:00Z", "en", "Europe/Berlin", now)).toBe("Oct 26");
    expect(formatShortDate("2026-10-25T23:30:00Z", "en", "America/New_York", now)).toBe("Oct 25");
  });

  it("decides the year in the zone as well: New Year's Eve in UTC is New Year's Day in Tokyo", () => {
    const newYear = new Date("2027-01-01T03:00:00Z");
    expect(formatShortDate("2026-12-31T20:00:00Z", "en", "Asia/Tokyo", newYear)).toBe("Jan 1");
    expect(formatShortDate("2026-12-31T20:00:00Z", "en", "UTC", newYear)).toBe("Dec 31, 2026");
  });
});
