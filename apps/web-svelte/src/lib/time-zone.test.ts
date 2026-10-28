import { afterEach, describe, expect, it } from "vitest";
import {
  browserTimeZone,
  displayTimeZone,
  formatInstant,
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
