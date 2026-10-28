import { describe, expect, it } from "vitest";
import { todayIn, trendDays } from "./trend.ts";

describe("trendDays", () => {
  it("fills the missing days with zero and ends today in the trend's zone", () => {
    // 23:30 UTC on 25 October is already 26 October in Berlin.
    const now = new Date("2026-10-25T23:30:00Z");
    expect(todayIn("Europe/Berlin", now)).toBe("2026-10-26");
    const days = trendDays(
      {
        timeZone: "Europe/Berlin",
        days: [
          { day: "2026-10-24", severity: "critical", n: 2 },
          { day: "2026-10-26", severity: "low", n: 1 },
          { day: "2026-10-26", severity: "negligible", n: 9 },
        ],
      },
      3,
      now,
    );
    expect(days).toEqual([
      { day: "2026-10-24", critical: 2, high: 0, medium: 0, low: 0 },
      { day: "2026-10-25", critical: 0, high: 0, medium: 0, low: 0 },
      { day: "2026-10-26", critical: 0, high: 0, medium: 0, low: 1 },
    ]);
  });

  it("counts calendar days across the spring switch", () => {
    const days = trendDays({ timeZone: "Europe/Berlin", days: [] }, 3, new Date("2026-03-30T10:00:00Z"));
    expect(days.map((d) => d.day)).toEqual(["2026-03-28", "2026-03-29", "2026-03-30"]);
  });
});
