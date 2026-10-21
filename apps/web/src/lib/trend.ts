import type { Overview, Severity } from "./types.ts";

export const TREND_SEVERITIES = ["critical", "high", "medium", "low"] as const satisfies readonly Severity[];
export type TrendSeverity = (typeof TREND_SEVERITIES)[number];
export type TrendDay = { day: string } & Record<TrendSeverity, number>;

/** Today's calendar date "YYYY-MM-DD" in an IANA zone. */
export function todayIn(timeZone: string, now = new Date()): string {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(now);
}

/** Calendar date arithmetic on "YYYY-MM-DD", independent of any zone. */
function addDays(day: string, delta: number): string {
  const date = new Date(`${day}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + delta);
  return date.toISOString().slice(0, 10);
}

/**
 * One entry per calendar day, oldest first, ending today in the trend's zone.
 * The API leaves out days without open findings; they count as zero here.
 */
export function trendDays(trend: Overview["trend"], days = 30, now = new Date()): TrendDay[] {
  const last = todayIn(trend.timeZone, now);
  const byDay = new Map<string, TrendDay>();
  for (let i = days - 1; i >= 0; i--) {
    const day = addDays(last, -i);
    byDay.set(day, { day, critical: 0, high: 0, medium: 0, low: 0 });
  }
  for (const point of trend.days) {
    const entry = byDay.get(point.day);
    if (entry && (TREND_SEVERITIES as readonly string[]).includes(point.severity)) {
      entry[point.severity as TrendSeverity] += point.n;
    }
  }
  return [...byDay.values()];
}
