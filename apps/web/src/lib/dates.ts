/**
 * Calendar arithmetic in the browser's time zone. Days are added on the
 * calendar (year, month, day), never as multiples of 24 hours: a day with a
 * daylight-saving switch has 23 or 25 hours.
 */

const DAY_MS = 24 * 3600 * 1000;

/** "YYYY-MM-DD" of the local calendar day of `date` (the format of <input type="date">). */
export function localDateInput(date: Date): string {
  const y = String(date.getFullYear()).padStart(4, "0");
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

/** The same local wall-clock time `days` calendar days later (or earlier). */
export function addLocalDays(date: Date, days: number): Date {
  const next = new Date(date);
  next.setDate(next.getDate() + days);
  return next;
}

/** First instant of the local calendar day of `date`. */
export function startOfLocalDay(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

/**
 * The instant a chosen day ends in the local zone: the first moment of the
 * following day. "Accept until 25 October" means through the whole of that
 * day, however many hours it has. If midnight itself is skipped by a
 * daylight-saving switch, the browser resolves it to the first existing time.
 */
export function endOfLocalDay(day: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!match) throw new RangeError(`Not a calendar date: ${day}`);
  const [, y, m, d] = match.map(Number) as [number, number, number, number];
  return new Date(y, m - 1, d + 1);
}

/** The calendar day of an instant in an IANA zone as a UTC-midnight timestamp, for day arithmetic. */
function dayNumberIn(date: Date, zone: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    year: "numeric",
    month: "numeric",
    day: "numeric",
  }).formatToParts(date);
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value);
  return Date.UTC(get("year"), get("month") - 1, get("day"));
}

/** "YYYY-MM-DD" of the calendar day of `date` in an IANA zone (ADR 0005: the user's zone, not the server's). */
export function dayKeyIn(date: Date, zone: string): string {
  return new Date(dayNumberIn(date, zone)).toISOString().slice(0, 10);
}

/**
 * Whole calendar days from `from` to `to` (negative if `to` is earlier): in the browser's zone,
 * or in `zone` when one is given (the user's chosen display zone).
 */
export function calendarDaysBetween(from: Date, to: Date, zone?: string): number {
  // Rounding absorbs the 23- or 25-hour days around a switch.
  if (zone) return Math.round((dayNumberIn(to, zone) - dayNumberIn(from, zone)) / DAY_MS);
  return Math.round((startOfLocalDay(to).getTime() - startOfLocalDay(from).getTime()) / DAY_MS);
}

/**
 * Value and unit for a relative time ("3 hours ago", "yesterday"). Below 12
 * hours it counts hours and minutes; beyond that it counts calendar days, so
 * anything on the previous calendar day is "yesterday" even across a switch.
 */
export function relativeTime(
  value: Date,
  now: Date,
  zone?: string,
): { value: number; unit: Intl.RelativeTimeFormatUnit } {
  const seconds = Math.round((value.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 60) return { value: 0, unit: "second" };
  if (abs < 3600) return { value: Math.trunc(seconds / 60), unit: "minute" };
  const days = calendarDaysBetween(now, value, zone);
  if (abs < 12 * 3600 || days === 0) return { value: Math.trunc(seconds / 3600), unit: "hour" };
  if (Math.abs(days) < 7) return { value: days, unit: "day" };
  if (Math.abs(days) < 30) return { value: Math.trunc(days / 7), unit: "week" };
  if (Math.abs(days) < 365) return { value: Math.trunc(days / 30), unit: "month" };
  return { value: Math.trunc(days / 365), unit: "year" };
}
