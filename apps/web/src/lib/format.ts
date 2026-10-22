import { relativeTime } from "./dates.ts";
import { i18n } from "./i18n.ts";
import { displayTimeZone, formatInstant } from "./time-zone.ts";
import { formatBytesIn } from "./units.ts";

/** Absolute date and time in the UI language and the user's display time zone (account page, else the browser's). */
export function formatDateTime(value: string | Date): string {
  return formatInstant(value, i18n.language, displayTimeZone());
}

export function formatDate(value: string | Date): string {
  return formatInstant(value, i18n.language, displayTimeZone(), "date");
}

/** "3 hours ago", "yesterday", "just now", counting calendar days in the user's display zone (ADR 0005). */
export function formatRelative(value: string | Date, now: Date = new Date()): string {
  const { value: amount, unit } = relativeTime(new Date(value), now, displayTimeZone());
  return new Intl.RelativeTimeFormat(i18n.language, { numeric: "auto" }).format(amount, unit);
}

/**
 * A wall-clock time such as "04:00:00" in the UI language ("4:00 AM", "04:00").
 * It is formatted as a time of day, not converted: the zone is shown next to it.
 */
export function formatWallClock(time: string): string {
  return new Intl.DateTimeFormat(i18n.language, {
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
  }).format(new Date(`1970-01-01T${time}Z`));
}

/** A calendar date "YYYY-MM-DD" as such, never shifted by the browser's zone. */
export function formatCalendarDate(day: string): string {
  return new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeZone: "UTC" }).format(
    new Date(`${day}T00:00:00Z`),
  );
}

/** A share from 0 to 1 as a percentage, e.g. 0.2133 -> "21.3%"; tiny values keep one significant digit. */
export function formatPercent(share: number): string {
  const pct = share * 100;
  return new Intl.NumberFormat(i18n.language, {
    style: "percent",
    maximumFractionDigits: pct < 0.1 ? 2 : 1,
  }).format(share);
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat(i18n.language).format(value);
}

/** A size in bytes with binary units, e.g. 3221225472 -> "3 GiB"; one decimal below 10. */
export const formatBytes = (bytes: number): string => formatBytesIn(bytes, i18n.language);

export { formatDuration } from "./units.ts";
