/**
 * Sizes and durations without any dependency on the page, so they can be tested on their own.
 * `format.ts` wraps them with the user's language.
 */

/** A size in bytes with binary units in `locale`, e.g. 3221225472 -> "3 GiB"; one decimal below 10. */
export function formatBytesIn(bytes: number, locale: string): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = value < 10 && unit > 0 ? 1 : 0;
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: digits }).format(value)} ${units[unit]}`;
}

/** A duration in seconds as its two largest units, e.g. 90061 -> "1 d 1 h"; less than a minute is "< 1 min". */
export function formatDuration(seconds: number): string {
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86_400);
  const h = Math.floor((s % 86_400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} min`;
  return m > 0 ? `${m} min` : "< 1 min";
}
