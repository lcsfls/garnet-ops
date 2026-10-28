/**
 * The time zone times are shown in (ADR 0005, ADR 0017). Instants are UTC everywhere; only
 * their display depends on a zone: the one the user chose on the account page, or else the
 * browser's. Calendar-day arithmetic (dates.ts) and the day figures of charts and exports
 * still follow the browser's zone.
 */

/** Reactive, so dates on screen follow a change made on the account page. */
let preferred = $state<string | null>(null);

/** Sets the zone from the user's account (null: follow the browser). Unknown names are ignored. */
export function setPreferredTimeZone(zone: string | null | undefined): void {
  preferred = zone && isKnownZone(zone) ? zone : null;
}

/** The browser's own zone, e.g. "Europe/Berlin". */
export function browserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/** The zone times are shown in: the user's choice, else the browser's. */
export function displayTimeZone(): string {
  return preferred ?? browserTimeZone();
}

export function isKnownZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat("en", { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

/** `value` as a date and time in `locale` and `zone`, e.g. "Oct 25, 2026, 2:30 AM". */
export function formatInstant(
  value: string | Date,
  locale: string,
  zone: string,
  style: "dateTime" | "date" = "dateTime",
): string {
  const options: Intl.DateTimeFormatOptions =
    style === "date"
      ? { dateStyle: "medium", timeZone: zone }
      : { dateStyle: "medium", timeStyle: "short", timeZone: zone };
  return new Intl.DateTimeFormat(locale, options).format(new Date(value));
}

/** IANA zones the browser knows, UTC first and `include` always present. */
export function timeZoneChoices(include?: string | null): string[] {
  const zones = new Set<string>(Intl.supportedValuesOf("timeZone"));
  if (include && isKnownZone(include)) zones.add(include);
  zones.delete("UTC");
  return ["UTC", ...[...zones].sort()];
}
