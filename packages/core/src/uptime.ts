/**
 * Availability of websites (ADR 0040): when a site counts as down or up again, and what the history adds up to. Pure logic shared by
 * the API, the worker and the web app.
 */

/** How often an asset may be checked, in minutes. */
export const UPTIME_INTERVALS = [1, 5, 15, 60] as const;
export type UptimeInterval = (typeof UPTIME_INTERVALS)[number];
/** Failures in a row before an asset counts as down: one lost packet is not an outage. */
export const UPTIME_DOWN_AFTER = 3;
/** Checks are kept this long. */
export const UPTIME_RETENTION_DAYS = 30;
/** One check waits this long for the answer's headers. */
export const UPTIME_TIMEOUT_MS = 10_000;
/** An answer slower than this is reported as slow (a hosting problem), though the site is up. */
export const UPTIME_SLOW_MS = 3_000;

export const UPTIME_ERRORS = ["timeout", "refused", "tls", "protocol", "dns", "address", "status"] as const;
export type UptimeError = (typeof UPTIME_ERRORS)[number];

export interface UptimeCheck {
  checkedAt: string;
  up: boolean;
  status: number | null;
  responseMs: number | null;
  error: UptimeError | null;
}

/** An answer below 500 is up (a redirect or a 404 is the server answering); a 5xx is a hosting problem. */
export const answeredUp = (status: number) => status < 500;

/**
 * The state after one more check. A new asset is up or down at once; after that it turns down only after
 * {@link UPTIME_DOWN_AFTER} failures in a row, and up again with the first success. `changed` says what to tell people.
 */
export function nextUptimeState(
  previous: { state: "up" | "down" | null; failures: number },
  up: boolean,
): { state: "up" | "down"; failures: number; changed: "down" | "up" | null } {
  if (up) {
    return { state: "up", failures: 0, changed: previous.state === "down" ? "up" : null };
  }
  const failures = previous.failures + 1;
  if (previous.state === "down") return { state: "down", failures, changed: null };
  if (failures >= UPTIME_DOWN_AFTER) return { state: "down", failures, changed: "down" };
  return { state: previous.state ?? "up", failures, changed: null };
}

export interface UptimeStats {
  /** Share of successful checks, 0 to 100 with one decimal; null without checks. */
  percent: number | null;
  /** Average time to the answer of the successful checks, in milliseconds. */
  averageMs: number | null;
  checks: number;
}

export function uptimeStats(checks: readonly UptimeCheck[], since: Date): UptimeStats {
  const inRange = checks.filter((c) => Date.parse(c.checkedAt) >= since.getTime());
  if (inRange.length === 0) return { percent: null, averageMs: null, checks: 0 };
  const ok = inRange.filter((c) => c.up);
  const times = ok.map((c) => c.responseMs).filter((ms): ms is number => ms !== null);
  return {
    percent: Math.round((ok.length / inRange.length) * 1000) / 10,
    averageMs: times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : null,
    checks: inRange.length,
  };
}

export interface UptimeIncident {
  from: string;
  /** null while it lasts. */
  to: string | null;
  /** The reason of the first failure. */
  error: UptimeError | null;
  status: number | null;
}

/**
 * Down periods from a history (oldest first): at least {@link UPTIME_DOWN_AFTER} failures in a row, from the first failure to the
 * first success after them.
 */
export function uptimeIncidents(checks: readonly UptimeCheck[]): UptimeIncident[] {
  const out: UptimeIncident[] = [];
  let run: UptimeCheck[] = [];
  const close = (to: string | null) => {
    if (run.length >= UPTIME_DOWN_AFTER) {
      const first = run[0] as UptimeCheck;
      out.push({ from: first.checkedAt, to, error: first.error, status: first.status });
    }
    run = [];
  };
  for (const check of checks) {
    if (check.up) close(check.checkedAt);
    else run.push(check);
  }
  close(null);
  return out;
}

export interface UptimeHour {
  /** Start of the hour. */
  from: string;
  checks: number;
  failures: number;
  /** The reason of the last failure in the hour. */
  error: UptimeError | null;
  status: number | null;
  averageMs: number | null;
}

/** The last 24 hours before `now` as hourly buckets, oldest first: a short strip that stays readable at any check interval. */
export function uptimeHours(checks: readonly UptimeCheck[], now: Date): UptimeHour[] {
  const end = now.getTime();
  const start = end - 24 * 3600_000;
  const hours = Array.from({ length: 24 }, (_, i) => ({
    from: new Date(start + i * 3600_000).toISOString(),
    checks: 0,
    failures: 0,
    error: null as UptimeError | null,
    status: null as number | null,
    times: [] as number[],
  }));
  for (const c of checks) {
    const at = Date.parse(c.checkedAt);
    if (at < start || at >= end) continue;
    const h = hours[Math.floor((at - start) / 3600_000)];
    if (!h) continue;
    h.checks++;
    if (c.up) {
      if (c.responseMs !== null) h.times.push(c.responseMs);
    } else {
      h.failures++;
      h.error = c.error;
      h.status = c.status;
    }
  }
  return hours.map(({ times, ...h }) => ({
    ...h,
    averageMs: times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : null,
  }));
}
