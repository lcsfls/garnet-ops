import { type SQL, sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import { isTimeZone } from "./trend.ts";

/** The time ranges the statistics page offers, in calendar days. */
export const STATISTICS_RANGES = [30, 90, 365] as const;
export type StatisticsRange = (typeof STATISTICS_RANGES)[number];

/** The severities the statistics count; "negligible" and "unknown" findings are left out, as in the trend. */
const SEVERITIES = sql`('critical', 'high', 'medium', 'low')`;

export interface StatisticsBucket {
  /** First calendar day of the bucket inside the range, "YYYY-MM-DD". */
  start: string;
  /** Last calendar day of the bucket inside the range (the day the open count is taken). */
  end: string;
  /** Open findings at the end of `end`, by severity. */
  open: Record<string, number>;
  /** Findings first seen in the bucket, by severity. */
  opened: Record<string, number>;
  /** Findings resolved in the bucket, by severity. */
  resolved: Record<string, number>;
  /** Gate results in the bucket. */
  gates: { passed: number; notes: number; blocked: number };
}

export interface TimeToFix {
  severity: string;
  /** Findings resolved in the range. */
  resolved: number;
  /** Median days from first seen to resolved; null without resolved findings. */
  medianDays: number | null;
}

export interface Statistics {
  range: { days: number; from: string; to: string; timeZone: string; granularity: "day" | "week" };
  buckets: StatisticsBucket[];
  totals: {
    opened: number;
    resolved: number;
    /** The same counts for the range of the same length right before. */
    previous: { opened: number; resolved: number };
    gates: { passed: number; notes: number; blocked: number };
    scans: { succeeded: number; failed: number };
    fixPrs: { opened: number; merged: number };
  };
  timeToFix: TimeToFix[];
}

/**
 * Activity of one organisation over the last `days` calendar days (`STATISTICS_RANGES`):
 * open findings over time, what was found and resolved, gate results, scans and fix
 * pull requests, and how long fixes took.
 *
 * Calendar days are the viewer's (`timeZone`), cut by PostgreSQL with `AT TIME ZONE` as in
 * {@link openFindingsTrend}, so a 23- or 25-hour day at a DST change is exactly one day.
 * Up to 31 days the buckets are days, above that ISO weeks (Monday first); the first and
 * last week are cut to the range, and every bucket names the days it covers.
 */
export async function organizationStatistics(
  db: Database,
  input: { organizationId: string; timeZone: string; days: number; asOf?: Date },
): Promise<Statistics> {
  if (!isTimeZone(input.timeZone)) throw new RangeError(`Unknown time zone: ${input.timeZone}`);
  const days = Math.min(Math.max(Math.trunc(input.days), 1), 366);
  const granularity = days <= 31 ? "day" : "week";
  const asOf = input.asOf ?? new Date();
  const tz = input.timeZone;
  const org = input.organizationId;
  const local = (column: SQL) => sql`(${column} at time zone ${tz})::date`;

  const bounds = sql`
    bounds as (
      select today - ${days - 1}::int as first_day, today
      from (select (${asOf.toISOString()}::timestamptz at time zone ${tz})::date as today) t
    ),
    buckets as (
      select greatest(g::date, b.first_day) as start,
             least(g::date + ${granularity === "day" ? 0 : 6}::int, b.today) as finish
      from bounds b,
           generate_series(
             ${granularity === "day" ? sql`b.first_day` : sql`date_trunc('week', b.first_day)::date`},
             b.today,
             ${granularity === "day" ? sql`interval '1 day'` : sql`interval '7 days'`}
           ) as g
    )`;

  const [range, open, opened, resolved, gates, totals, timeToFix] = await Promise.all([
    db.execute<{ first_day: string; today: string; start: string; finish: string }>(sql`
      with ${bounds}
      select b.first_day::text, b.today::text, k.start::text, k.finish::text
      from bounds b, buckets k order by k.start`),
    db.execute<{ start: string; severity: string; n: number }>(sql`
      with ${bounds}
      select k.start::text, x.severity, count(x.id)::int as n
      from buckets k
      join finding x on x.organization_id = ${org}
        and x.severity in ${SEVERITIES}
        and ${local(sql`x.first_seen_at`)} <= k.finish
        and (x.resolved_at is null or ${local(sql`x.resolved_at`)} > k.finish)
      group by k.start, x.severity`),
    db.execute<{ start: string; severity: string; n: number }>(sql`
      with ${bounds}
      select k.start::text, x.severity, count(x.id)::int as n
      from buckets k
      join finding x on x.organization_id = ${org}
        and x.severity in ${SEVERITIES}
        and ${local(sql`x.first_seen_at`)} between k.start and k.finish
      group by k.start, x.severity`),
    db.execute<{ start: string; severity: string; n: number }>(sql`
      with ${bounds}
      select k.start::text, x.severity, count(x.id)::int as n
      from buckets k
      join finding x on x.organization_id = ${org}
        and x.severity in ${SEVERITIES}
        and x.resolved_at is not null
        and ${local(sql`x.resolved_at`)} between k.start and k.finish
      group by k.start, x.severity`),
    db.execute<{ start: string; result: string; n: number }>(sql`
      with ${bounds}
      select k.start::text, g.result, count(g.id)::int as n
      from buckets k
      join gate_run g on g.organization_id = ${org}
        and ${local(sql`g.created_at`)} between k.start and k.finish
      group by k.start, g.result`),
    db.execute<{
      previous_opened: number;
      previous_resolved: number;
      scans_succeeded: number;
      scans_failed: number;
      prs_opened: number;
      prs_merged: number;
    }>(sql`
      with ${bounds}
      select
        (select count(*) from finding x, bounds b
          where x.organization_id = ${org} and x.severity in ${SEVERITIES}
            and ${local(sql`x.first_seen_at`)} between b.first_day - ${days}::int and b.first_day - 1)::int
          as previous_opened,
        (select count(*) from finding x, bounds b
          where x.organization_id = ${org} and x.severity in ${SEVERITIES} and x.resolved_at is not null
            and ${local(sql`x.resolved_at`)} between b.first_day - ${days}::int and b.first_day - 1)::int
          as previous_resolved,
        (select count(*) from scan s, bounds b
          where s.organization_id = ${org} and s.state = 'succeeded'
            and ${local(sql`coalesce(s.finished_at, s.created_at)`)} between b.first_day and b.today)::int
          as scans_succeeded,
        (select count(*) from scan s, bounds b
          where s.organization_id = ${org} and s.state = 'failed'
            and ${local(sql`coalesce(s.finished_at, s.created_at)`)} between b.first_day and b.today)::int
          as scans_failed,
        (select count(*) from fix_pr p, bounds b
          where p.organization_id = ${org} and p.opened_at is not null
            and ${local(sql`p.opened_at`)} between b.first_day and b.today)::int
          as prs_opened,
        (select count(*) from fix_pr p, bounds b
          where p.organization_id = ${org} and p.state = 'merged' and p.closed_at is not null
            and ${local(sql`p.closed_at`)} between b.first_day and b.today)::int
          as prs_merged`),
    db.execute<{ severity: string; resolved: number; median_days: number | null }>(sql`
      with ${bounds}
      select x.severity, count(*)::int as resolved,
        (percentile_cont(0.5) within group (
          order by extract(epoch from x.resolved_at - x.first_seen_at)) / 86400)::float8 as median_days
      from finding x, bounds b
      where x.organization_id = ${org} and x.severity in ${SEVERITIES} and x.resolved_at is not null
        and ${local(sql`x.resolved_at`)} between b.first_day and b.today
      group by x.severity`),
  ]);

  const byStart = <T extends { start: string; n: number }>(rows: T[], key: (row: T) => string) => {
    const map = new Map<string, Record<string, number>>();
    for (const row of rows) {
      const entry = map.get(row.start) ?? {};
      entry[key(row)] = row.n;
      map.set(row.start, entry);
    }
    return map;
  };
  const openBy = byStart(open.rows, (r) => r.severity);
  const openedBy = byStart(opened.rows, (r) => r.severity);
  const resolvedBy = byStart(resolved.rows, (r) => r.severity);
  const gatesBy = byStart(gates.rows, (r) => r.result);

  const buckets: StatisticsBucket[] = range.rows.map((row) => {
    const g = gatesBy.get(row.start) ?? {};
    return {
      start: row.start,
      end: row.finish,
      open: openBy.get(row.start) ?? {},
      opened: openedBy.get(row.start) ?? {},
      resolved: resolvedBy.get(row.start) ?? {},
      gates: { passed: g.passed ?? 0, notes: g.notes ?? 0, blocked: g.blocked ?? 0 },
    };
  });
  const sum = (pick: (b: StatisticsBucket) => Record<string, number>) =>
    buckets.reduce((total, b) => total + Object.values(pick(b)).reduce((s, n) => s + n, 0), 0);
  const t = totals.rows[0];
  const first = range.rows[0];

  return {
    range: {
      days,
      from: first?.first_day ?? "",
      to: first?.today ?? "",
      timeZone: tz,
      granularity,
    },
    buckets,
    totals: {
      opened: sum((b) => b.opened),
      resolved: sum((b) => b.resolved),
      previous: { opened: t?.previous_opened ?? 0, resolved: t?.previous_resolved ?? 0 },
      gates: {
        passed: buckets.reduce((s, b) => s + b.gates.passed, 0),
        notes: buckets.reduce((s, b) => s + b.gates.notes, 0),
        blocked: buckets.reduce((s, b) => s + b.gates.blocked, 0),
      },
      scans: { succeeded: t?.scans_succeeded ?? 0, failed: t?.scans_failed ?? 0 },
      fixPrs: { opened: t?.prs_opened ?? 0, merged: t?.prs_merged ?? 0 },
    },
    timeToFix: ["critical", "high", "medium", "low"].map((severity) => {
      const row = timeToFix.rows.find((r) => r.severity === severity);
      return {
        severity,
        resolved: row?.resolved ?? 0,
        medianDays: row?.median_days ?? null,
      };
    }),
  };
}
