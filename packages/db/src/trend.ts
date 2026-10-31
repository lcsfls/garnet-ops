import { sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import { activeRepository, visibleRepository } from "./visibility.ts";

/** True for IANA zone names the runtime knows, e.g. "Europe/Berlin" or "UTC". */
export function isTimeZone(value: string): boolean {
  if (value.length > 64) return false;
  try {
    new Intl.DateTimeFormat("en", { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

export interface TrendPoint {
  /** Calendar day in the requested time zone, "YYYY-MM-DD". */
  day: string;
  severity: string;
  n: number;
}

/**
 * Open findings per calendar day and severity for the last `days` days,
 * reconstructed from first-seen and resolved times.
 *
 * Days are calendar days in `timeZone` (the viewer's zone), computed by
 * PostgreSQL with `AT TIME ZONE`, so a 23-hour day in spring and a 25-hour day
 * in autumn are each exactly one day: never skipped, never counted twice.
 * Stored times are UTC instants (`timestamptz`) and are never shifted.
 */
export async function openFindingsTrend(
  db: Database,
  input: {
    organizationId: string;
    /** The person asking: their own private repositories count, other people's do not (ADR 0030). */
    userId: string;
    timeZone: string;
    days?: number;
    asOf?: Date;
    repositoryId?: string;
  },
): Promise<TrendPoint[]> {
  if (!isTimeZone(input.timeZone)) throw new RangeError(`Unknown time zone: ${input.timeZone}`);
  const span = Math.min(Math.max(input.days ?? 30, 1), 366) - 1;
  const asOf = input.asOf ?? new Date();
  const result = await db.execute<{ day: string; severity: string; n: number }>(sql`
    with bounds as (
      select (${asOf.toISOString()}::timestamptz at time zone ${input.timeZone})::date as today
    ),
    days as (
      select (b.today - g.offset_days) as day
      from bounds b, generate_series(0, ${span}) as g(offset_days)
    )
    select d.day::text as day, x.severity, count(x.id)::int as n
    from days d
    join finding x on x.organization_id = ${input.organizationId}
      and ${visibleRepository(sql`x.repository_id`, input)}
      ${input.repositoryId ? sql`and x.repository_id = ${input.repositoryId}` : sql`and ${activeRepository(sql`x.repository_id`)}`}
      and (x.first_seen_at at time zone ${input.timeZone})::date <= d.day
      and (x.resolved_at is null or (x.resolved_at at time zone ${input.timeZone})::date > d.day)
      and x.severity in ('critical', 'high', 'medium', 'low')
    group by d.day, x.severity
    order by d.day, x.severity`);
  return result.rows;
}

/**
 * Open findings per repository and calendar day, all severities from low up, for the
 * small trend line in the repository list. Same day rules as {@link openFindingsTrend}.
 * Every repository gets exactly `days` values, oldest first, with 0 for quiet days.
 */
export async function openTotalsByRepository(
  db: Database,
  input: { organizationId: string; timeZone: string; repositoryIds: string[]; days?: number; asOf?: Date },
): Promise<Map<string, number[]>> {
  if (!isTimeZone(input.timeZone)) throw new RangeError(`Unknown time zone: ${input.timeZone}`);
  const totals = new Map<string, number[]>();
  if (input.repositoryIds.length === 0) return totals;
  const days = Math.min(Math.max(input.days ?? 14, 1), 90);
  const asOf = input.asOf ?? new Date();
  const result = await db.execute<{ repository_id: string; day: string; n: number }>(sql`
    with bounds as (
      select (${asOf.toISOString()}::timestamptz at time zone ${input.timeZone})::date as today
    ),
    days as (
      select (b.today - g.offset_days) as day
      from bounds b, generate_series(0, ${days - 1}) as g(offset_days)
    ),
    repos as (
      select unnest(${sql.param(input.repositoryIds)}::text[]) as id
    )
    select r.id as repository_id, d.day::text as day, count(x.id)::int as n
    from repos r
    cross join days d
    left join finding x on x.repository_id = r.id
      and x.organization_id = ${input.organizationId}
      and (x.first_seen_at at time zone ${input.timeZone})::date <= d.day
      and (x.resolved_at is null or (x.resolved_at at time zone ${input.timeZone})::date > d.day)
      and x.severity in ('critical', 'high', 'medium', 'low')
    group by r.id, d.day
    order by r.id, d.day`);
  for (const row of result.rows) {
    const list = totals.get(row.repository_id) ?? [];
    list.push(row.n);
    totals.set(row.repository_id, list);
  }
  return totals;
}
