/**
 * Reads for the System status page (ADR 0024): the next nightly run, the database's size and
 * migration state. Read-only; nothing here changes data.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sql } from "drizzle-orm";
import type { Database } from "./index.ts";

export interface NextNightlyRun {
  /** The organisation's schedule switch. */
  enabled: boolean;
  /** Local wall-clock time "HH:MM:SS" and the IANA zone it is read in. */
  localTime: string;
  timeZone: string;
  /**
   * The instant of the next run, or null if the schedule is off or the zone is unknown to the
   * database. An instant in the past means the run is due and the next tick (within five
   * minutes) starts it.
   */
  at: Date | null;
}

/**
 * When the nightly run of an organisation happens next (ADR 0005): today at the scheduled local
 * time if no run exists for today's local date yet, tomorrow at that time otherwise. Computed by
 * the database in the organisation's zone, like the run itself, so the answer follows daylight
 * saving time. On the two days a year when the local time is skipped (spring) or read twice
 * (autumn) the answer can be an hour off the real run, which follows ADR 0005 and starts at the
 * first tick that reaches the time.
 */
export async function nextNightlyRun(
  db: Database,
  organizationId: string,
  asOf?: Date,
): Promise<NextNightlyRun | null> {
  const at = asOf ? sql`${asOf.toISOString()}::timestamptz` : sql`now()`;
  const result = await db.execute<{
    enabled: boolean;
    local_time: string;
    time_zone: string;
    next_at: Date | null;
  }>(sql`
    select o.scan_schedule_enabled as enabled,
           o.scan_local_time::text as local_time,
           o.scan_time_zone as time_zone,
           case when l.local_now is null then null else
             ((l.local_now::date
               + (case when exists (
                    select 1 from scan_schedule_run r
                    where r.organization_id = o.id and r.local_date = l.local_now::date)
                  then 1 else 0 end))
              + o.scan_local_time) at time zone o.scan_time_zone
           end as next_at
    from organization o,
      lateral (
        select case
          when exists (select 1 from pg_timezone_names z where z.name = o.scan_time_zone)
          then ${at} at time zone o.scan_time_zone
        end as local_now
      ) l
    where o.id = ${organizationId}`);
  const row = result.rows[0];
  if (!row) return null;
  return {
    enabled: row.enabled,
    localTime: row.local_time,
    timeZone: row.time_zone,
    at: row.enabled && row.next_at ? new Date(row.next_at) : null,
  };
}

export interface DatabaseState {
  sizeBytes: number | null;
  /** Migrations applied, migrations this build ships, and the name of the newest applied one. */
  migrations: { applied: number; expected: number; latest: string | null };
}

const journalFile = fileURLToPath(new URL("../drizzle/meta/_journal.json", import.meta.url));

/** The migration journal this build ships: tag and creation time of each migration. */
function shippedMigrations(): { tag: string; when: number }[] {
  try {
    const journal = JSON.parse(readFileSync(journalFile, "utf8")) as {
      entries?: { tag: string; when: number }[];
    };
    return journal.entries ?? [];
  } catch {
    return [];
  }
}

/** Size of the database and how many migrations are applied. A failed read gives null / 0, never an error. */
export async function databaseState(db: Database): Promise<DatabaseState> {
  const shipped = shippedMigrations();
  const size = await db
    .execute<{ size: string }>(sql`select pg_database_size(current_database())::text as size`)
    .then((r) => (r.rows[0] ? Number(r.rows[0].size) : null))
    .catch(() => null);
  const applied = await db
    .execute<{ n: string; newest: string | null }>(
      sql`select count(*)::text as n, max(created_at)::text as newest from drizzle.__drizzle_migrations`,
    )
    .then((r) => r.rows[0] ?? null)
    .catch(() => null);
  const newest = applied?.newest ? Number(applied.newest) : null;
  return {
    sizeBytes: size,
    migrations: {
      applied: applied ? Number(applied.n) : 0,
      expected: shipped.length,
      latest: newest === null ? null : (shipped.find((m) => m.when === newest)?.tag ?? null),
    },
  };
}
