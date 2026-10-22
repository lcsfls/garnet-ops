import { newId } from "@garnetops/core";
import { and, eq, inArray, notExists, sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import * as schema from "./schema.ts";

export interface StartedRun {
  organizationId: string;
  /** Intended local date of the run in the organisation's zone, "YYYY-MM-DD". */
  localDate: string;
  scans: { scanId: string; repositoryId: string }[];
  /** Server inventories queued by the same run (ADR 0011). */
  hostRuns: { runId: string; hostId: string }[];
}

/**
 * Starts every nightly run that is due (ADR 0005). Called by a frequent tick.
 *
 * A run is due when, in the organisation's IANA zone and by the database clock,
 * the local time has reached the scheduled time and no run exists yet for that
 * local date. The (organisation, local date) key makes this idempotent:
 * - autumn: the repeated hour cannot start a second run on the same date;
 * - spring: a time inside the skipped hour is caught up by the next tick;
 * - several workers ticking at once start each run exactly once.
 * Organisations with a zone PostgreSQL does not know are skipped, not fatal.
 *
 * Queues a scan for each repository without a queued or running scan, and an
 * inventory for each server with a confirmed host key and no queued or running
 * one, in the same transaction. The caller sends the jobs after this returns.
 */
export async function startDueNightlyRuns(db: Database, asOf?: Date): Promise<StartedRun[]> {
  const at = asOf ? sql`${asOf.toISOString()}::timestamptz` : sql`now()`;
  return db.transaction(async (tx) => {
    const due = await tx.execute<{ organization_id: string; local_date: string }>(sql`
      insert into scan_schedule_run (organization_id, local_date, queued_scans)
      select o.id, l.local_time::date, 0
      from organization o,
        -- CASE fixes the evaluation order: AT TIME ZONE never sees an unknown zone,
        -- which would otherwise abort the statement for every organisation.
        lateral (
          select case
            when exists (select 1 from pg_timezone_names z where z.name = o.scan_time_zone)
            then ${at} at time zone o.scan_time_zone
          end as local_time
        ) l
      where o.scan_schedule_enabled
        and l.local_time is not null
        and l.local_time::time >= o.scan_local_time
      on conflict do nothing
      returning organization_id, local_date`);

    const runs: StartedRun[] = [];
    for (const row of due.rows) {
      const repos = await tx
        .select({ id: schema.repository.id })
        .from(schema.repository)
        .where(
          and(
            eq(schema.repository.organizationId, row.organization_id),
            notExists(
              tx
                .select({ one: sql`1` })
                .from(schema.scan)
                .where(
                  and(
                    eq(schema.scan.repositoryId, schema.repository.id),
                    inArray(schema.scan.state, ["queued", "running"]),
                  ),
                ),
            ),
          ),
        );
      // Millisecond precision on purpose: scan.created_at is a pagination key.
      const createdAt = new Date();
      const scans = repos.map((r) => ({ scanId: newId("scan"), repositoryId: r.id }));
      if (scans.length) {
        await tx.insert(schema.scan).values(
          scans.map((s) => ({
            id: s.scanId,
            organizationId: row.organization_id,
            repositoryId: s.repositoryId,
            state: "queued" as const,
            trigger: "schedule" as const,
            createdAt,
          })),
        );
      }
      await tx
        .update(schema.scanScheduleRun)
        .set({ queuedScans: scans.length })
        .where(
          and(
            eq(schema.scanScheduleRun.organizationId, row.organization_id),
            eq(schema.scanScheduleRun.localDate, row.local_date),
          ),
        );

      const hosts = await tx
        .select({ id: schema.host.id })
        .from(schema.host)
        .where(
          and(
            eq(schema.host.organizationId, row.organization_id),
            eq(schema.host.hostKeyStatus, "confirmed"),
            notExists(
              tx
                .select({ one: sql`1` })
                .from(schema.hostInventoryRun)
                .where(
                  and(
                    eq(schema.hostInventoryRun.hostId, schema.host.id),
                    inArray(schema.hostInventoryRun.state, ["queued", "running"]),
                  ),
                ),
            ),
          ),
        );
      const hostRuns = hosts.map((h) => ({ runId: newId("hrun"), hostId: h.id }));
      if (hostRuns.length) {
        await tx.insert(schema.hostInventoryRun).values(
          hostRuns.map((r) => ({
            id: r.runId,
            organizationId: row.organization_id,
            hostId: r.hostId,
            state: "queued" as const,
            trigger: "schedule" as const,
            createdAt,
          })),
        );
      }
      runs.push({ organizationId: row.organization_id, localDate: row.local_date, scans, hostRuns });
    }
    return runs;
  });
}

/**
 * Scans still queued after `olderThan` whose job may have been lost (for
 * example a crash between the transaction above and sending the job). Sending
 * their job again is safe: a worker only ever claims a scan that is queued.
 */
export async function strandedQueuedScans(
  db: Database,
  olderThan = "10 minutes",
): Promise<{ scanId: string; repositoryId: string }[]> {
  return db
    .select({ scanId: schema.scan.id, repositoryId: schema.scan.repositoryId })
    .from(schema.scan)
    .where(
      and(eq(schema.scan.state, "queued"), sql`${schema.scan.createdAt} < now() - ${olderThan}::interval`),
    );
}

/** The same for server inventories: queued for a while, so their job may have been lost. */
export async function strandedQueuedHostRuns(
  db: Database,
  olderThan = "10 minutes",
): Promise<{ runId: string; hostId: string }[]> {
  return db
    .select({ runId: schema.hostInventoryRun.id, hostId: schema.hostInventoryRun.hostId })
    .from(schema.hostInventoryRun)
    .where(
      and(
        eq(schema.hostInventoryRun.state, "queued"),
        sql`${schema.hostInventoryRun.createdAt} < now() - ${olderThan}::interval`,
      ),
    );
}
