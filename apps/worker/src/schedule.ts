import { startDueNightlyRuns, strandedQueuedScans } from "@garnetops/db";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";

export const SCAN_QUEUE = "scan.repository";
export const TICK_QUEUE = "scan.schedule-tick";

/** Same job options as scans queued by the API (apps/api/src/routes/repositories.ts). */
const SCAN_JOB = { retryLimit: 1, expireInSeconds: 1800 };

/**
 * One tick of the nightly schedule (ADR 0005). Runs every few minutes in UTC;
 * which organisation is due is decided in the database, in each
 * organisation's own zone, so the tick itself has no clock logic.
 */
export async function scheduleTick(boss: PgBoss): Promise<void> {
  const runs = await startDueNightlyRuns(db);
  for (const run of runs) {
    for (const scan of run.scans) {
      await boss.send(SCAN_QUEUE, { scanId: scan.scanId }, { ...SCAN_JOB, singletonKey: scan.repositoryId });
    }
    console.log(`schedule: ${run.organizationId} ${run.localDate}: ${run.scans.length} scans queued`);
  }
  // Re-send jobs that may have been lost between queueing and sending; a worker
  // only claims a scan that is still queued, so a duplicate job does nothing.
  for (const scan of await strandedQueuedScans(db)) {
    await boss.send(SCAN_QUEUE, { scanId: scan.scanId }, { ...SCAN_JOB, singletonKey: scan.repositoryId });
  }
}

/** Registers the tick: every five minutes, cron evaluated in UTC (never in a zone with DST). */
export async function startScheduler(boss: PgBoss): Promise<void> {
  await boss.createQueue(TICK_QUEUE);
  await boss.schedule(TICK_QUEUE, "*/5 * * * *", null, { tz: "UTC" });
  await boss.work(TICK_QUEUE, { batchSize: 1 }, async () => {
    await scheduleTick(boss);
  });
}
