import { mkdir } from "node:fs/promises";
import { PgBoss } from "pg-boss";
import { AI_PROBE_QUEUE, AI_QUEUE, runGeneration, runProbe, sweepAi } from "./ai.ts";
import { pool } from "./db.ts";
import {
  DIRECTORY_QUEUE,
  runDirectoryRequest,
  startDirectoryReconcile,
  sweepDirectory,
} from "./directory.ts";
import { startEarlyWarnings } from "./early-warning.ts";
import { env } from "./env.ts";
import {
  EXPOSURE_RUN_QUEUE,
  EXPOSURE_VERIFY_QUEUE,
  runExposure,
  runVerify,
  startExposureScheduler,
} from "./exposure.ts";
import {
  checkWriteAccess,
  FIX_PR_CHECK_QUEUE,
  FIX_PR_QUEUE,
  FIX_PR_REFRESH_QUEUE,
  refreshFixPrs,
  runFixPr,
  startFixPrScheduler,
} from "./fix-pr.ts";
import { FORGE_CONNECTION_QUEUE, type RefreshJob, refreshConnection } from "./forge-connection.ts";
import { FORGE_SIGN_IN_QUEUE, runSignIn } from "./forge-sign-in.ts";
import { startHosts } from "./hosts.ts";
import { deliver, eventsForScan, NOTIFY_QUEUE, queueNotifications } from "./notify.ts";
import { startPullRequestRefresh } from "./pull-requests.ts";
import { removeRetiredQueues } from "./retired-queues.ts";
import { runScan } from "./scan.ts";
import { SCAN_QUEUE as QUEUE, startScheduler } from "./schedule.ts";
import { startSystemReports } from "./system-report.ts";
import { startUptime } from "./uptime.ts";
import { startUserNotificationUpkeep, tellAboutScan } from "./user-notify.ts";
import { startVulnDbUpdates } from "./vulndb.ts";

const AI_CONCURRENCY = 4;
const DIRECTORY_CONCURRENCY = 4;
const EXPOSURE_CONCURRENCY = 2;

await mkdir(env.GARNETOPS_WORK_DIR, { recursive: true });
const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-worker-queue" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(QUEUE);
await boss.createQueue(NOTIFY_QUEUE);
await boss.createQueue(AI_QUEUE);
await boss.createQueue(AI_PROBE_QUEUE);
await boss.createQueue(FIX_PR_QUEUE);
await boss.createQueue(FIX_PR_CHECK_QUEUE);
await boss.createQueue(FIX_PR_REFRESH_QUEUE);
await boss.createQueue(DIRECTORY_QUEUE);
await boss.createQueue(FORGE_CONNECTION_QUEUE);
await boss.createQueue(FORGE_SIGN_IN_QUEUE);
await boss.createQueue(EXPOSURE_VERIFY_QUEUE);
await boss.createQueue(EXPOSURE_RUN_QUEUE);
// Queues and schedules of the modules removed in 0.0.4 (ADR 0025) would otherwise stay in the database.
const retired = await removeRetiredQueues(boss);
if (retired.length > 0) console.log(`worker: removed ${retired.length} retired queues`);

for (let i = 0; i < env.GARNETOPS_SCAN_CONCURRENCY; i++) {
  await boss.work<{ scanId: string }>(QUEUE, { batchSize: 1 }, async ([job]) => {
    if (!job) return;
    const started = performance.now(); // monotonic: unaffected by clock changes (ADR 0005)
    await runScan(job.data.scanId);
    console.log(`scan ${job.data.scanId} finished in ${Math.round((performance.now() - started) / 1000)} s`);
    // Notifications never fail a scan: a broken channel is recorded on the channel, not here.
    const events = await eventsForScan(job.data.scanId).catch((error: Error) => {
      console.error(`notify after scan ${job.data.scanId}:`, error.message);
      return null;
    });
    if (events) {
      await queueNotifications(boss, events.organizationId, events.payloads).catch((error: Error) => {
        console.error(`notify after scan ${job.data.scanId}:`, error.message);
      });
      // The same facts for the people of the organisation, in the app and by their own mail (ADR 0019).
      await tellAboutScan(events);
    }
  });
}
await boss.work<{ channelId: string; payload: Parameters<typeof deliver>[1] }>(
  NOTIFY_QUEUE,
  { batchSize: 1 },
  async ([job]) => {
    if (job) await deliver(job.data.channelId, job.data.payload);
  },
);
// AI triage (ADR 0013): the worker is the only process that opens the API key, so it makes every model call.
// Generations are I/O bound (a stream can last minutes), so several run at once; the per-organisation
// limit is enforced where they are queued.
for (let i = 0; i < AI_CONCURRENCY; i++) {
  await boss.work<{ messageId: string }>(AI_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (job) await runGeneration(job.data.messageId);
  });
}
await boss.work<{ probeId: string }>(AI_PROBE_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runProbe(job.data.probeId);
});
const aiSweep = setInterval(
  () => sweepAi().catch((error: Error) => console.error("ai sweep:", error.name)),
  60_000,
);
sweepAi().catch((error: Error) => console.error("ai sweep:", error.name));
// Directory sign-in (ADR 0020): the worker is the only process that opens the service account's password, so it
// makes every connection to the directory. A person waits for the answer, so this queue is polled twice a second.
for (let i = 0; i < DIRECTORY_CONCURRENCY; i++) {
  await boss.work<{ requestId: string }>(
    DIRECTORY_QUEUE,
    { batchSize: 1, pollingIntervalSeconds: 0.5 },
    async ([job]) => {
      if (job) await runDirectoryRequest(job.data.requestId);
    },
  );
}
const directorySweep = setInterval(
  () => sweepDirectory().catch((error: Error) => console.error("directory sweep:", error.name)),
  60_000,
);
// Fix pull requests (ADR 0014): the worker is the only process that opens the write token. No retries:
// a second attempt could open a second pull request, so a failure is stored on the request instead.
for (let i = 0; i < 2; i++) {
  await boss.work<{ fixPrId: string }>(FIX_PR_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (job) await runFixPr(job.data.fixPrId);
  });
}
await boss.work<{ repositoryId: string }>(FIX_PR_CHECK_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await checkWriteAccess(job.data.repositoryId);
});
await boss.work<{ organizationId?: string; repositoryId?: string }>(
  FIX_PR_REFRESH_QUEUE,
  { batchSize: 1 },
  async ([job]) => {
    if (job) await refreshFixPrs({ ...job.data, force: true });
  },
);
await startFixPrScheduler(boss);
// The open pull requests of the monitored repositories with their gate results (ADR 0032).
await startPullRequestRefresh(boss);
// Personal forge connections (ADR 0030): checking a token and listing what its account can see.
await boss.work<RefreshJob>(FORGE_CONNECTION_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await refreshConnection(job.data);
});
// Signing in to a forge (ADR 0031): a device flow waits for the person for up to 15 minutes, so several run side by side.
for (let i = 0; i < 4; i++) {
  await boss.work<{ signInId: string }>(FORGE_SIGN_IN_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (job) await runSignIn(job.data.signInId);
  });
}
// Website monitoring (ADR 0023, a module since ADR 0033): the proof of control, stage 1 (passive) and stage 2 (light active).
// Every outbound connection to an asset is made here, after the address was checked, and only for organisations that
// switched the module on.
await boss.work<{ assetId: string }>(EXPOSURE_VERIFY_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runVerify(job.data.assetId);
});
for (let i = 0; i < EXPOSURE_CONCURRENCY; i++) {
  await boss.work<{ runId: string }>(EXPOSURE_RUN_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (!job) return;
    const started = performance.now();
    await runExposure(job.data.runId);
    console.log(
      `website check ${job.data.runId} finished in ${Math.round((performance.now() - started) / 1000)} s`,
    );
  });
}
await startExposureScheduler(boss);
// Hosts and containers (ADR 0034): matching the packages of running images, and the opt-in registry check.
await startHosts(boss);
await startUptime(boss);
await startScheduler(boss);
const stopDirectoryReconcile = startDirectoryReconcile();
const stopVulnDbUpdates = startVulnDbUpdates();
const stopUserNotifications = startUserNotificationUpkeep();
// The heartbeat, the scanner versions and the database metadata for the System status page (ADR 0024).
const stopSystemReports = startSystemReports();
const stopEarlyWarnings = startEarlyWarnings(boss);
console.log(`worker: ready (${env.GARNETOPS_SCAN_CONCURRENCY} scan slots, nightly schedule active)`);

async function shutdown() {
  stopDirectoryReconcile();
  stopVulnDbUpdates();
  stopEarlyWarnings();
  stopUserNotifications();
  await stopSystemReports();
  clearInterval(aiSweep);
  clearInterval(directorySweep);
  await boss.stop({ graceful: true, timeout: 30_000 }).catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
