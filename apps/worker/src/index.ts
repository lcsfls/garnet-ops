import { mkdir } from "node:fs/promises";
import { PgBoss } from "pg-boss";
import { AI_PROBE_QUEUE, AI_QUEUE, runGeneration, runProbe, sweepAi } from "./ai.ts";
import { ATTACK_SUMMARY_QUEUE, runAttackSummary, sweepAttackSummaries } from "./attack-summary.ts";
import { startAttacksScheduler } from "./attacks.ts";
import { pool } from "./db.ts";
import { env } from "./env.ts";
import {
  checkWriteAccess,
  FIX_PR_CHECK_QUEUE,
  FIX_PR_QUEUE,
  FIX_PR_REFRESH_QUEUE,
  refreshFixPrs,
  runFixPr,
  startFixPrScheduler,
} from "./fix-pr.ts";
import {
  ensureHostAccessKey,
  HOST_ACCESS_KEY_QUEUE,
  HOST_INVENTORY_QUEUE,
  HOST_KEYSCAN_QUEUE,
  runHostInventory,
  scanHost,
} from "./hosts.ts";
import { deliver, eventsForScan, NOTIFY_QUEUE, queueNotifications } from "./notify.ts";
import {
  PROXMOX_CERT_QUEUE,
  PROXMOX_SYNC_QUEUE,
  readCertificate,
  runProxmoxSync,
  startProxmoxScheduler,
} from "./proxmox.ts";
import { runScan } from "./scan.ts";
import { SCAN_QUEUE as QUEUE, startScheduler } from "./schedule.ts";
import { startVulnDbUpdates } from "./vulndb.ts";
import {
  readCertificate as readWazuhCertificate,
  runWazuhSync,
  startWazuhScheduler,
  WAZUH_CERT_QUEUE,
  WAZUH_SYNC_QUEUE,
} from "./wazuh.ts";
import { runWazuhSummary, sweepWazuhSummaries, WAZUH_SUMMARY_QUEUE } from "./wazuh-summary.ts";

const AI_CONCURRENCY = 4;

await mkdir(env.GARNETOPS_WORK_DIR, { recursive: true });
const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-worker-queue" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(QUEUE);
await boss.createQueue(NOTIFY_QUEUE);
await boss.createQueue(AI_QUEUE);
await boss.createQueue(AI_PROBE_QUEUE);
await boss.createQueue(HOST_KEYSCAN_QUEUE);
await boss.createQueue(HOST_INVENTORY_QUEUE);
await boss.createQueue(HOST_ACCESS_KEY_QUEUE);
await boss.createQueue(PROXMOX_CERT_QUEUE);
await boss.createQueue(PROXMOX_SYNC_QUEUE);
await boss.createQueue(WAZUH_CERT_QUEUE);
await boss.createQueue(WAZUH_SYNC_QUEUE);
await boss.createQueue(WAZUH_SUMMARY_QUEUE);
await boss.createQueue(ATTACK_SUMMARY_QUEUE);
await boss.createQueue(FIX_PR_QUEUE);
await boss.createQueue(FIX_PR_CHECK_QUEUE);
await boss.createQueue(FIX_PR_REFRESH_QUEUE);

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
    if (events)
      await queueNotifications(boss, events.organizationId, events.payloads).catch((error: Error) => {
        console.error(`notify after scan ${job.data.scanId}:`, error.message);
      });
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
// Servers (ADR 0011): the organisation's access key, host key scans and inventories.
await boss.work<{ organizationId: string }>(HOST_ACCESS_KEY_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await ensureHostAccessKey(job.data.organizationId);
});
await boss.work<{ hostId: string }>(HOST_KEYSCAN_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await scanHost(job.data.hostId);
});
for (let i = 0; i < env.GARNETOPS_SCAN_CONCURRENCY; i++) {
  await boss.work<{ runId: string }>(HOST_INVENTORY_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (!job) return;
    const started = performance.now();
    await runHostInventory(job.data.runId);
    console.log(
      `host inventory ${job.data.runId} finished in ${Math.round((performance.now() - started) / 1000)} s`,
    );
  });
}
// Proxmox VE (ADR 0012): certificate reads and read-only syncs; one sync at a time per worker slot.
await boss.work<{ clusterId: string }>(PROXMOX_CERT_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await readCertificate(job.data.clusterId);
});
await boss.work<{ runId: string }>(PROXMOX_SYNC_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (!job) return;
  const started = performance.now();
  await runProxmoxSync(job.data.runId);
  console.log(
    `proxmox sync ${job.data.runId} finished in ${Math.round((performance.now() - started) / 1000)} s`,
  );
});
// Wazuh (ADR 0015): certificate reads, read-only syncs and the optional AI summary of the aggregates.
await boss.work<{ endpointId: string }>(WAZUH_CERT_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await readWazuhCertificate(job.data.endpointId);
});
await boss.work<{ runId: string }>(WAZUH_SYNC_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (!job) return;
  const started = performance.now();
  await runWazuhSync(job.data.runId);
  console.log(`xdr sync ${job.data.runId} finished in ${Math.round((performance.now() - started) / 1000)} s`);
});
await boss.work<{ summaryId: string }>(WAZUH_SUMMARY_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runWazuhSummary(job.data.summaryId);
});
const wazuhSweep = setInterval(
  () => sweepWazuhSummaries().catch((error: Error) => console.error("xdr sweep:", error.name)),
  60_000,
);
// Attack overview (ADR 0016): the optional AI summary of the aggregates; GeoIP download, OSINT and retention run below.
await boss.work<{ summaryId: string }>(ATTACK_SUMMARY_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runAttackSummary(job.data.summaryId);
});
const attackSweep = setInterval(
  () => sweepAttackSummaries().catch((error: Error) => console.error("attack sweep:", error.name)),
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
await startScheduler(boss);
await startProxmoxScheduler(boss);
await startWazuhScheduler(boss);
await startAttacksScheduler(boss);
const stopVulnDbUpdates = startVulnDbUpdates();
console.log(`worker: ready (${env.GARNETOPS_SCAN_CONCURRENCY} scan slots, nightly schedule active)`);

async function shutdown() {
  stopVulnDbUpdates();
  clearInterval(aiSweep);
  clearInterval(wazuhSweep);
  clearInterval(attackSweep);
  await boss.stop({ graceful: true, timeout: 30_000 }).catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
