import { mkdir } from "node:fs/promises";
import { PgBoss } from "pg-boss";
import { pool } from "./db.ts";
import { env } from "./env.ts";
import { runScan } from "./scan.ts";
import { SCAN_QUEUE as QUEUE, startScheduler } from "./schedule.ts";
import { startVulnDbUpdates } from "./vulndb.ts";

await mkdir(env.GARNETOPS_WORK_DIR, { recursive: true });
const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-worker-queue" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(QUEUE);

for (let i = 0; i < env.GARNETOPS_SCAN_CONCURRENCY; i++) {
  await boss.work<{ scanId: string }>(QUEUE, { batchSize: 1 }, async ([job]) => {
    if (!job) return;
    const started = performance.now(); // monotonic: unaffected by clock changes (ADR 0005)
    await runScan(job.data.scanId);
    console.log(`scan ${job.data.scanId} finished in ${Math.round((performance.now() - started) / 1000)} s`);
  });
}
await startScheduler(boss);
const stopVulnDbUpdates = startVulnDbUpdates();
console.log(`worker: ready (${env.GARNETOPS_SCAN_CONCURRENCY} scan slots, nightly schedule active)`);

async function shutdown() {
  stopVulnDbUpdates();
  await boss.stop({ graceful: true, timeout: 30_000 }).catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
