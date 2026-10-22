import { runMigrations } from "@garnetops/db";
import { serve } from "@hono/node-server";
import { app } from "./app.ts";
import { boss, db, pool, QUEUES } from "./db.ts";
import { env } from "./env.ts";
import { listenBus } from "./lib/listen-bus.ts";
import { prepareSetupToken } from "./routes/setup.ts";
import { updater } from "./updater/client.ts";
import { journalStore, startJournalSync } from "./updater/journal.ts";

await runMigrations(db);
await boss.start();
for (const name of Object.values(QUEUES)) await boss.createQueue(name);
await prepareSetupToken();
// Copies the update sidecar's journal into the audit log; idles when there is no sidecar.
const stopJournalSync = startJournalSync(updater, journalStore(db));

const server = serve({ fetch: app.fetch, port: env.PORT, hostname: env.HOST }, (info) => {
  console.log(`api: listening on http://${env.HOST}:${info.port}`);
});

async function shutdown() {
  stopJournalSync();
  server.close();
  await listenBus.close().catch(() => {});
  await boss.stop({ graceful: true, timeout: 10_000 }).catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
