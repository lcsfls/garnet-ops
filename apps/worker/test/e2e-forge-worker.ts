/**
 * For the end-to-end tests of the web app only (apps/web/e2e): the fix pull request part of the
 * worker (ADR 0014) plus a fake Gitea/Forgejo server (HTTPS, throw-away certificate made with
 * openssl) in one process, and a small control server on plain http for the tests to look at
 * what the forge received and to merge a pull request. The real worker stays off there: it would
 * also pick up the scans other tests queue.
 *
 * The API address the tests enter names a private address; the hooks below open the socket to this
 * process on loopback instead, while the address policy still judges the configured address.
 * Run with: tsx test/e2e-forge-worker.ts (environment as for the worker).
 */
import { createServer } from "node:http";
import { PgBoss } from "pg-boss";
import { env } from "../src/env.ts";
import {
  checkWriteAccess,
  FIX_PR_CHECK_QUEUE,
  FIX_PR_QUEUE,
  FIX_PR_REFRESH_QUEUE,
  refreshFixPrs,
  runFixPr,
} from "../src/fix-pr.ts";
import { setForgeTestHooks } from "../src/forge.ts";
import { FakeForge } from "./fake-forge.ts";

const forgePort = Number(process.env.E2E_FORGE_PORT ?? 8093);
const controlPort = Number(process.env.E2E_FORGE_CONTROL_PORT ?? 8094);
const TOKEN = "e2e-write-token-0123456789";
/** What the end-to-end database's manifest row was made from (apps/web/e2e/seed.ts). */
const MANIFEST = '{"name":"seeded-app","dependencies":{"pkg-1":"^1.0.0","pkg-2":"1.0.0"}}\n';

const forge = await new FakeForge("gitea", TOKEN, "team", "seeded-app", {
  files: { "package.json": MANIFEST },
}).start(forgePort);
setForgeTestHooks({ resolve: async () => ["192.168.1.20"], connectTo: () => "127.0.0.1", ca: forge.ca });

createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  res.setHeader("content-type", "application/json");
  if (url.pathname === "/state") {
    return void res.end(
      JSON.stringify({
        token: TOKEN,
        requests: forge.requests,
        pulls: forge.pulls,
        branches: [...forge.branches.keys()],
        files: Object.fromEntries(
          [...forge.branches.keys()].map((b) => [b, forge.fileOn(b, "package.json")]),
        ),
      }),
    );
  }
  const merge = /^\/merge\/(\d+)$/.exec(url.pathname);
  if (merge && req.method === "POST") {
    forge.setPull(Number(merge[1]), { state: "closed", merged: true });
    return void res.end("{}");
  }
  if (url.pathname === "/reset") {
    forge.requests.length = 0;
    return void res.end("{}");
  }
  res.writeHead(404).end("{}");
}).listen(controlPort, "127.0.0.1", () =>
  console.log(`e2e: fake forge on 127.0.0.1:${forgePort}, control on 127.0.0.1:${controlPort}`),
);

const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-e2e-forge" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(FIX_PR_QUEUE);
await boss.createQueue(FIX_PR_CHECK_QUEUE);
await boss.createQueue(FIX_PR_REFRESH_QUEUE);
await boss.work<{ fixPrId: string }>(FIX_PR_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runFixPr(job.data.fixPrId);
});
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
console.log("e2e: fix pull request worker ready");
