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
import { FORGE_CONNECTION_QUEUE, type RefreshJob, refreshConnection } from "../src/forge-connection.ts";
import { FORGE_SIGN_IN_QUEUE, runSignIn } from "../src/forge-sign-in.ts";
import { PULL_REQUEST_QUEUE, refreshPullRequests } from "../src/pull-requests.ts";
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
// Signing in (ADR 0031): the OAuth2 application the e2e tests register, and the redirect address of the e2e app.
forge.oauth.clientId = "garnetops-e2e-client";
forge.oauth.clientSecret = "e2e-client-secret-0123";
// The device flow stays "pending" until the test cancels it.
forge.oauth.pendingPolls = 10_000;
forge.oauth.redirectUri = `${(process.env.PUBLIC_URL ?? "").replace(/\/+$/, "")}/settings/accounts/callback`;
// What a connected account sees (personal connections, ADR 0030): the seeded repository and two more.
forge.listed = ["seeded-app", "billing-portal", "website"].map((name, i) => ({
  id: 500 + i,
  full_name: `team/${name}`,
  clone_url: `https://forge.example.test:${forgePort}/team/${name}.git`,
  default_branch: "main",
  private: name !== "website",
  archived: false,
  description: name === "website" ? "The public website" : null,
}));
// An open pull request someone else opened (pull request overview, ADR 0032), with a title that tries to be markup.
forge.extraPulls = [
  {
    number: 42,
    title: "<b>Bump pkg-1</b> to 1.2.0",
    user: { login: "sam" },
    head: { ref: "deps/pkg-1", sha: "4".repeat(40) },
    base: { ref: "main" },
    html_url: "https://elsewhere.example.com/phish",
    draft: false,
    created_at: "2026-10-28T08:00:00Z",
    updated_at: "2026-10-29T08:00:00Z",
  },
];

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
  // What the forge's authorize page would do after the person agreed: a code bound to the PKCE challenge.
  if (url.pathname === "/authorize") {
    return void res.end(JSON.stringify({ code: forge.authorize(url.searchParams.get("challenge") ?? "") }));
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
await boss.createQueue(FORGE_CONNECTION_QUEUE);
await boss.createQueue(FORGE_SIGN_IN_QUEUE);
await boss.createQueue(PULL_REQUEST_QUEUE);
await boss.work<{ organizationId: string; repositoryIds?: string[] }>(
  PULL_REQUEST_QUEUE,
  { batchSize: 1 },
  async ([job]) => {
    if (job) await refreshPullRequests(job.data);
  },
);
await boss.work<{ signInId: string }>(FORGE_SIGN_IN_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runSignIn(job.data.signInId);
});
await boss.work<RefreshJob>(FORGE_CONNECTION_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await refreshConnection(job.data);
});
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
