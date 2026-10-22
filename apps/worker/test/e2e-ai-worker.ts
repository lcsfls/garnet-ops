/**
 * For the end-to-end tests of the web app only (apps/web/e2e): the AI part of the worker plus a
 * fake OpenAI-compatible model server, in one process. The real worker is not started there,
 * because it would also pick up the scans the other tests queue.
 *
 * The settings in the tests name a VPN overlay address (100.64.0.20, where plain http is accepted); the test hook below opens the
 * socket to this process on loopback instead, while the address policy still judges the
 * configured address. Run with: tsx test/e2e-ai-worker.ts (environment as for the worker).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { PgBoss } from "pg-boss";
import { AI_PROBE_QUEUE, AI_QUEUE, runGeneration, runProbe } from "../src/ai.ts";
import { setModelTestHooks } from "../src/ai-client.ts";
import { ATTACK_SUMMARY_QUEUE, runAttackSummary } from "../src/attack-summary.ts";
import { env } from "../src/env.ts";
import { runWazuhSummary, WAZUH_SUMMARY_QUEUE } from "../src/wazuh-summary.ts";

const port = Number(process.env.E2E_MODEL_PORT ?? 8092);
const KEY = "e2e-secret-key";
setModelTestHooks({ connectTo: () => "127.0.0.1" });

const TRIAGE = {
  exploitability: "likely",
  reachable: "yes",
  confidence: "high",
  summary: "The vulnerable function is called with request data, so an attacker can reach it.",
  recommendation: "Update to the fixed version and run the tests. Then redeploy.",
  upgradeTo: "1.0.1",
  references: ["https://advisories.example.test/CVE-2099-0001", "https://evil.example.com/phish"],
  // A model that was talked into more than it may do: none of this is ever acted on.
  severity: "low",
  state: "resolved",
  gate: "passed",
};

const FOLLOW_UP = [
  "Updating to **1.0.1** is a patch release.\n\n",
  "- run the tests\n- check usages of `merge()`\n\n",
  "[advisory](https://advisories.example.test/CVE-2099-0001) ",
  "<script>document.title='pwned'</script> ",
  "[click me](javascript:document.title='pwned')\n\n",
  "```sh\nnpm install pkg-1@1.0.1\n```\n",
];

interface Seen {
  path: string;
  model: string;
  stream: boolean;
  authOk: boolean;
  system: string;
  prompt: string;
}
const seen: Seen[] = [];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const chunk = (content: string) => `data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`;

async function model(req: IncomingMessage, res: ServerResponse, body: Record<string, unknown> | null) {
  const messages = (body?.messages ?? []) as { role: string; content: string }[];
  const name = String(body?.model ?? "");
  seen.push({
    path: req.url ?? "",
    model: name,
    stream: body?.stream === true,
    authOk: req.headers.authorization === `Bearer ${KEY}`,
    system: messages.find((m) => m.role === "system")?.content ?? "",
    prompt: messages.find((m) => m.role === "user")?.content ?? "",
  });
  if (body?.stream === false) {
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(JSON.stringify({ choices: [{ message: { content: "ok" } }] }));
  }
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  // A triage ends with the instruction to answer in JSON; a follow-up ends with the person's question.
  const triage = String(messages.at(-1)?.content ?? "").includes("Respond with exactly one JSON object");
  const pieces =
    name === "e2e-slow"
      ? Array.from({ length: 600 }, (_, i) => `word${i} `)
      : triage
        ? (JSON.stringify(TRIAGE).match(/[\s\S]{1,24}/g) ?? [])
        : FOLLOW_UP;
  for (const piece of pieces) {
    if (res.destroyed) return;
    res.write(chunk(piece));
    await sleep(name === "e2e-slow" ? 100 : triage ? 70 : 150);
  }
  res.write(
    `data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 321, completion_tokens: 54 } })}\n\ndata: [DONE]\n\n`,
  );
  res.end();
}

createServer((req, res) => {
  const url = req.url ?? "";
  if (url === "/__test/requests") {
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(JSON.stringify(seen));
  }
  if (url === "/__test/reset") {
    seen.length = 0;
    return void res.writeHead(204).end();
  }
  if (url === "/v1/models" && req.method === "GET") {
    // The tests' own readiness check has no key; only requests that carry one are the worker's.
    if (req.headers.authorization) {
      seen.push({
        path: url,
        model: "",
        stream: false,
        authOk: req.headers.authorization === `Bearer ${KEY}`,
        system: "",
        prompt: "",
      });
    }
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(JSON.stringify({ data: [{ id: "e2e-model" }, { id: "e2e-slow" }] }));
  }
  let data = "";
  req.on("data", (c) => {
    data += c;
  });
  req.on("end", () => {
    let body: Record<string, unknown> | null = null;
    try {
      body = data ? (JSON.parse(data) as Record<string, unknown>) : null;
    } catch {
      body = null;
    }
    if (url.endsWith("/chat/completions")) void model(req, res, body);
    else res.writeHead(404).end();
  });
}).listen(port, "127.0.0.1", () => console.log(`e2e: fake model on 127.0.0.1:${port}`));

const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-e2e-ai" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(AI_QUEUE);
await boss.createQueue(AI_PROBE_QUEUE);
await boss.createQueue(WAZUH_SUMMARY_QUEUE);
await boss.createQueue(ATTACK_SUMMARY_QUEUE);
for (let i = 0; i < 2; i++) {
  await boss.work<{ messageId: string }>(AI_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (job) await runGeneration(job.data.messageId);
  });
}
await boss.work<{ probeId: string }>(AI_PROBE_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runProbe(job.data.probeId);
});
// The XDR page's "Summarise with AI" (ADR 0015) goes through the same model and the same address policy.
await boss.work<{ summaryId: string }>(WAZUH_SUMMARY_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runWazuhSummary(job.data.summaryId);
});
// The Attacks page's "Summarise with AI" (ADR 0016): numbers per country and network, never an address.
await boss.work<{ summaryId: string }>(ATTACK_SUMMARY_QUEUE, { batchSize: 1 }, async ([job]) => {
  if (job) await runAttackSummary(job.data.summaryId);
});
console.log("e2e: AI worker ready");
