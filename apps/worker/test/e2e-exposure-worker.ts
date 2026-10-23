/**
 * For the end-to-end tests of the web app only (apps/web/e2e): the exposure part of the worker (ADR 0023) with a fake resolver and two
 * local services, in one process, and a small control server on plain http for the tests to publish or withdraw the proof of control of
 * a name, make a name resolve, and read the ports of the services. The real worker stays off there: it would also pick up the scans other
 * tests queue, and its schedule would touch the seeded assets.
 *
 * Names resolve to loopback only when a test says so, and stage 2 uses a list of two ports (a service that greets with an SSH banner
 * and a silent one that stands in for a database) instead of the documented thirty, so a run is quick and deterministic. The address
 * policy of the worker is switched to its test mode (loopback allowed) for this process only. Run with:
 * tsx test/e2e-exposure-worker.ts (environment as for the worker).
 */
import { createServer } from "node:http";
import { createServer as createNetServer, type Server } from "node:net";
import type { PortSpec } from "@garnetops/core/exposure";
import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { PgBoss } from "pg-boss";
import { db, pool } from "../src/db.ts";
import { env } from "../src/env.ts";
import { EXPOSURE_RUN_QUEUE, EXPOSURE_VERIFY_QUEUE, runExposure, runVerify } from "../src/exposure.ts";
import type { DnsLike } from "../src/exposure-net.ts";

const controlPort = Number(process.env.E2E_EXPOSURE_CONTROL_PORT ?? 8097);

/** Names whose proof is published, and names that resolve (to loopback). */
const proofs = new Set<string>();
const resolving = new Set<string>();

const noData = () => Object.assign(new Error("no data"), { code: "ENODATA" });
const tokenOf = async (domain: string) =>
  (
    await db
      .select({ token: schema.exposureAsset.verifyToken })
      .from(schema.exposureAsset)
      .where(eq(schema.exposureAsset.value, domain))
      .limit(1)
  )[0]?.token;

const dns: DnsLike = {
  resolve4: async (name) => (resolving.has(name) ? ["127.0.0.1"] : Promise.reject(noData())),
  resolve6: () => Promise.reject(noData()),
  resolveCname: () => Promise.reject(noData()),
  resolveMx: () => Promise.reject(noData()),
  resolveNs: () => Promise.reject(noData()),
  resolveCaa: () => Promise.reject(noData()),
  resolveTxt: async (name) => {
    const domain = /^_garnetops-challenge\.(.+)$/.exec(name)?.[1];
    const token = domain && proofs.has(domain) ? await tokenOf(domain) : undefined;
    if (!token) throw noData();
    return [[`garnetops-verify=${token}`]];
  },
  reverse: () => Promise.reject(noData()),
};

function listen(
  onConnect: (socket: import("node:net").Socket) => void,
): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createNetServer((socket) => {
      socket.on("error", () => {});
      onConnect(socket);
    });
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: (server.address() as { port: number }).port }),
    );
  });
}
const ssh = await listen((socket) => socket.write("SSH-2.0-E2E_Service_1.0\r\n"));
const redis = await listen(() => {});

const ports: PortSpec[] = [
  { port: ssh.port, service: "ssh", category: "expected", banner: true, tls: false, severity: null },
  { port: redis.port, service: "redis", category: "database", banner: false, tls: false, severity: "high" },
];
const deps = {
  net: { dns, allowTestRanges: true, connectTimeoutMs: 1000, bannerReadMs: 800 },
  ports,
};

const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-e2e-exposure" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(EXPOSURE_VERIFY_QUEUE);
await boss.createQueue(EXPOSURE_RUN_QUEUE);
await boss.work<{ assetId: string }>(
  EXPOSURE_VERIFY_QUEUE,
  { batchSize: 1, pollingIntervalSeconds: 0.5 },
  async ([job]) => {
    if (job) await runVerify(job.data.assetId, deps);
  },
);
await boss.work<{ runId: string }>(
  EXPOSURE_RUN_QUEUE,
  { batchSize: 1, pollingIntervalSeconds: 0.5 },
  async ([job]) => {
    if (job) await runExposure(job.data.runId, deps);
  },
);

const control = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const json = (status: number, body: unknown) =>
    void res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  const state = () => ({
    sshPort: ssh.port,
    redisPort: redis.port,
    proofs: [...proofs],
    resolving: [...resolving],
  });
  if (req.method === "GET" && url.pathname === "/state") return json(200, state());
  const match = /^\/(proof|resolve)\/([A-Za-z0-9.-]{1,253})$/.exec(url.pathname);
  if (match && (req.method === "PUT" || req.method === "DELETE")) {
    const set = match[1] === "proof" ? proofs : resolving;
    const name = match[2] as string;
    if (req.method === "PUT") set.add(name);
    else set.delete(name);
    return json(200, state());
  }
  json(404, { error: "not found" });
});
control.listen(controlPort, "127.0.0.1", () => {
  console.log(`e2e exposure worker: ready (ssh ${ssh.port}, silent ${redis.port}, control ${controlPort})`);
});

async function shutdown() {
  control.close();
  ssh.server.close();
  redis.server.close();
  await boss.stop({ graceful: true, timeout: 10_000 }).catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
