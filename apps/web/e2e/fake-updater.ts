/**
 * A stand-in for the cicd-updater sidecar's HTTP API (ADR 0007), for the end-to-end
 * tests only. It keeps one installation's state in memory: version 1.0.0 runs, 1.1.0 is
 * available. Every answer is checked against the SDK's own schemas before it is sent,
 * so the fake cannot drift from what the real sidecar promises.
 *
 * Test controls (no token): POST /__test/reset, POST /__test/phase {"phase": ...}.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { dirname } from "node:path";
import {
  type EventsView,
  eventsViewSchema,
  initialSteps,
  publicStatusOf,
  publicStatusSchema,
  type Run,
  releasesViewSchema,
  stateViewSchema,
  stepOrder,
} from "@restow-backup/cicd-updater/protocol";
import { E2E } from "./env.ts";

const RUNNING = "1.0.0";
const NEXT = "1.1.0";
const RELEASE_SHA = createHash("sha256").update(`garnetops ${NEXT} e2e release.json`).digest("hex");
const CONFIG_HASH = "c".repeat(64);

const token = randomBytes(32).toString("hex");
mkdirSync(dirname(E2E.updaterTokenFile), { recursive: true });
writeFileSync(E2E.updaterTokenFile, token, { mode: 0o600 });

type Phase = "idle" | "scheduled" | "running" | "succeeded" | "failed";
type Event = EventsView["events"][number];

let phase: Phase = "idle";
let run: Run | null = null;
let events: Event[] = [];
let counter = 0;

const iso = (ms = Date.now()) => new Date(ms).toISOString();

function journal(action: Event["action"], actor: { id: string | null; label: string }) {
  if (!run) return;
  counter += 1;
  events.push({
    id: `${String(Date.now()).padStart(15, "0")}-${String(counter).padStart(6, "0")}`,
    at: iso(),
    action,
    runId: run.id,
    actor: { ...actor, via: "api" },
    target: run.targetVersion,
    details: {},
  });
}

function newRun(
  version: string,
  leadSeconds: number,
  requestedBy: { id?: string | null; label: string },
): Run {
  const now = Date.now();
  const startsAt = iso(now + leadSeconds * 1000);
  return {
    id: `r-${now}-${randomBytes(2).toString("hex")}`,
    mode: "image",
    fromVersion: RUNNING,
    targetVersion: version,
    targetTag: `v${version}`,
    notesUrl: `https://github.com/lcsfls/garnet-ops/releases/tag/v${version}`,
    release: { sha256: RELEASE_SHA, channel: "stable", document: "verified" },
    trustMode: "keyless",
    verification: { signatures: "verified", digests: null },
    requestedBy: { id: requestedBy.id ?? null, label: requestedBy.label, via: "api" },
    scheduledAt: iso(now),
    startsAt,
    leadSeconds,
    startedAt: null,
    finishedAt: null,
    cancelled: false,
    cancelledAt: null,
    abortRequestedAt: null,
    outcome: null,
    step: null,
    steps: initialSteps(stepOrder(false), new Set()),
    progress: 0,
    message: { code: "run.scheduled", params: { version, startsAt } },
    failure: null,
    recovery: null,
    images: {},
    configHash: CONFIG_HASH,
    log: [],
  } as Run;
}

function stateView() {
  return stateViewSchema.parse({
    api: { version: "1.0", features: ["abort"] },
    updater: { version: "1.0.0", configHash: CONFIG_HASH, latestAvailable: NEXT },
    phase,
    run,
    history: [],
    running: { version: phase === "succeeded" ? NEXT : RUNNING, source: "health" },
    trust: {
      mode: "keyless",
      identity: "https://github.com/lcsfls/garnet-ops/.github/workflows/release.yml",
      keys: null,
    },
    sourceMode: { enabled: false, allowlist: [] },
    capabilities: {
      ready: true,
      blockers: [],
      warnings: [],
      docker: {
        serverVersion: "29.0.0",
        apiVersion: "1.50",
        architecture: "linux/amd64",
        imageStore: "classic",
      },
      compose: {
        projectName: "garnetops",
        projectDir: "/opt/garnetops",
        files: ["docker-compose.yml"],
        envFile: ".env",
      },
      backups: [],
      checkedAt: iso(),
    },
    serverTime: iso(),
  });
}

function releasesView() {
  const done = phase === "succeeded";
  return releasesViewSchema.parse({
    channel: "stable",
    running: done ? NEXT : RUNNING,
    releases: [
      {
        version: NEXT,
        tag: `v${NEXT}`,
        channel: "stable",
        publishedAt: "2026-10-20T08:00:00.000Z",
        notesUrl: `https://github.com/lcsfls/garnet-ops/releases/tag/v${NEXT}`,
        releaseSha256: RELEASE_SHA,
        minimumFromVersion: null,
        manualStepsRequired: false,
        refusals: done ? ["not_newer"] : [],
        verified: false,
      },
    ],
    nextInstallable: done ? null : NEXT,
    checkedAt: iso(),
  });
}

function send(res: ServerResponse, status: number, body: unknown, type = "application/json") {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

function problem(res: ServerResponse, status: number, code: string, title: string, extra: object = {}) {
  send(
    res,
    status,
    { type: `about:blank#${code}`, title, status, code, ...extra },
    "application/problem+json",
  );
}

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  let text = "";
  for await (const chunk of req) text += chunk;
  return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}

function authorized(req: IncomingMessage): boolean {
  const given = Buffer.from((req.headers.authorization ?? "").replace(/^Bearer /, ""));
  const expected = Buffer.from(token);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://fake-updater");
  const path = url.pathname;
  try {
    if (path === "/__test/reset" && req.method === "POST") {
      phase = "idle";
      run = null;
      events = [];
      return send(res, 200, { ok: true });
    }
    if (path === "/__test/phase" && req.method === "POST") {
      const next = (await body(req)).phase as Phase;
      if (run && next === "running") {
        run = {
          ...run,
          startedAt: iso(),
          step: "fetch",
          progress: 35,
          message: { code: "run.started", params: { version: run.targetVersion } },
        };
        journal("update.started", { id: null, label: "system" });
      }
      if (run && next === "succeeded") {
        run = { ...run, finishedAt: iso(), outcome: "succeeded", progress: 100, step: null };
        journal("update.succeeded", { id: null, label: "system" });
      }
      phase = next;
      return send(res, 200, { ok: true });
    }
    if (path === "/public/v1/status") {
      return send(res, 200, publicStatusSchema.parse(publicStatusOf(phase, run, new Date())));
    }
    if (!path.startsWith("/v1/")) return problem(res, 404, "not_found", "Not found");
    if (!authorized(req)) return problem(res, 401, "unauthorized", "Missing or wrong token");

    if (req.method === "GET" && path === "/v1/state") return send(res, 200, stateView());
    if (req.method === "GET" && path === "/v1/releases") return send(res, 200, releasesView());
    if (req.method === "GET" && path === "/v1/events") {
      const after = url.searchParams.get("after");
      const limit = Number(url.searchParams.get("limit") ?? 100);
      const page = events.filter((e) => !after || e.id > after).slice(0, limit);
      return send(
        res,
        200,
        eventsViewSchema.parse({ events: page, next: page.at(-1)?.id ?? null, gap: false }),
      );
    }
    if (req.method === "POST" && path === "/v1/runs") {
      const input = await body(req);
      if (phase === "scheduled" || phase === "running")
        return problem(res, 409, "busy", "An update is already planned");
      if ((input.expect as { releaseSha256?: string } | undefined)?.releaseSha256 !== RELEASE_SHA) {
        return problem(res, 409, "release_mismatch", "The release changed");
      }
      run = newRun(
        String(input.version),
        Number(input.leadSeconds ?? 0),
        input.requestedBy as { id: string; label: string },
      );
      phase = "scheduled";
      journal("update.scheduled", run.requestedBy);
      return send(res, 202, stateView());
    }
    const action = /^\/v1\/runs\/([^/]+)\/(cancel|acknowledge)$/.exec(path);
    if (req.method === "POST" && action) {
      const input = await body(req);
      if (!run || run.id !== action[1]) return problem(res, 404, "not_found", "No such run");
      const actor = (input.requestedBy as { id: string; label: string } | undefined) ?? {
        id: null,
        label: "unknown",
      };
      journal(action[2] === "cancel" ? "update.cancelled" : "update.acknowledged", actor);
      phase = "idle";
      run = null;
      return send(res, 200, stateView());
    }
    return problem(res, 404, "not_found", "Not found");
  } catch (error) {
    console.error("fake updater:", error);
    return problem(res, 500, "internal", "Fake updater failed");
  }
});

server.listen(E2E.updaterPort, "127.0.0.1", () => {
  console.log(`e2e: fake updater on http://127.0.0.1:${E2E.updaterPort}`);
});
