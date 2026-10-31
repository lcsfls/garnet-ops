/**
 * Our own vulnerability database (ADR 0044): with GARNETOPS_GRYPE_DB_UPDATE=build the worker asks the builder service
 * (Compose profile `vulndb`) once a day for a new database, checks the archive it leaves and imports it with grype.
 *
 * The builder parses the feeds, which are hostile input; it has no database, no vault key and no route into the stack.
 * The worker opens the optional GitHub token and NVD API key (Settings → External services) and hands them over for
 * one build only, over a Unix socket on a volume only the two mount. What comes back is checked here: the status with a
 * schema, the archive by name, size and SHA-256 before grype reads it. A failed build keeps the database that is there.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, realpath, stat } from "node:fs/promises";
import { request } from "node:http";
import { join, sep } from "node:path";
import { pipeline } from "node:stream/promises";
import {
  VULNDB_UPDATE_INTERVAL_HOURS,
  type VulnDbBuildReport,
  type VulnDbUpdateReason,
  vulnDbBuildReportSchema,
  vulnDbReportSchema,
} from "@garnetops/core/system-status";
import { VULNDB_BUILD_SETTINGS_ID } from "@garnetops/core/vulndb-build";
import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { run } from "./run.ts";
import { probeVulnDb, readReport, reportVulnDbUpdate, writeReport } from "./system-report.ts";
import { openSecretText } from "./vault-secrets.ts";

const INTERVAL_MS = VULNDB_UPDATE_INTERVAL_HOURS * 3600 * 1000;
/** How often the worker asks while a build runs, and how long a build may take in all. */
const POLL_MS = 60_000;
const BUILD_DEADLINE_MS = 30 * 3600 * 1000;
/** A grype v6 archive is around 100 MB today; anything far larger is refused. */
const MAX_ARCHIVE_BYTES = 4 * 1024 ** 3;
const ARCHIVE_NAME = /^vulnerability-db_v\d+\.\d+\.\d+_[0-9TZ:.-]+_\d+\.tar\.zst$/;
const REQUEST_TIMEOUT_MS = 15_000;

const providerSchema = z.object({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/),
  lastRunAt: z.string().datetime({ offset: true }).nullable(),
  result: z.enum(["ok", "failed", "skipped"]).nullable(),
  records: z.number().int().nonnegative().nullable(),
  durationMs: z.number().int().nonnegative().nullable(),
  reason: z
    .string()
    .regex(/^[a-z_]{1,40}$/)
    .nullable(),
});

/** The builder's answer to `GET /v1/build`. */
export const builderStatusSchema = z.object({
  state: z.enum(["idle", "running", "succeeded", "failed"]),
  startedAt: z.string().datetime({ offset: true }).nullable(),
  finishedAt: z.string().datetime({ offset: true }).nullable(),
  reason: z
    .string()
    .regex(/^[a-z_]{1,40}$/)
    .nullable(),
  providers: z.array(providerSchema).max(200),
  archive: z
    .object({
      file: z.string().regex(ARCHIVE_NAME),
      sha256: z.string().regex(/^[0-9a-f]{64}$/),
      size: z.number().int().positive().max(MAX_ARCHIVE_BYTES),
      built: z.string().datetime({ offset: true }).nullable(),
      schemaVersion: z.string().max(40).nullable(),
    })
    .nullable(),
});
export type BuilderStatus = z.infer<typeof builderStatusSchema>;

export class BuilderUnavailableError extends Error {}

/** One request to the builder; the answer is at most 1 MB of JSON. */
function call(
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<{ status: number; json: unknown }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath: env.GARNETOPS_VULNDB_BUILDER_SOCKET,
        path,
        method,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: body === undefined ? {} : { "content-type": "application/json" },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          text += chunk;
          if (text.length > 1024 * 1024) req.destroy(new Error("answer too large"));
        });
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : null });
          } catch {
            reject(new BuilderUnavailableError("unreadable answer"));
          }
        });
        res.on("error", (error) => reject(new BuilderUnavailableError(error.message)));
      },
    );
    req.on("error", (error) => reject(new BuilderUnavailableError(error.message)));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

export async function builderStatus(): Promise<BuilderStatus> {
  const { status, json } = await call("GET", "/v1/build");
  if (status !== 200) throw new BuilderUnavailableError(`http ${status}`);
  return builderStatusSchema.parse(json);
}

/** The keys for one build: opened from the vault, never stored or logged by the worker. */
export async function buildKeys(): Promise<{ githubToken: string | null; nvdApiKey: string | null }> {
  const [row] = await db
    .select()
    .from(schema.vulnDbBuildSettings)
    .where(eq(schema.vulnDbBuildSettings.id, VULNDB_BUILD_SETTINGS_ID))
    .limit(1);
  if (!row) return { githubToken: null, nvdApiKey: null };
  const githubToken = row.githubOrganizationId
    ? await openSecretText(row.githubSecretId, row.githubOrganizationId, "vulndb-github-token")
    : null;
  const nvdApiKey = row.nvdOrganizationId
    ? await openSecretText(row.nvdSecretId, row.nvdOrganizationId, "vulndb-nvd-api-key")
    : null;
  return { githubToken, nvdApiKey };
}

/** Starts a build; false when one already runs (the worker then follows that one). */
async function startBuild(): Promise<boolean> {
  const keys = await buildKeys();
  const { status } = await call("POST", "/v1/build", keys);
  if (status === 202) return true;
  if (status === 409) return false;
  throw new BuilderUnavailableError(`http ${status}`);
}

async function sha256Of(file: string): Promise<string> {
  const hash = createHash("sha256");
  await pipeline(createReadStream(file), hash);
  return hash.digest("hex");
}

/**
 * Checks the archive the builder left and returns its path: a plain file of the expected name, inside the builds
 * directory, of the announced size and SHA-256. Null when anything does not match.
 */
export async function verifiedArchive(
  archive: NonNullable<BuilderStatus["archive"]>,
  dir: string,
): Promise<string | null> {
  try {
    const root = await realpath(dir);
    const file = await realpath(join(root, archive.file));
    if (!file.startsWith(root + sep)) return null;
    const info = await stat(file);
    if (!info.isFile() || info.size !== archive.size || info.size > MAX_ARCHIVE_BYTES) return null;
    return (await sha256Of(file)) === archive.sha256 ? file : null;
  } catch {
    return null;
  }
}

/** The report for the System status page; nothing of the builder's output but codes and counts. */
export function buildReportOf(status: BuilderStatus, previous: VulnDbBuildReport | null): VulnDbBuildReport {
  return vulnDbBuildReportSchema.parse({
    v: 1,
    enabled: true,
    lastBuildAt: status.state === "succeeded" ? status.finishedAt : (previous?.lastBuildAt ?? null),
    providers: status.providers.map((p) => ({ ...p, name: p.name.slice(0, 100) })),
  });
}

/** Maps the builder's code for a failed build to the reasons the System status page knows. */
export function reasonOfBuild(code: string | null): VulnDbUpdateReason {
  if (code === "no_data") return "no_data";
  if (code === "vunnel_unavailable" || code === "interrupted") return "not_started";
  return "build_failed";
}

async function importArchive(path: string): Promise<void> {
  const home = join(env.GARNETOPS_WORK_DIR, "vulndb-home");
  await mkdir(home, { recursive: true });
  await run(env.GARNETOPS_GRYPE_BIN, ["db", "import", path], {
    env: {
      PATH: process.env.PATH,
      HOME: home,
      TMP: home,
      TEMP: home,
      GRYPE_DB_CACHE_DIR: env.GARNETOPS_GRYPE_DB_DIR,
      GRYPE_DB_AUTO_UPDATE: "false",
      GRYPE_CHECK_FOR_APP_UPDATE: "false",
    },
    timeoutMs: 30 * 60_000,
  });
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    });
  });

/** One build from start to import. Reports every outcome; never throws. */
export async function buildOnce(
  signal: AbortSignal,
  options: { start?: boolean; nextInMs?: number; pollMs?: number } = {},
): Promise<void> {
  const attemptedAt = new Date().toISOString();
  const nextAt = new Date(Date.now() + (options.nextInMs ?? INTERVAL_MS)).toISOString();
  const fail = (reason: VulnDbUpdateReason) =>
    reportVulnDbUpdate({
      mode: "build",
      lastAttemptAt: attemptedAt,
      lastResult: "failed",
      reason,
      nextAt,
    });
  let status: BuilderStatus;
  try {
    const start = options.start ?? true;
    if (start) await startBuild();
    const deadline = Date.now() + BUILD_DEADLINE_MS;
    status = await builderStatus();
    while ((start || status.state === "running") && Date.now() < deadline) {
      await sleep(options.pollMs ?? POLL_MS, signal);
      if (signal.aborted) return;
      status = await builderStatus();
      if (status.state !== "running") break;
    }
  } catch (error) {
    console.error(`vulndb build: the builder did not answer: ${(error as Error).message}`);
    await fail("builder_unreachable");
    return;
  }
  const previous = vulnDbBuildReportSchema.safeParse(await readReport("vulndb_build"));
  await writeReport("vulndb_build", buildReportOf(status, previous.success ? previous.data : null));
  if (status.state === "running") {
    await fail("timeout");
    return;
  }
  if (status.state !== "succeeded" || !status.archive) {
    console.error(
      `vulndb build: no database was built (${status.reason ?? "unknown"}); scans keep the current one`,
    );
    await fail(reasonOfBuild(status.reason));
    return;
  }
  const current = vulnDbReportSchema.safeParse(await readReport("vulndb"));
  const built = status.archive.built ? Date.parse(status.archive.built) : Number.NaN;
  if (
    current.success &&
    current.data.valid &&
    current.data.builtAt &&
    Date.parse(current.data.builtAt) === built
  ) {
    return; // already imported (a restart took over the last build)
  }
  const path = await verifiedArchive(status.archive, env.GARNETOPS_VULNDB_BUILDS_DIR);
  if (!path) {
    console.error("vulndb build: the archive failed its checks and was not imported");
    await fail("archive_rejected");
    return;
  }
  try {
    await importArchive(path);
  } catch (error) {
    console.error(`vulndb build: grype could not import the archive: ${(error as Error).message}`);
    await fail("archive_rejected");
    return;
  }
  console.log(`vulndb build: imported ${status.archive.file}`);
  await reportVulnDbUpdate({
    mode: "build",
    lastAttemptAt: attemptedAt,
    lastSuccessAt: new Date().toISOString(),
    lastResult: "ok",
    reason: null,
    nextAt,
  });
  // The early warnings follow the database's build time (ADR 0029), which the probe reads.
  await probeVulnDb();
}

/**
 * How long to wait before the first build after the worker starts: none, unless the builder finished one less than a
 * day ago (a restart, an update). That build is taken over instead (imported if it is new), and the next one follows
 * a day after it; a build still running is followed.
 */
export function firstBuildPlan(
  status: BuilderStatus | null,
  now: number,
): { follow: boolean; waitMs: number } {
  if (status?.state === "running") return { follow: true, waitMs: 0 };
  const finished =
    status?.state === "succeeded" && status.finishedAt ? Date.parse(status.finishedAt) : Number.NaN;
  const age = now - finished;
  return age >= 0 && age < INTERVAL_MS
    ? { follow: true, waitMs: INTERVAL_MS - age }
    : { follow: false, waitMs: 0 };
}

/** Builds at start (see `firstBuildPlan`) and then once a day, as long as the worker runs. */
export function startVulnDbBuilds(): () => void {
  const controller = new AbortController();
  const announced = reportVulnDbUpdate({ mode: "build", nextAt: new Date().toISOString() });
  void (async () => {
    await announced;
    const plan = firstBuildPlan(await builderStatus().catch(() => null), Date.now());
    if (plan.follow) {
      await buildOnce(controller.signal, { start: false, nextInMs: plan.waitMs });
      await sleep(plan.waitMs, controller.signal);
    }
    while (!controller.signal.aborted) {
      await buildOnce(controller.signal);
      await sleep(INTERVAL_MS, controller.signal);
    }
  })();
  return () => controller.abort();
}
