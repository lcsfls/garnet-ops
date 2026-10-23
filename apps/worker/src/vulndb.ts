import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { VULNDB_UPDATE_INTERVAL_HOURS, vulnDbUpdateReason } from "@garnetops/core/system-status";
import { env } from "./env.ts";
import { CommandError, run } from "./run.ts";
import { probeVulnDb, reportVulnDbUpdate } from "./system-report.ts";

const INTERVAL_MS = VULNDB_UPDATE_INTERVAL_HOURS * 3600 * 1000;

/**
 * Keeps the local vulnerability database current when GARNETOPS_GRYPE_DB_UPDATE=auto:
 * once at start and then once a day, with `grype db update` (Anchore's published
 * database, checked by grype against its signed listing). Off by default, so air-gapped
 * installations import the database themselves and nothing phones home unless the
 * operator chose it (AGENTS.md rule 1). Replaced by our own vunnel build later (ROADMAP).
 *
 * A failed update is logged and scans keep using the database that is there. Every attempt
 * is reported for the System status page (ADR 0024) as a time, a result and a short code.
 */
export function startVulnDbUpdates(): () => void {
  if (env.GARNETOPS_GRYPE_DB_UPDATE !== "auto") {
    void reportVulnDbUpdate({ mode: "off", nextAt: null });
    return () => {};
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;

  // The first attempt starts at once; until it ends, the next one is "now". The attempt waits for this write.
  const announced = reportVulnDbUpdate({ mode: "auto", nextAt: new Date().toISOString() });

  const update = async () => {
    await announced;
    const home = join(env.GARNETOPS_WORK_DIR, "vulndb-home");
    await mkdir(home, { recursive: true });
    const started = performance.now();
    const attemptedAt = new Date();
    try {
      await run(env.GARNETOPS_GRYPE_BIN, ["db", "update"], {
        env: {
          PATH: process.env.PATH,
          HOME: home,
          TMP: home,
          TEMP: home,
          GRYPE_DB_CACHE_DIR: env.GARNETOPS_GRYPE_DB_DIR,
          GRYPE_CHECK_FOR_APP_UPDATE: "false",
          // Proxy settings of the container apply to the download.
          ...(process.env.HTTPS_PROXY ? { HTTPS_PROXY: process.env.HTTPS_PROXY } : {}),
          ...(process.env.NO_PROXY ? { NO_PROXY: process.env.NO_PROXY } : {}),
        },
        timeoutMs: 30 * 60_000,
      });
      console.log(`vulndb: updated in ${Math.round((performance.now() - started) / 1000)} s`);
      await reportVulnDbUpdate({
        mode: "auto",
        lastAttemptAt: attemptedAt.toISOString(),
        lastSuccessAt: new Date().toISOString(),
        lastResult: "ok",
        reason: null,
        nextAt: new Date(Date.now() + INTERVAL_MS).toISOString(),
      });
    } catch (error) {
      console.error(`vulndb: update failed, scans keep the current database: ${(error as Error).message}`);
      await reportVulnDbUpdate({
        mode: "auto",
        lastAttemptAt: attemptedAt.toISOString(),
        lastResult: "failed",
        reason: vulnDbUpdateReason(
          error instanceof CommandError ? error : { message: (error as Error)?.message },
        ),
        nextAt: new Date(Date.now() + INTERVAL_MS).toISOString(),
      });
    }
    // The metadata changes with a new database and is cheap to read again either way.
    await probeVulnDb();
  };

  const loop = () => {
    void update().finally(() => {
      if (stopped) return;
      timer = setTimeout(loop, INTERVAL_MS);
      timer.unref();
    });
  };
  loop();
  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}
