import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { env } from "./env.ts";
import { run } from "./run.ts";

const DAY_MS = 24 * 3600 * 1000;

/**
 * Keeps the local vulnerability database current when GARNETOPS_GRYPE_DB_UPDATE=auto:
 * once at start and then once a day, with `grype db update` (Anchore's published
 * database, checked by grype against its signed listing). Off by default, so air-gapped
 * installations import the database themselves and nothing phones home unless the
 * operator chose it (AGENTS.md rule 1). Replaced by our own vunnel build later (ROADMAP).
 *
 * A failed update is logged and scans keep using the database that is there.
 */
export function startVulnDbUpdates(): () => void {
  if (env.GARNETOPS_GRYPE_DB_UPDATE !== "auto") return () => {};
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;

  const update = async () => {
    const home = join(env.GARNETOPS_WORK_DIR, "vulndb-home");
    await mkdir(home, { recursive: true });
    const started = performance.now();
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
    } catch (error) {
      console.error(`vulndb: update failed, scans keep the current database: ${(error as Error).message}`);
    }
  };

  const loop = () => {
    void update().finally(() => {
      if (stopped) return;
      timer = setTimeout(loop, DAY_MS);
      timer.unref();
    });
  };
  loop();
  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}
