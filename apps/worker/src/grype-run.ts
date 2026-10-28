import { join } from "node:path";
import { run } from "./run.ts";

/** Upper bound for one syft or grype run. */
export const SCANNER_TIMEOUT_MS = 15 * 60_000;

/**
 * Runs grype against an SBOM file (`sbom:<path>`) or a directory (`dir:<path>`) and returns the
 * path of its JSON report in `outDir`. Never updates the database itself (that is a separate job)
 * and reads no configuration of its own, so the worker and the scanner service (ADR 0028) share it.
 */
export async function runGrype(bin: string, dbDir: string, target: string, outDir: string): Promise<string> {
  const out = join(outDir, "grype.json");
  await run(bin, [target, "-o", "json", "--file", out, "-q"], {
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      HOME: outDir,
      USERPROFILE: outDir,
      TMP: outDir,
      TEMP: outDir,
      GRYPE_DB_CACHE_DIR: dbDir,
      GRYPE_DB_AUTO_UPDATE: "false",
      GRYPE_CHECK_FOR_APP_UPDATE: "false",
      GRYPE_DB_VALIDATE_AGE: "false",
    },
    timeoutMs: SCANNER_TIMEOUT_MS,
  });
  return out;
}
