import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { redactGitleaksReport } from "@garnetops/core/secret-fingerprint";
import { gitleaksArgs, gitleaksConfig } from "@garnetops/core/secrets";
import { SCANNER_TIMEOUT_MS } from "./grype-run.ts";
import { run } from "./run.ts";

/** What a secret scan hands to the worker: gitleaks' reports with every value replaced by its SHA-256 (ADR 0049). */
export interface SecretReports {
  /** The scanned commit's files. */
  tree: unknown[];
  /** Every commit the clone has; null unless asked for. */
  history: unknown[] | null;
}

/**
 * Runs gitleaks on a clone with GarnetOps' own configuration, never the repository's, and returns the path of the redacted
 * result in `outDir`. The raw reports, which hold the values, are deleted as soon as they are read. Shared by the worker and the
 * scanner service (ADR 0028), like grype.
 */
export async function runGitleaks(
  bin: string,
  dir: string,
  outDir: string,
  opts: { history: boolean },
): Promise<string> {
  const config = join(outDir, "gitleaks.toml");
  const empty = join(outDir, "no-ignore");
  await writeFile(config, gitleaksConfig(), { mode: 0o600 });
  await mkdir(empty, { recursive: true });
  const env = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: outDir,
    USERPROFILE: outDir,
    TMP: outDir,
    TEMP: outDir,
    // History mode runs `git log`: no system or user configuration, no prompts, nothing from the repository's own hooks.
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: join(outDir, "no-gitconfig"),
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
  };

  const scan = async (mode: "dir" | "git", name: string): Promise<unknown[]> => {
    const raw = join(outDir, `${name}.raw.json`);
    try {
      const extra = mode === "git" ? ["--log-opts=--all"] : [];
      await run(
        bin,
        [mode, dir, ...extra, ...gitleaksArgs({ configPath: config, emptyDir: empty, reportPath: raw })],
        { env, timeoutMs: SCANNER_TIMEOUT_MS },
      );
      return JSON.parse(redactGitleaksReport(await readFile(raw, "utf8"))) as unknown[];
    } finally {
      await rm(raw, { force: true });
    }
  };

  const reports: SecretReports = { tree: await scan("dir", "tree"), history: null };
  if (opts.history) reports.history = await scan("git", "history");
  const out = join(outDir, "secrets.json");
  await writeFile(out, JSON.stringify(reports), { mode: 0o600 });
  return out;
}
