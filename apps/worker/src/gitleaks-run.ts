import { lstat, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { cleanRepoGitleaksConfig, REPO_GITLEAKS_IGNORE_FILE } from "@garnetops/core/repo-gitleaks";
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
  /**
   * The repository run (ADR 0049 addendum 2026-11-12), only when the repository's configuration was handed in: the same, with the
   * repository's configuration, ignore file and `gitleaks:allow` comments. `problem` says why it did not run.
   */
  repo?: { tree: unknown[]; history: unknown[] | null; problem: string | null };
}

/** The repository's own files, as the worker read them from its clone before the ignore file was removed. */
export interface RepoGitleaksFiles {
  config: string | null;
  ignore: string | null;
}

/**
 * gitleaks reads a `.gitleaksignore` from the scanned directory as well as from `--gitleaks-ignore-path`, and its entries (file,
 * history and absolute fingerprints alike) hide findings. A repository's own file must never do that (ADR 0049), so it is removed
 * from the clone before every run, and the run refuses to start if it is still there.
 */
export async function removeRepositoryIgnoreFile(dir: string): Promise<void> {
  const file = join(dir, ".gitleaksignore");
  await rm(file, { recursive: true, force: true });
  const left = await lstat(file).then(
    () => true,
    () => false,
  );
  if (left) throw new Error("The repository's .gitleaksignore could not be removed from the clone");
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
  opts: { history: boolean; repo?: RepoGitleaksFiles | null },
): Promise<string> {
  await removeRepositoryIgnoreFile(dir);
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

  const scan = async (
    mode: "dir" | "git",
    name: string,
    repository?: { configPath: string; ignoreDir: string },
  ): Promise<unknown[]> => {
    const raw = join(outDir, `${name}.raw.json`);
    try {
      const extra = mode === "git" ? ["--log-opts=--all"] : [];
      const args = gitleaksArgs({
        configPath: repository?.configPath ?? config,
        emptyDir: repository?.ignoreDir ?? empty,
        reportPath: raw,
        repository: Boolean(repository),
      });
      // The repository run reads the clone from inside it, so that paths in its .gitleaksignore (file mode) match.
      await run(bin, [mode, repository && mode === "dir" ? "." : dir, ...extra, ...args], {
        env,
        timeoutMs: SCANNER_TIMEOUT_MS,
        ...(repository ? { cwd: dir } : {}),
      });
      return JSON.parse(redactGitleaksReport(await readFile(raw, "utf8"))) as unknown[];
    } finally {
      await rm(raw, { force: true });
    }
  };

  const reports: SecretReports = { tree: await scan("dir", "tree"), history: null };
  if (opts.history) reports.history = await scan("git", "history");
  if (opts.repo) {
    // Anything wrong here sets nothing aside: the strict result above stands, and the problem is reported.
    let problem: string | null = null;
    const cleaned = opts.repo.config === null ? { config: "" } : cleanRepoGitleaksConfig(opts.repo.config);
    if ("problem" in cleaned) problem = cleaned.problem;
    else {
      try {
        const repoCopy = join(outDir, "repository-gitleaks.toml");
        const merged = join(outDir, "gitleaks-with-repository.toml");
        const ignoreDir = join(outDir, "repository-ignore");
        await writeFile(repoCopy, cleaned.config || "[extend]\nuseDefault = true\n", { mode: 0o600 });
        await writeFile(merged, gitleaksConfig({ extendPath: repoCopy }), { mode: 0o600 });
        await mkdir(ignoreDir, { recursive: true });
        if (opts.repo.ignore !== null) {
          await writeFile(join(ignoreDir, REPO_GITLEAKS_IGNORE_FILE), opts.repo.ignore, { mode: 0o600 });
        }
        const repository = { configPath: merged, ignoreDir };
        const tree = await scan("dir", "repository-tree", repository);
        const history = opts.history ? await scan("git", "repository-history", repository) : null;
        reports.repo = { tree, history, problem: null };
      } catch (error) {
        console.error(`gitleaks with the repository's configuration: ${(error as Error).message}`);
        problem = "failed";
      }
    }
    if (problem) reports.repo = { tree: [], history: null, problem };
  }
  const out = join(outDir, "secrets.json");
  await writeFile(out, JSON.stringify(reports), { mode: 0o600 });
  return out;
}
