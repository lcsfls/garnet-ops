import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadVaultPrivateKey } from "@garnetops/core/vault";
import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("production"),
  DATABASE_URL: z.string().min(1),
  /** PEM file with the vault private key. Mounted only into the worker (ADR 0004). */
  GARNETOPS_VAULT_PRIVATE_KEY_FILE: z.string().min(1),
  /** Path to the grype binary. */
  GARNETOPS_GRYPE_BIN: z.string().min(1),
  /**
   * Path to the syft binary. With it every scan stores the repository's full package
   * inventory and grype matches that SBOM; without it grype scans the directory itself
   * and only vulnerable packages are known.
   */
  GARNETOPS_SYFT_BIN: z.string().min(1).optional(),
  /** Directory of the local vulnerability database. */
  GARNETOPS_GRYPE_DB_DIR: z.string().min(1),
  /**
   * The worker's private scratch directory (deploy keys, git's HOME, scanner output) and, without the
   * scanner service, the clones. Every scan gets its own subdirectory, removed afterwards.
   */
  GARNETOPS_WORK_DIR: z.string().default(join(tmpdir(), "garnetops-work")),
  GARNETOPS_SCAN_CONCURRENCY: z.coerce.number().int().min(1).max(16).default(2),
  /**
   * Unix socket of the scanner service (ADR 0028). Set: syft and grype run there, without network,
   * vault key or database. Unset (a compose file older than 0.0.9): they run in the worker, as before.
   */
  GARNETOPS_SCANNER_SOCKET: z.string().min(1).optional(),
  /**
   * With the scanner service: where the worker clones repositories, on a volume the service mounts
   * read-only at the same path. Nothing else of a scan is written there.
   */
  GARNETOPS_SCANNER_WORK_DIR: z.string().min(1).optional(),
  /**
   * "auto": the worker updates the vulnerability database at start and daily (needs
   * outbound HTTPS to Anchore). "off" (default): the operator imports it, e.g. air-gapped.
   */
  GARNETOPS_GRYPE_DB_UPDATE: z.enum(["auto", "off"]).default("off"),
  /** The address users open; links in notifications point here (ADR 0010). */
  PUBLIC_URL: z.string().url().optional(),
  /** Upper bound for a cloned repository on disk. */
  GARNETOPS_MAX_REPO_MB: z.coerce.number().int().min(10).max(20_000).default(2048),
});

const parsed = schema
  .refine((v) => Boolean(v.GARNETOPS_SCANNER_SOCKET) === Boolean(v.GARNETOPS_SCANNER_WORK_DIR), {
    path: ["GARNETOPS_SCANNER_WORK_DIR"],
    message: "set together with GARNETOPS_SCANNER_SOCKET, or neither",
  })
  .safeParse(process.env);
if (!parsed.success) {
  for (const issue of parsed.error.issues) console.error(`config: ${issue.path.join(".")}: ${issue.message}`);
  process.exit(1);
}

export const env = parsed.data;
export const vaultPrivateKey = loadVaultPrivateKey(
  readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"),
);
