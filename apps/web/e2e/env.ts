/**
 * Environment for the end-to-end run: the development settings from
 * .data/dev.env (created by `pnpm dev`), but a separate, throw-away database
 * and separate ports, so the run never touches development data.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const devEnvFile = fileURLToPath(new URL("../../../.data/dev.env", import.meta.url));

function readDevEnv(): Record<string, string> {
  try {
    return Object.fromEntries(
      readFileSync(devEnvFile, "utf8")
        .split("\n")
        .filter((l) => l && !l.startsWith("#"))
        .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim()]),
    );
  } catch {
    throw new Error("Missing .data/dev.env: run `pnpm dev` once to create the development environment.");
  }
}

const dev = readDevEnv();
const devDb = new URL(dev.DATABASE_URL ?? "");
const e2eDb = new URL(devDb);
e2eDb.pathname = "/garnetops_e2e";

export const E2E = {
  webPort: 5174,
  apiPort: 3001,
  publicUrl: "http://localhost:5174",
  /** Fixed token so the test can complete first-run setup. Only valid for this throw-away database. */
  setupToken: "e2e-setup-token-not-a-secret",
  /** The fake update sidecar (fake-updater.ts) and the token file it shares with the API. */
  updaterPort: 8091,
  /** The fake OpenAI-compatible model server (apps/worker/test/e2e-ai-worker.ts), which also runs the AI jobs. */
  modelPort: 8092,
  /** The fake Gitea/Forgejo server and its control server (apps/worker/test/e2e-forge-worker.ts). */
  forgePort: 8093,
  forgeControlPort: 8094,
  updaterTokenFile: fileURLToPath(new URL("./.state/updater-token", import.meta.url)),
  /** The owner's TOTP secret, saved by the sign-in flow for later step-up tests (throw-away database). */
  totpSecretFile: fileURLToPath(new URL("./.state/totp-secret", import.meta.url)),
  adminDatabaseUrl: devDb.toString(),
  databaseUrl: e2eDb.toString(),
  dev,
};
