/**
 * Entry point of the scanner service (ADR 0028). It reads only its own configuration: it never
 * loads the worker's, which names the database and the vault key.
 *
 *   node apps/worker/src/scanner.ts           serve on GARNETOPS_SCANNER_SOCKET
 *   node apps/worker/src/scanner.ts health    exit 0 when the service answers (container health check)
 */
import { chmod, mkdir, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";
import { scannerHealth } from "./scanner-client.ts";
import { createScannerService } from "./scanner-service.ts";

const schema = z.object({
  /** The Unix socket the service listens on, on a volume shared with the worker. */
  GARNETOPS_SCANNER_SOCKET: z.string().min(1),
  /** The clones, on a volume the worker writes and this service only reads. */
  GARNETOPS_SCANNER_WORK_DIR: z.string().min(1),
  GARNETOPS_GRYPE_BIN: z.string().min(1),
  GARNETOPS_SYFT_BIN: z.string().min(1),
  GARNETOPS_GRYPE_DB_DIR: z.string().min(1),
  GARNETOPS_SCAN_CONCURRENCY: z.coerce.number().int().min(1).max(16).default(2),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  for (const issue of parsed.error.issues) console.error(`config: ${issue.path.join(".")}: ${issue.message}`);
  process.exit(1);
}
const env = parsed.data;

if (process.argv[2] === "health") {
  process.exit((await scannerHealth(env.GARNETOPS_SCANNER_SOCKET)) ? 0 : 1);
}

const server = createScannerService({
  workDir: env.GARNETOPS_SCANNER_WORK_DIR,
  grypeBin: env.GARNETOPS_GRYPE_BIN,
  syftBin: env.GARNETOPS_SYFT_BIN,
  grypeDbDir: env.GARNETOPS_GRYPE_DB_DIR,
  concurrency: env.GARNETOPS_SCAN_CONCURRENCY,
  version: process.env.APP_VERSION ?? null,
});

const socket = env.GARNETOPS_SCANNER_SOCKET;
await mkdir(dirname(socket), { recursive: true });
// A socket left behind by an earlier run of this container would block listen().
await rm(socket, { force: true });
server.listen(socket, async () => {
  // Only this user (the worker runs as the same one) may connect.
  await chmod(socket, 0o600);
  console.log(`scanner: listening, ${env.GARNETOPS_SCAN_CONCURRENCY} runs at once`);
});

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    server.close(() => process.exit(0));
    // Running scans are not waited for: the worker records them as failed.
    setTimeout(() => process.exit(0), 2_000).unref();
  });
}
