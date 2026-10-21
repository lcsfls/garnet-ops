/**
 * Creates the vault key pair of a container installation once (ADR 0004): the public
 * key for the API, the private key for the worker only. Runs as the `init` service of
 * the Compose stack before API and worker start; an existing pair is never replaced,
 * because every stored secret is sealed to it.
 *
 *   node apps/worker/src/init-vault.ts /vault
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateVaultKeyPair } from "@garnetops/core/vault";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: init-vault.ts <directory>");
  process.exit(64);
}
const publicFile = join(dir, "public", "vault.pub.pem");
const privateFile = join(dir, "private", "vault.key.pem");

if (existsSync(publicFile) && existsSync(privateFile)) {
  console.log("init: vault key pair present");
} else if (existsSync(publicFile) || existsSync(privateFile)) {
  // Half a pair cannot be repaired: a new key would orphan every sealed secret.
  console.error("init: only one half of the vault key pair exists; restore the other half from the backup");
  process.exit(1);
} else {
  const pair = generateVaultKeyPair();
  mkdirSync(join(dir, "public"), { recursive: true, mode: 0o755 });
  mkdirSync(join(dir, "private"), { recursive: true, mode: 0o700 });
  writeFileSync(privateFile, pair.privateKeyPem, { mode: 0o600, flag: "wx" });
  writeFileSync(publicFile, pair.publicKeyPem, { mode: 0o644, flag: "wx" });
  console.log(`init: created vault key pair ${pair.id}`);
}
