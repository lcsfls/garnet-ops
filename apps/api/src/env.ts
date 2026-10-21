import { readFileSync } from "node:fs";
import { loadVaultPublicKey } from "@garnetops/core/vault";
import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("production"),
  /** Bind address. Loopback by default; the container image sets 0.0.0.0 behind the reverse proxy. */
  HOST: z.string().default("127.0.0.1"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  /** Public URL of the web app, e.g. https://garnetops.example.com. Used for cookies and origin checks. */
  PUBLIC_URL: z.string().url(),
  DATABASE_URL: z.string().min(1),
  /** At least 32 random characters. Signs sessions and encrypts better-auth's TOTP secrets. */
  BETTER_AUTH_SECRET: z.string().min(32, "BETTER_AUTH_SECRET must be at least 32 characters"),
  /** PEM file with the vault public key. The API can seal secrets but never open them (ADR 0004). */
  GARNETOPS_VAULT_PUBLIC_KEY_FILE: z.string().min(1),
  /**
   * Optional update sidecar (cicd-updater, ADR 0007), e.g. http://updater:8090. Empty or
   * unset: in-app updates are off and the Updates page shows the manual steps.
   */
  UPDATER_URL: z
    .string()
    .trim()
    .default("")
    .refine((v) => v === "" || /^https?:\/\/[^\s/]+/.test(v), "UPDATER_URL must be an http(s) URL or empty"),
  /** The sidecar's shared token, mounted read-only into the API container only. */
  UPDATER_TOKEN_FILE: z.string().min(1).default("/run/cicd-updater/token"),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Print only variable names and messages, never values.
  for (const issue of parsed.error.issues) console.error(`config: ${issue.path.join(".")}: ${issue.message}`);
  process.exit(1);
}

export const env = parsed.data;
export const isProduction = env.NODE_ENV === "production";
export const vaultPublicKey = loadVaultPublicKey(readFileSync(env.GARNETOPS_VAULT_PUBLIC_KEY_FILE, "utf8"));
