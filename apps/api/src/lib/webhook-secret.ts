/**
 * The shared secret of a repository webhook (ADR 0045), encrypted for the API itself: AES-256-GCM with a key derived from
 * BETTER_AUTH_SECRET by HKDF (the key is never stored), bound to the webhook's id as associated data, so a sealed secret
 * copied to another row does not open. The API needs the secret to check each delivery's HMAC; nothing else can use it, and
 * all it can do is ask for a scan of its repository. Changing BETTER_AUTH_SECRET makes every webhook need a new secret.
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { env } from "../env.ts";

const VERSION = "v1";
let cached: Buffer | null = null;

/** The key for webhook secrets derived from a session secret; a restore (ADR 0046) needs the one of the old installation. */
export function webhookKeyFrom(authSecret: string): Buffer {
  return Buffer.from(hkdfSync("sha256", authSecret, "garnetops", "repository webhook secrets v1", 32));
}

function key(): Buffer {
  cached ??= webhookKeyFrom(env.BETTER_AUTH_SECRET);
  return cached;
}

/** A new secret to show once: 32 random bytes, base64url. */
export function newWebhookSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function sealWebhookSecret(secret: string, webhookId: string, withKey: Buffer = key()): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", withKey, iv);
  cipher.setAAD(Buffer.from(webhookId));
  const sealed = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return `${VERSION}.${Buffer.concat([iv, sealed, cipher.getAuthTag()]).toString("base64url")}`;
}

/** The secret, or null when it does not open (another key, another row, or damaged). */
export function openWebhookSecret(sealed: string, webhookId: string, withKey: Buffer = key()): string | null {
  const [version, data] = sealed.split(".");
  if (version !== VERSION || !data) return null;
  const raw = Buffer.from(data, "base64url");
  if (raw.length < 12 + 16 + 1) return null;
  try {
    const decipher = createDecipheriv("aes-256-gcm", withKey, raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(webhookId));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString(
      "utf8",
    );
  } catch {
    return null;
  }
}
