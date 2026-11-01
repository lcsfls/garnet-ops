/**
 * Scan on push (ADR 0045): what a webhook delivery from GitHub, Gitea or Forgejo means. Pure functions, so the API route stays
 * small and every case is tested here. A delivery is hostile until its signature matches: nothing of it is read before.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

/** At most this much is read of a delivery; a push with many commits stays far below it. */
export const MAX_WEBHOOK_BODY_BYTES = 5 * 1024 * 1024;

/** The result of one delivery, as kept for the setup and returned to the forge. Codes only. */
export const WEBHOOK_RESULTS = [
  "scan-queued",
  "already-queued",
  "ping",
  "ignored-event",
  "ignored-branch",
  "ignored-delete",
  "inactive",
  "unreadable",
  "bad-signature",
  "rate-limited",
] as const;
export type WebhookResult = (typeof WEBHOOK_RESULTS)[number];

/** Base64url of 32 random bytes: the shared secret shown once. */
export const WEBHOOK_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface WebhookHeaders {
  /** The event name the forge sends, e.g. "push" or "ping"; null when none is named. */
  event: string | null;
  /** The HMAC-SHA256 of the body as lower-case hex; null when the delivery is not signed. */
  signature: string | null;
}

/**
 * The event and signature of a delivery. GitHub sends `X-GitHub-Event` and `X-Hub-Signature-256: sha256=<hex>`; Gitea and
 * Forgejo send their own `X-Gitea-*` / `X-Forgejo-*` headers (and newer versions the GitHub ones as well).
 */
export function webhookHeaders(get: (name: string) => string | undefined | null): WebhookHeaders {
  const event = (get("x-github-event") ?? get("x-gitea-event") ?? get("x-forgejo-event") ?? "")
    .trim()
    .toLowerCase();
  const hub = get("x-hub-signature-256")?.trim();
  const raw = hub?.toLowerCase().startsWith("sha256=")
    ? hub.slice("sha256=".length)
    : (get("x-gitea-signature") ?? get("x-forgejo-signature") ?? "").trim();
  const signature = /^[0-9a-fA-F]{64}$/.test(raw) ? raw.toLowerCase() : null;
  return { event: /^[a-z_]{1,40}$/.test(event) ? event : null, signature };
}

/** Whether `signature` is the HMAC-SHA256 of `body` with `secret`, compared in constant time. */
export function signatureMatches(secret: string, body: Uint8Array, signature: string | null): boolean {
  if (!signature) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  const given = Buffer.from(signature, "hex");
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/**
 * What a signed delivery asks for. A push starts a scan only when it updates the branch GarnetOps scans: the repository's
 * branch, or, when it follows the default branch, the default branch the forge names in the payload. A branch that was
 * deleted starts nothing.
 */
export function webhookIntent(
  event: string | null,
  payload: unknown,
  monitoredBranch: string | null,
):
  | "scan"
  | Exclude<WebhookResult, "scan-queued" | "already-queued" | "inactive" | "bad-signature" | "rate-limited"> {
  if (event === "ping") return "ping";
  if (event !== "push") return "ignored-event";
  if (typeof payload !== "object" || payload === null) return "unreadable";
  const p = payload as { ref?: unknown; deleted?: unknown; repository?: { default_branch?: unknown } };
  if (typeof p.ref !== "string" || !p.ref.startsWith("refs/")) return "unreadable";
  if (p.deleted === true) return "ignored-delete";
  const branch =
    monitoredBranch ??
    (typeof p.repository?.default_branch === "string" ? p.repository.default_branch : null);
  if (!branch) return "unreadable";
  return p.ref === `refs/heads/${branch}` ? "scan" : "ignored-branch";
}
