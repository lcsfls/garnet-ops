import { createHash, randomBytes } from "node:crypto";

/** Gate tokens start with this, so secret scanners and people recognise them. */
export const GATE_TOKEN_PREFIX = "gog_";

/** A new gate token: shown once, only its hash is stored (ADR 0008). */
export function newGateToken(): { token: string; hash: string; prefix: string } {
  const token = `${GATE_TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  return { token, hash: hashGateToken(token), prefix: token.slice(0, GATE_TOKEN_PREFIX.length + 6) };
}

/** SHA-256 is enough: the token has 256 random bits, so there is nothing to brute-force. */
export function hashGateToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** The token from an `Authorization: Bearer gog_…` header, or null. */
export function bearerGateToken(header: string | undefined): string | null {
  const match = /^Bearer\s+(gog_[A-Za-z0-9_-]{43})$/.exec(header ?? "");
  return match?.[1] ?? null;
}
