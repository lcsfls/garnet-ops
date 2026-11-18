import { createHash, randomBytes } from "node:crypto";

/** Inventory tokens start with this, so secret scanners and people recognise them (ADR 0053). */
export const INVENTORY_TOKEN_PREFIX = "goi_";

/** A new inventory token: shown once, only its hash is stored. */
export function newInventoryToken(): { token: string; hash: string; prefix: string } {
  const token = `${INVENTORY_TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  return {
    token,
    hash: hashInventoryToken(token),
    prefix: token.slice(0, INVENTORY_TOKEN_PREFIX.length + 6),
  };
}

/** SHA-256 is enough: the token has 256 random bits, so there is nothing to brute-force. */
export function hashInventoryToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** The token from an `Authorization: Bearer goi_…` header, or null. */
export function bearerInventoryToken(header: string | undefined): string | null {
  const match = /^Bearer\s+(goi_[A-Za-z0-9_-]{43})$/.exec(header ?? "");
  return match?.[1] ?? null;
}
