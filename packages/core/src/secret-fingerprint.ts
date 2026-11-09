import { createHmac } from "node:crypto";

/**
 * The keyed fingerprint of a found secret (ADR 0049): HMAC-SHA-256 with the organisation's own fingerprint key, cut to 128 bits.
 * It tells whether the same secret turns up again (in another file, another commit, a later scan) without keeping anything that
 * leads back to the value: without the key, a fingerprint cannot be checked against a guess. A rule about a whole file has no
 * value; its fingerprint covers the rule and the path instead.
 */
export function secretFingerprint(key: Uint8Array, ruleId: string, secret: string, path: string): string {
  if (key.length < 32) throw new Error("fingerprint key too short");
  const input = secret ? `v\u0000${secret}` : `f\u0000${ruleId}\u0000${path}`;
  return createHmac("sha256", key).update(input, "utf8").digest().subarray(0, 16).toString("base64url");
}
