/** Certificate helpers shared by the directory sign-in (ADR 0020): fingerprints in the form browsers show. */
import { createHash } from "node:crypto";

// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** SHA-256 of a DER certificate as browsers show it: upper-case hex pairs separated by colons. */
export function certificateFingerprint(der: Uint8Array): string {
  return (createHash("sha256").update(der).digest("hex").toUpperCase().match(/../g) as string[]).join(":");
}

export const FINGERPRINT_PATTERN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

/** Upper-cases a fingerprint an admin or an API client sent; null if it is not SHA-256 in colon form. */
export function normalizeFingerprint(value: string): string | null {
  const f = value.trim().toUpperCase();
  return FINGERPRINT_PATTERN.test(f) ? f : null;
}

/** Subject or issuer of a certificate on one line, without control characters, at most 300 characters. */
export function certificateName(value: string | undefined): string {
  return (value ?? "")
    .replace(CONTROL, "")
    .trim()
    .slice(0, 300)
    .replace(/\s*\n\s*/g, ", ");
}
