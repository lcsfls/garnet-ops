import { createHash, createHmac } from "node:crypto";
import { isSensitiveFileRule, SECRET_LIMITS } from "./secrets.ts";

/**
 * The keyed fingerprint of a found secret (ADR 0049): HMAC-SHA-256 with the organisation's own fingerprint key, cut to 128 bits.
 * It tells whether the same secret turns up again (in another file, another commit, a later scan) without keeping anything that
 * leads back to the value: without the key, a fingerprint cannot be checked against a guess. `secret` is what
 * `redactGitleaksReport` left of the value (its SHA-256), never the value itself. A rule about a whole file has no value; its
 * fingerprint covers the rule and the path instead.
 */
export function secretFingerprint(key: Uint8Array, ruleId: string, secret: string, path: string): string {
  if (key.length < 32) throw new Error("fingerprint key too short");
  const input = secret ? `v\u0000${secret}` : `f\u0000${ruleId}\u0000${path}`;
  return createHmac("sha256", key).update(input, "utf8").digest().subarray(0, 16).toString("base64url");
}

/**
 * Rewrites gitleaks' JSON report before it leaves the scanner (ADR 0049): the secret becomes its SHA-256 (empty for rules about a
 * whole file), and only rule, file, line, commit and date are kept. The matched text, the commit author, e-mail and message, and
 * gitleaks' own fingerprint are dropped. The worker never receives a value.
 */
export function redactGitleaksReport(text: string): string {
  if (text.length > SECRET_LIMITS.maxReportBytes) throw new Error("secret report too large");
  const trimmed = text.trim();
  const data: unknown = trimmed === "" ? [] : JSON.parse(trimmed);
  if (!Array.isArray(data)) throw new Error("secret report is not a list");
  const out = (data as unknown[]).map((entry) => {
    const e = (entry ?? {}) as Record<string, unknown>;
    const ruleId = typeof e.RuleID === "string" ? e.RuleID : "";
    const secret = typeof e.Secret === "string" && e.Secret && !isSensitiveFileRule(ruleId) ? e.Secret : "";
    return {
      RuleID: ruleId,
      File: typeof e.File === "string" ? e.File : "",
      StartLine: typeof e.StartLine === "number" ? e.StartLine : 0,
      Commit: typeof e.Commit === "string" ? e.Commit : "",
      Date: typeof e.Date === "string" ? e.Date : "",
      Secret: secret ? createHash("sha256").update(secret, "utf8").digest("hex") : "",
    };
  });
  return JSON.stringify(out);
}
