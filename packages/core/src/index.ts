/**
 * Domain types and helpers shared by API, worker and web.
 * Keep this file free of Node-only imports: the web app imports it too.
 */
import { z } from "zod";

export const SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const severitySchema = z.enum(SEVERITIES);

/** Higher number = worse. Used for sorting "worst first". */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  negligible: 1,
  unknown: 0,
};

export const FINDING_STATES = ["open", "accepted", "resolved"] as const;
export type FindingState = (typeof FINDING_STATES)[number];
export const findingStateSchema = z.enum(FINDING_STATES);

export const SCAN_STATES = ["queued", "running", "succeeded", "failed"] as const;
export type ScanState = (typeof SCAN_STATES)[number];

export const REPO_AUTH_KINDS = ["none", "https-token", "ssh-deploy-key"] as const;
export type RepoAuthKind = (typeof REPO_AUTH_KINDS)[number];

export const ROLES = ["owner", "admin", "member", "viewer"] as const;
export type Role = (typeof ROLES)[number];

/** RFC 9457 problem details, the error body of every API error. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  /** Field errors for validation problems. */
  errors?: { path: string; message: string }[];
  /** Further extension members (RFC 9457, section 3.2), e.g. the blockers of a refused update. */
  [extension: string]: unknown;
}

/**
 * Accepts only repository URLs we know how to clone safely.
 * No local paths, no `file://`, no `ext::` transports, no credentials in the URL.
 */
export const repoUrlSchema = z
  .string()
  .trim()
  .max(500)
  .refine((value) => {
    if (/^(https:\/\/)/i.test(value)) {
      try {
        const url = new URL(value);
        return !url.username && !url.password && url.hostname.length > 0;
      } catch {
        return false;
      }
    }
    // scp-like SSH syntax (git@host:owner/repo.git) or ssh:// URLs
    // Every segment must start with a letter or digit, so nothing can be read as a command-line option.
    const seg = /[A-Za-z0-9][\w.-]*/.source;
    const path = /[A-Za-z0-9_~][\w./~-]*/.source;
    return (
      new RegExp(`^ssh://(${seg}@)?${seg}(:[0-9]{1,5})?/${path}$`).test(value) ||
      new RegExp(`^${seg}@${seg}:${path}$`).test(value)
    );
  }, "Use an https:// or SSH repository URL without credentials in it");

export function isSshRepoUrl(url: string): boolean {
  return !/^https:\/\//i.test(url);
}

const ID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

/**
 * Prefixed random IDs such as `fnd_8k2m…`: 20 characters from a 32-letter
 * alphabet (100 bits of entropy), safe in URLs and easy to read in logs.
 */
export function newId(prefix: string): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += ID_ALPHABET[b & 31];
  return `${prefix}_${out}`;
}

export * from "./pagination.ts";
export * from "./scan-errors.ts";
