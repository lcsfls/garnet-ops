/**
 * Optional OSINT enrichment of attacking addresses (ADR 0016). Off by default. When an owner or
 * admin switches it on, the worker (and only the worker) sends public source addresses of the
 * busiest attackers to the provider they chose, with the API key they supplied. Those addresses
 * leave the customer's network, which is why it is opt-in, step-up protected, audited and explained
 * in plain words before it can be enabled.
 *
 * A provider is a small description: where to ask, how to build the request, how to read the
 * answer. Only AbuseIPDB exists today; another source adds one entry and one parser. The answer is
 * hostile input like everything from outside: it is parsed field by field, bounded, and only a
 * score, a report count and a date are kept. Nothing the provider sends is shown as text,
 * rendered as markup or sent to a model.
 */
import { canonicalIp, ipScope } from "./geoip.ts";

export const OSINT_PROVIDER_IDS = ["abuseipdb"] as const;
export type OsintProviderId = (typeof OSINT_PROVIDER_IDS)[number];

/** What is kept from a provider's answer about one address. */
export interface OsintResult {
  /** 0 to 100: how confident the provider is that the address is abusive. */
  score: number;
  /** Reports the provider has about the address in its look-back period. */
  reports: number;
  lastReportedAt: Date | null;
}

export interface OsintRequest {
  method: "GET";
  /** Path and query on the provider's host. */
  path: string;
  headers: Record<string, string>;
}

export interface OsintProvider {
  id: OsintProviderId;
  name: string;
  /** The only host a request is ever sent to. */
  host: string;
  /** The provider's page about one address, linked from the UI only while the provider is enabled. */
  pageUrl(ip: string): string;
  /** Where the provider publishes its terms of use; shown next to the switch. */
  termsUrl: string;
  /** The daily number of checks of the provider's free plan: the ceiling for our own budget. */
  freeDailyLimit: number;
  /** A key that cannot be right is refused before it is stored. */
  keyProblem(key: string): "empty" | "tooShort" | "tooLong" | "characters" | null;
  request(ip: string, key: string): OsintRequest;
  /** The score, the report count and the last report from an answer about `ip`; null if the answer does not fit. */
  parse(body: unknown, ip: string): OsintResult | null;
  /**
   * Whether the maintainers have confirmed that the provider's terms allow a customer to use their
   * own key this way. False means: documented as unconfirmed, the customer must check (ADR 0016).
   */
  termsConfirmed: boolean;
}

const asRecord = (v: unknown): Record<string, unknown> | null =>
  v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

const boundedInt = (v: unknown, min: number, max: number): number | null =>
  typeof v === "number" && Number.isInteger(v) && v >= min && v <= max ? v : null;

export const ABUSEIPDB: OsintProvider = {
  id: "abuseipdb",
  name: "AbuseIPDB",
  host: "api.abuseipdb.com",
  pageUrl: (ip) => `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
  termsUrl: "https://www.abuseipdb.com/terms",
  // AbuseIPDB's free plan allows 1,000 checks per day (its API documentation); we stay well below.
  freeDailyLimit: 1000,
  termsConfirmed: false,
  keyProblem(key) {
    if (key.length === 0) return "empty";
    if (key.length < 20) return "tooShort";
    if (key.length > 128) return "tooLong";
    return /^[A-Za-z0-9]+$/.test(key) ? null : "characters";
  },
  request(ip, key) {
    const address = canonicalIp(ip);
    if (!address || ipScope(address) !== "public") throw new Error("Only public addresses are checked");
    return {
      method: "GET",
      path: `/api/v2/check?ipAddress=${encodeURIComponent(address)}&maxAgeInDays=90`,
      headers: { Key: key, Accept: "application/json" },
    };
  },
  parse(body, ip) {
    const data = asRecord(asRecord(body)?.data);
    if (!data) return null;
    // An answer about another address is not an answer to our question.
    const answered = typeof data.ipAddress === "string" ? canonicalIp(data.ipAddress) : null;
    if (!answered || answered !== canonicalIp(ip)) return null;
    const score = boundedInt(data.abuseConfidenceScore, 0, 100);
    if (score === null) return null;
    const reports = boundedInt(data.totalReports, 0, 100_000_000) ?? 0;
    let lastReportedAt: Date | null = null;
    if (typeof data.lastReportedAt === "string" && data.lastReportedAt.length <= 40) {
      const at = new Date(data.lastReportedAt);
      if (
        !Number.isNaN(at.getTime()) &&
        at.getTime() > Date.UTC(2000, 0, 1) &&
        at.getTime() < Date.now() + 864e5
      ) {
        lastReportedAt = at;
      }
    }
    return { score, reports, lastReportedAt };
  },
};

export const OSINT_PROVIDERS: Record<OsintProviderId, OsintProvider> = { abuseipdb: ABUSEIPDB };

export function osintProvider(id: string): OsintProvider | null {
  return (OSINT_PROVIDER_IDS as readonly string[]).includes(id)
    ? OSINT_PROVIDERS[id as OsintProviderId]
    : null;
}

/* -------------------------------------------------------------------------- */
/* Limits and settings                                                         */
/* -------------------------------------------------------------------------- */

export const OSINT_LIMITS = {
  /** Results are reused for this long. */
  cacheHours: 24,
  /** At most this many addresses are looked up per Wazuh sync (the busiest first). */
  topN: { default: 20, min: 1, max: 50 },
  /** At most this many requests per UTC day, always below the provider's own limit. */
  dailyBudget: { default: 300, min: 10, max: 900 },
  /** Pause between two requests: polite, and far below any rate limit. */
  gapMs: 1100,
  timeoutMs: 10_000,
  /** An answer is a few hundred bytes; more is refused. */
  maxResponseBytes: 16 * 1024,
  /** A score at or above this is called out in the table. */
  highScore: 75,
} as const;

/** The score as a band for the table; the number itself is always shown. */
export const scoreBand = (score: number): "high" | "medium" | "low" =>
  score >= OSINT_LIMITS.highScore ? "high" : score >= 25 ? "medium" : "low";

/** Short, fixed reasons a lookup run stopped; stored as codes and translated in the web app. */
export const OSINT_ERROR_CODES = [
  "keyRejected",
  "rateLimited",
  "budgetReached",
  "unreachable",
  "unexpectedAnswer",
  "redirected",
  "credentialsMissing",
] as const;
export type OsintErrorCode = (typeof OSINT_ERROR_CODES)[number];
export const isOsintErrorCode = (v: unknown): v is OsintErrorCode =>
  (OSINT_ERROR_CODES as readonly unknown[]).includes(v);

/** The statements an admin confirms when switching OSINT on. The API checks that both were confirmed. */
export const OSINT_ACKNOWLEDGEMENTS = ["addressesLeaveNetwork", "termsChecked"] as const;
