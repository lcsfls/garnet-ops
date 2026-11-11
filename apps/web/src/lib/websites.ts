/**
 * Website monitoring on the web side (ADR 0023, a module since ADR 0033): the shapes the API sends, and the small decisions the screens share. Everything a
 * remote system sent (banners, headers, certificate names, record texts) arrives as text that the worker already cleaned; the
 * screens still render it as text only.
 */
import {
  type ActiveSnapshot,
  type AssetKind,
  EXPOSURE_ERRORS,
  type ExposureErrorCode,
  type ExposureSeverity,
  type PassiveSnapshot,
  type VerifyErrorDetail,
  type VerifyMethod,
  type VerifyState,
} from "@garnetops/core/exposure";
import type { MessageKey } from "./i18n.svelte.ts";
import type { BadgeTone } from "./severity-meta.ts";

export type {
  CertificateGroup,
  CertificateServer,
  WildcardMiss,
} from "@garnetops/core/exposure-certificates";
export type { ActiveSnapshot, AssetKind, ExposureSeverity, PassiveSnapshot, VerifyMethod, VerifyState };

export interface ExposureRunSummary {
  id: string;
  state: "queued" | "running" | "succeeded" | "failed";
  trigger: "manual" | "schedule" | "enable";
  error: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface WebsiteAsset {
  id: string;
  kind: AssetKind;
  value: string;
  includeSubdomains: boolean;
  verification: {
    state: VerifyState;
    method: VerifyMethod | null;
    confirmedAt: string | null;
    checkedAt: string | null;
    error: string | null;
    /** For a redirect of the proof file: where it points (0.1.0; older servers send none). */
    errorDetail?: VerifyErrorDetail | null;
    effective: boolean;
    via: "self" | "parent" | null;
    parent: { id: string; value: string } | null;
  };
  stage1: {
    enabled: boolean;
    lastAt: string | null;
    error: string | null;
    run: ExposureRunSummary | null;
    summary: {
      takenAt: string | null;
      addresses: string[];
      resolves: boolean;
      httpsOpen: boolean;
      certificateExpires: string | null;
      httpStatus: number | null;
    } | null;
  };
  stage2: {
    enabled: boolean;
    schedule: "daily" | "weekly";
    acknowledgedAt: string | null;
    lastAt: string | null;
    error: string | null;
    run: ExposureRunSummary | null;
    summary: { takenAt: string | null; open: number; checked: number | null } | null;
    nextManualAt: string | null;
  };
  /** Files that must not be public (ADR 0050); off until an admin switches it on for a proved name. */
  exposedFiles: {
    enabled: boolean;
    enabledAt: string | null;
    last: { error: "notVerified" | "noHttps" | null; checked: number; failed: number; found: number } | null;
  };
  open: Record<ExposureSeverity, number>;
  /** Availability (ADR 0040); off until an admin switches it on. */
  uptime: {
    enabled: boolean;
    intervalMinutes: number;
    state: "up" | "down" | null;
    since: string | null;
    checkedAt: string | null;
  };
  createdAt: string;
}

export interface ExposureFindingRow {
  id: string;
  stage: "passive" | "active";
  rule: string;
  subject: string;
  severity: ExposureSeverity;
  state: "open" | "resolved";
  params: Record<string, string | number>;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
}

export interface ExposurePortRow {
  address: string;
  port: number;
  service: string;
  banner: string | null;
  tls: import("@garnetops/core/exposure").TlsSnapshot | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ExposureHistoryRow {
  id: string;
  stage: "passive" | "active";
  state: "queued" | "running" | "succeeded" | "failed";
  trigger: "manual" | "schedule" | "enable";
  error: string | null;
  findingCounts: Record<string, number> | null;
  openPorts: number | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface ExposureDetail extends WebsiteAsset {
  passive: PassiveSnapshot | null;
  active: ActiveSnapshot | null;
  findings: ExposureFindingRow[];
  ports: ExposurePortRow[];
  runs: ExposureHistoryRow[];
  suggestions: { id: string; name: string; source: "ct" | "dns" }[];
  /** What the site names about its software, judged against the end-of-life data (ADR 0038). */
  software: (import("@garnetops/core/software").SoftwareJudgement & { name: string })[];
  /** The GarnetOps WordPress plugin (ADR 0042, part 4); how its last read went is in `passive.wordpressPlugin`. */
  wordpressPlugin: { connected: boolean; connectedAt: string | null };
  /** wordpress.org's answers for the site's plugins and themes; null while the lookup is off (ADR 0042). */
  wordpressOrg:
    | { kind: "plugin" | "theme"; slug: string; listed: boolean; latest: string | null; checkedAt: string }[]
    | null;
  /**
   * Per certificate of the latest stage 1 look, the other websites that served the same certificate (one wildcard certificate on
   * many names). Absent from an API before this field existed.
   */
  sharedCertificates?: { fingerprint: string; others: { id: string; value: string }[] }[];
  /** Only for owners and admins. */
  instructions: {
    value: string;
    dns: { type: "TXT"; name: string } | null;
    file: { url: string; path: string };
  } | null;
  limits: { ports: number; scheduleHours: Record<string, number> };
  availability: {
    day: import("@garnetops/core/uptime").UptimeStats;
    week: import("@garnetops/core/uptime").UptimeStats;
    month: import("@garnetops/core/uptime").UptimeStats;
    /** The last 24 hours, hour by hour, oldest first. */
    hours: import("@garnetops/core/uptime").UptimeHour[];
    incidents: import("@garnetops/core/uptime").UptimeIncident[];
  };
}

export interface ExposureCounts {
  all: number;
  attention: number;
  unverified: number;
  stage2: number;
  open: Record<ExposureSeverity, number>;
  limit: number;
}

export interface ExposureSettings {
  certificateTransparency: {
    enabled: boolean;
    enabledAt: string | null;
    enabledBy: string | null;
    provider: { id: string; name: string; operator: string; urlTemplate: string };
    usageToday: number;
    dailyBudget: number;
    lastError: string | null;
  };
  /** The organisation's own Wordfence Intelligence key (ADR 0042, part 3); the key itself is never returned. */
  wordfence: {
    configured: boolean;
    setAt: string | null;
    setBy: string | null;
    syncedAt: string | null;
    error: string | null;
    advisories: number;
    host: string;
  };
  /** Latest versions of WordPress plugins and themes from wordpress.org (ADR 0042, opt-in). */
  wordpressOrg: { enabled: boolean; enabledAt: string | null; enabledBy: string | null; host: string };
}

/* -------------------------------------------------------------------------- */
/* States                                                                      */
/* -------------------------------------------------------------------------- */

export type Stage1Key = "never" | "queued" | "running" | "failed" | "ok" | "paused";
export type Stage2Key = "off" | "waiting" | "queued" | "running" | "failed" | "on";
export type VerificationKey = "verified" | "covered" | "unverified" | "lost";

export const busy = (run: ExposureRunSummary | null): boolean =>
  run?.state === "queued" || run?.state === "running";

/** What stage 1 is doing for an asset: a run in progress wins, then a failed last run, then whether it has ever worked. */
export function stage1Key(asset: Pick<WebsiteAsset, "stage1">): Stage1Key {
  const { run, lastAt, error, enabled } = asset.stage1;
  if (run?.state === "running") return "running";
  if (run?.state === "queued") return "queued";
  if (error) return "failed";
  if (lastAt) return "ok";
  return enabled ? "never" : "paused";
}

export function stage2Key(asset: Pick<WebsiteAsset, "stage2">): Stage2Key {
  const { run, enabled, lastAt, error } = asset.stage2;
  if (!enabled) return "off";
  if (run?.state === "running") return "running";
  if (run?.state === "queued") return "queued";
  if (error) return "failed";
  return lastAt ? "on" : "waiting";
}

export function verificationKey(asset: Pick<WebsiteAsset, "verification">): VerificationKey {
  const v = asset.verification;
  if (v.state === "verified") return "verified";
  if (v.state === "lost") return "lost";
  return v.effective ? "covered" : "unverified";
}

/** Tones never use green: a proof of control or a finished run proves nothing about security (AGENTS.md rule 6). */
export const VERIFICATION_TONE: Record<VerificationKey, BadgeTone> = {
  verified: "info",
  covered: "info",
  unverified: "neutral",
  lost: "critical",
};

export function stage1Tone(key: Stage1Key): BadgeTone {
  return key === "failed" ? "critical" : key === "queued" || key === "running" ? "info" : "neutral";
}
export function stage2Tone(key: Stage2Key): BadgeTone {
  return key === "failed"
    ? "critical"
    : key === "queued" || key === "running" || key === "on"
      ? "info"
      : "neutral";
}

/** Whether anything about the asset is still being worked on, so the screen should look again soon. */
export const isBusy = (asset: Pick<WebsiteAsset, "stage1" | "stage2">): boolean =>
  busy(asset.stage1.run) || busy(asset.stage2.run);

/** Whole days from now until an instant; negative when it has passed. */
export function daysUntil(value: string | null, now: Date = new Date()): number | null {
  if (!value) return null;
  return Math.floor((new Date(value).getTime() - now.getTime()) / 86_400_000);
}

/** A stored error code as a sentence key, or null for a code this version does not know (shown as it is). */
export const errorKey = (code: string | null | undefined): `websites.error.${ExposureErrorCode}` | null => {
  const known = knownError(code);
  return known ? `websites.error.${known}` : null;
};

/** The code in an error text that the worker stored, if it is one this version knows. */
export const knownError = (code: string | null | undefined): ExposureErrorCode | null =>
  code && (EXPOSURE_ERRORS as readonly string[]).includes(code) ? (code as ExposureErrorCode) : null;

/** Verification codes that come with a next step in the verify dialog. */
const NEXT_STEPS = [
  "dnsRecordMissing",
  "dnsNoMatch",
  "dnsFailed",
  "fileUnreachable",
  "fileNotFound",
  "fileNoMatch",
  "fileTooLarge",
  "tlsFailed",
  "timeout",
  "unresolvable",
  "addressRefused",
] as const;
/** Codes about the file (or reaching the site), for which a domain can use the DNS record instead. */
const FILE_SIDE = new Set<string>([
  "fileUnreachable",
  "fileNotFound",
  "fileNoMatch",
  "fileRedirected",
  "fileTooLarge",
  "tlsFailed",
  "timeout",
  "addressRefused",
]);

type Sentence = { key: MessageKey; params?: Record<string, string> };

/**
 * Why the last verification check failed, in words, and what to do next: for a redirect of the proof file it names where it
 * points (another host by name, or the same site). Redirects are never followed; the text says what to verify instead. Null when
 * the check found the proof or nothing was checked yet; an unknown code (a newer worker) is shown as it is.
 */
export function verifyProblem(
  asset: Pick<WebsiteAsset, "kind" | "verification">,
): { problem: Sentence | { text: string }; next: Sentence[] } | null {
  const code = asset.verification.error;
  if (!code) return null;
  const known = knownError(code);
  if (!known) return { problem: { text: code }, next: [] };
  const next: Sentence[] = [];
  let problem: Sentence = { key: `websites.error.${known}` };
  if (known === "fileRedirected") {
    const redirect = asset.verification.errorDetail?.redirect;
    if (redirect?.kind === "otherHost") {
      problem = { key: "websites.verifyRedirect.otherHost", params: { host: redirect.host } };
      next.push({ key: "websites.verifyNext.redirectOtherHost", params: { host: redirect.host } });
    } else if (redirect?.kind === "sameHost") {
      problem = { key: "websites.verifyRedirect.sameHost" };
      next.push({ key: "websites.verifyNext.redirectSameHost" });
    } else {
      next.push({ key: "websites.verifyNext.redirectUnusable" });
    }
  } else if ((NEXT_STEPS as readonly string[]).includes(known)) {
    next.push({ key: `websites.verifyNext.${known as (typeof NEXT_STEPS)[number]}` });
  }
  if (asset.kind === "domain" && FILE_SIDE.has(known)) next.push({ key: "websites.verifyNext.orDns" });
  return { problem, next };
}

/** A value of a rule's parameters as text for a sentence. */
export const paramText = (value: string | number | undefined): string =>
  value === undefined ? "" : String(value);

export const SEVERITY_ORDER: ExposureSeverity[] = ["critical", "high", "medium", "low"];
