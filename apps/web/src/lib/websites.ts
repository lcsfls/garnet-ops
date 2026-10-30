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
  type VerifyMethod,
  type VerifyState,
} from "@garnetops/core/exposure";
import type { BadgeTone } from "./components/ui/tones.ts";

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
  /** wordpress.org's answers for the site's plugins and themes; null while the lookup is off (ADR 0042). */
  wordpressOrg:
    | { kind: "plugin" | "theme"; slug: string; listed: boolean; latest: string | null; checkedAt: string }[]
    | null;
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

/** A value of a rule's parameters as text for a sentence. */
export const paramText = (value: string | number | undefined): string =>
  value === undefined ? "" : String(value);

export const SEVERITY_ORDER: ExposureSeverity[] = ["critical", "high", "medium", "low"];
