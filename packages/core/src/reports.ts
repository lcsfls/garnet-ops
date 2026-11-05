/**
 * Reports (ADR 0047): the summary of one repository, one host, the websites, and the whole organisation for a period. Pure
 * types and functions, no Node-only imports: the API and the worker assemble the data (packages/db `reports.ts`), the web app
 * shows it, and `report-documents.ts` writes the PDF and the mail text.
 *
 * Every report is assembled for one person with that person's visibility (ADR 0030); nothing here widens it. Report data holds
 * names, counts, dates and, for one repository or host, the worst findings' ids and packages. Nothing in a report is ever
 * interpreted: the PDF writer and the web app treat every value as text.
 */
import { type Freshness, vulnDbFreshness } from "./system-status.ts";

export type { Freshness };

/* -------------------------------------------------------------------------- */
/* Severities                                                                  */
/* -------------------------------------------------------------------------- */

/** The severities a report counts; "negligible" and "unknown" are left out, as in the statistics. */
export const REPORT_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type ReportSeverity = (typeof REPORT_SEVERITIES)[number];
export type SeverityCounts = Record<ReportSeverity, number>;

export const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0 });

export const isReportSeverity = (value: string): value is ReportSeverity =>
  (REPORT_SEVERITIES as readonly string[]).includes(value);

export const totalOf = (counts: SeverityCounts): number =>
  counts.critical + counts.high + counts.medium + counts.low;

/** The worst severity with at least one finding, or null. */
export const worstOf = (counts: SeverityCounts): ReportSeverity | null =>
  REPORT_SEVERITIES.find((s) => counts[s] > 0) ?? null;

export function addCounts(...all: SeverityCounts[]): SeverityCounts {
  const sum = emptyCounts();
  for (const counts of all) for (const s of REPORT_SEVERITIES) sum[s] += counts[s];
  return sum;
}

/** Worst first: more critical, then more high, then more medium, then more low. */
export function compareCounts(a: SeverityCounts, b: SeverityCounts): number {
  for (const s of REPORT_SEVERITIES) if (a[s] !== b[s]) return b[s] - a[s];
  return 0;
}

/* -------------------------------------------------------------------------- */
/* Periods and time zones (ADR 0005)                                           */
/* -------------------------------------------------------------------------- */

/** The periods a person can download: the last 7 or 30 calendar days, today included. */
export const REPORT_RANGES = [7, 30] as const;
export type ReportRange = (typeof REPORT_RANGES)[number];

/** How often the report mail comes: the day before, the week before (Monday to Sunday), or the month before. */
export const REPORT_FREQUENCIES = ["daily", "weekly", "monthly"] as const;
export type ReportFrequency = (typeof REPORT_FREQUENCIES)[number];

/** The report mail goes out from this local time on the day after its period, in the person's own zone. */
export const REPORT_MAIL_TIME = "07:00";

export interface ReportPeriod {
  /** First and last calendar day of the period in `timeZone`, "YYYY-MM-DD", both included. */
  from: string;
  to: string;
  days: number;
  timeZone: string;
}

/** The calendar date and wall-clock time of an instant in a zone: { date: "2026-10-25", time: "02:30" }. */
export function localParts(at: Date, timeZone: string): { date: string; time: string } {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(at);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return { date: `${get("year")}-${get("month")}-${get("day")}`, time: `${get("hour")}:${get("minute")}` };
}

const DAY_MS = 86_400_000;
const dateValue = (date: string) => Date.parse(`${date}T00:00:00Z`);
const dateOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** Adds calendar days to a date (never hours to an instant, ADR 0005). */
export const addDays = (date: string, days: number): string => dateOf(dateValue(date) + days * DAY_MS);

/** Calendar days from `from` to `to`, both included. */
export const daysIn = (from: string, to: string): number =>
  Math.round((dateValue(to) - dateValue(from)) / DAY_MS) + 1;

/** 1 for Monday to 7 for Sunday. */
const isoWeekday = (date: string) => ((new Date(dateValue(date)).getUTCDay() + 6) % 7) + 1;

/** Whether a zone name is one this runtime knows. */
export function knownTimeZone(timeZone: string): boolean {
  try {
    new Intl.DateTimeFormat("en", { timeZone });
    return true;
  } catch {
    return false;
  }
}

/** The last `days` calendar days in `timeZone`, today included. */
export function rangePeriod(days: number, timeZone: string, now: Date): ReportPeriod {
  const today = localParts(now, timeZone).date;
  return { from: addDays(today, -(days - 1)), to: today, days, timeZone };
}

/**
 * The latest complete period of a frequency whose mail is due by `now`, and the local date it is sent on. The mail is due
 * from {@link REPORT_MAIL_TIME} on the day after the period: daily the previous day, weekly on Monday for Monday to Sunday,
 * monthly on the 1st for the previous month.
 */
export function mailPeriod(
  frequency: ReportFrequency,
  timeZone: string,
  now: Date,
): { period: ReportPeriod; sendDate: string } {
  const local = localParts(now, timeZone);
  // Before the send time, today's mail is not due yet: the latest due one is from the day before.
  const reference = local.time >= REPORT_MAIL_TIME ? local.date : addDays(local.date, -1);
  let sendDate: string;
  let from: string;
  if (frequency === "daily") {
    sendDate = reference;
    from = addDays(sendDate, -1);
  } else if (frequency === "weekly") {
    sendDate = addDays(reference, -(isoWeekday(reference) - 1));
    from = addDays(sendDate, -7);
  } else {
    sendDate = `${reference.slice(0, 7)}-01`;
    const previous = addDays(sendDate, -1);
    from = `${previous.slice(0, 7)}-01`;
  }
  const to = addDays(sendDate, -1);
  return { period: { from, to, days: daysIn(from, to), timeZone }, sendDate };
}

/**
 * The report mail that is due for one person, or null. A period is due once its send time has passed and the person chose
 * the frequency before that send time (switching it on does not send last week's report at once). The returned key names
 * the period; the worker records it before sending, so a repeated hour in autumn cannot send it twice and a skipped hour
 * in spring only moves it to the next tick (ADR 0005).
 */
export function dueReportMail(input: {
  frequency: ReportFrequency;
  timeZone: string;
  now: Date;
  /** When the person last chose this frequency. */
  since: Date;
}): { key: string; period: ReportPeriod } | null {
  const { period, sendDate } = mailPeriod(input.frequency, input.timeZone, input.now);
  const chosen = localParts(input.since, input.timeZone);
  if (`${chosen.date} ${chosen.time}` >= `${sendDate} ${REPORT_MAIL_TIME}`) return null;
  return { key: `${input.frequency}:${period.from}`, period };
}

/* -------------------------------------------------------------------------- */
/* What to do next                                                             */
/* -------------------------------------------------------------------------- */

/** A recommendation as a code and a count; the web app and the PDF turn it into a sentence (`reports.next.*`). */
export type NextStep = { code: NextStepCode; count?: number };
export const NEXT_STEP_CODES = [
  "scanNever",
  "scanFailed",
  "knownExploited",
  "fixCritical",
  "fixHigh",
  "gateBlocked",
  "gatesBlocked",
  "acceptedExpired",
  "earlyWarnings",
  "vulnDbStale",
  "neverScanned",
  "hostNotReporting",
  "hostsNotReporting",
  "kernelUpdate",
  "packagesUpdate",
  "imageUpdates",
  "imageFindings",
  "websitesDown",
  "certificatesExpiring",
  "nothing",
] as const;
export type NextStepCode = (typeof NEXT_STEP_CODES)[number];

/** A certificate or an accepted risk that ends within this many days is named in the reports. */
export const ENDING_SOON_DAYS = 14;

/** A host that has not reported for this long is "not reporting" (the agent reports every 6 hours by default, ADR 0034). */
export const HOST_STALE_AFTER_MS = 25 * 3600_000;

/* -------------------------------------------------------------------------- */
/* Report shapes                                                               */
/* -------------------------------------------------------------------------- */

export interface ReportFindingRow {
  severity: ReportSeverity;
  vulnerabilityId: string;
  packageName: string;
  packageVersion: string;
  fixedIn: string[];
  knownExploited: boolean;
  /** Hosts only: "kernel", "packages", or the image reference of a running container. */
  where?: string;
}

export interface VulnDbState {
  builtAt: string | null;
  freshness: Freshness;
}

export const vulnDbState = (builtAt: Date | string | null | undefined, now: Date): VulnDbState => ({
  builtAt: builtAt ? new Date(builtAt).toISOString() : null,
  freshness: vulnDbFreshness(builtAt ?? null, now),
});

export interface RepositoryReport {
  kind: "repository";
  generatedAt: string;
  repository: { id: string; name: string; url: string; branch: string | null; inactive: boolean };
  /** The newest scan in any state, so a running or failed one is named. */
  lastScan: { state: "queued" | "running" | "succeeded" | "failed"; at: string } | null;
  /** The newest scan that worked: what the open findings come from. */
  lastSuccessfulScan: {
    at: string;
    commit: string | null;
    packages: number | null;
  } | null;
  /** The vulnerability database the last successful scan used. */
  vulnDb: VulnDbState;
  open: SeverityCounts;
  /** Open findings with a fixed version. */
  fixable: SeverityCounts;
  knownExploited: number;
  accepted: { total: number; expired: number };
  /** Grade A to F (ADR 0018); null before the first scan. */
  grade: { grade: string; stale: boolean } | null;
  /** The newest quality gate result. */
  gate: { result: "passed" | "notes" | "blocked"; at: string } | null;
  earlyWarnings: { open: number; worst: ReportSeverity | null };
  /** Up to ten open findings, worst first. */
  top: ReportFindingRow[];
  nextSteps: NextStep[];
}

export interface HostReport {
  kind: "host";
  generatedAt: string;
  host: {
    id: string;
    name: string;
    hostname: string;
    os: string | null;
    runtime: string | null;
    agentVersion: string | null;
  };
  lastReportAt: string | null;
  reporting: boolean;
  kernel: {
    release: string | null;
    /** True once the running kernel was matched against the vulnerability database. */
    checked: boolean;
    matchedAt: string | null;
    open: SeverityCounts;
  };
  /** The packages of the host itself (systemd agent); null when the agent does not send them. */
  packages: { count: number | null; matchedAt: string | null; open: SeverityCounts; fixable: number } | null;
  images: {
    containers: number;
    images: number;
    /** Running images with an open critical or high finding. */
    withSerious: number;
    notMatched: number;
    /** Containers whose registry has a newer image (ADR 0034, opt-in). */
    updates: number;
    open: SeverityCounts;
  };
  open: SeverityCounts;
  vulnDb: VulnDbState;
  earlyWarnings: { open: number; worst: ReportSeverity | null };
  top: ReportFindingRow[];
  nextSteps: NextStep[];
}

export interface WebsiteOverviewRow {
  id: string;
  value: string;
  kind: "domain" | "ip";
  verifyState: "unverified" | "verified" | "lost";
  /** Its own proof or a verified parent domain's (ADR 0023). */
  verified: boolean;
  availability: { enabled: boolean; state: "up" | "down" | null; since: string | null };
  certificateExpires: string | null;
  /** Whole days until the certificate ends; negative once it ended. */
  certificateDays: number | null;
  open: SeverityCounts;
  /** Worst of the open findings, and "high" while the site is down. */
  worst: ReportSeverity | null;
  /** The rule of the worst open finding (the web app names it). */
  worstRule: string | null;
  /** Software the site names: behind its line, or on a line that gets no fixes any more (ADR 0038). */
  software: { outdated: string[]; endOfLife: string[] };
  /** The last daily look (stage 1) and its error code, if it failed. */
  lastCheckedAt: string | null;
  checkError: string | null;
}

const SEVERITY_RANK: Record<ReportSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const rankOf = (s: ReportSeverity | null) => (s ? SEVERITY_RANK[s] : 0);

/** Websites worst first: worst state, then more findings, then the certificate that ends first, then by name. */
export function compareWebsites(a: WebsiteOverviewRow, b: WebsiteOverviewRow): number {
  return (
    rankOf(b.worst) - rankOf(a.worst) ||
    compareCounts(a.open, b.open) ||
    b.software.endOfLife.length - a.software.endOfLife.length ||
    b.software.outdated.length - a.software.outdated.length ||
    (a.certificateDays ?? Number.MAX_SAFE_INTEGER) - (b.certificateDays ?? Number.MAX_SAFE_INTEGER) ||
    a.value.localeCompare(b.value)
  );
}

export interface RiskRow {
  id: string;
  name: string;
  open: SeverityCounts;
}

export interface OrganizationReport {
  kind: "organization";
  generatedAt: string;
  organization: string;
  period: ReportPeriod;
  findings: {
    /** Open now, in the repositories the person sees (active ones, ADR 0043). */
    open: SeverityCounts;
    /** First seen in the period. */
    opened: SeverityCounts;
    /** No longer found in the period. */
    fixed: SeverityCounts;
    fixableCritical: number;
    knownExploited: number;
  };
  repositories: {
    total: number;
    scanned: number;
    failedScans: number;
    neverScanned: { id: string; name: string }[];
    neverScannedCount: number;
  };
  gates: { passed: number; notes: number; blocked: number };
  earlyWarnings: { repositories: number; runtime: number | null };
  accepted: { total: number; expired: number; endingSoon: number };
  top: { repositories: RiskRow[]; hosts: RiskRow[] | null };
  /** Null while the hosts module is off. */
  hosts: {
    total: number;
    notReporting: { id: string; name: string; lastReportAt: string | null }[];
  } | null;
  /** Null while the websites module is off; worst first. */
  websites: WebsiteOverviewRow[] | null;
  vulnDb: VulnDbState;
  nextSteps: NextStep[];
}

/* -------------------------------------------------------------------------- */
/* Next steps from the data                                                    */
/* -------------------------------------------------------------------------- */

/** A database known to have missed updates; an unknown one is not called stale (nothing says it is). */
const behind = (db: VulnDbState) => db.freshness === "stale" || db.freshness === "outdated";

const step = (code: NextStepCode, count?: number): NextStep =>
  count === undefined ? { code } : { code, count };

export function repositoryNextSteps(r: Omit<RepositoryReport, "nextSteps">): NextStep[] {
  const steps: NextStep[] = [];
  if (!r.lastSuccessfulScan) steps.push(step("scanNever"));
  if (r.lastScan?.state === "failed") steps.push(step("scanFailed"));
  if (r.knownExploited > 0) steps.push(step("knownExploited", r.knownExploited));
  if (r.fixable.critical > 0) steps.push(step("fixCritical", r.fixable.critical));
  if (r.fixable.high > 0) steps.push(step("fixHigh", r.fixable.high));
  if (r.gate?.result === "blocked") steps.push(step("gateBlocked"));
  if (r.accepted.expired > 0) steps.push(step("acceptedExpired", r.accepted.expired));
  if (r.earlyWarnings.open > 0) steps.push(step("earlyWarnings", r.earlyWarnings.open));
  if (r.lastSuccessfulScan && behind(r.vulnDb)) steps.push(step("vulnDbStale"));
  return steps.length > 0 ? steps : [step("nothing")];
}

export function hostNextSteps(h: Omit<HostReport, "nextSteps">): NextStep[] {
  const steps: NextStep[] = [];
  if (!h.reporting) steps.push(step("hostNotReporting"));
  const kernel = totalOf(h.kernel.open);
  if (kernel > 0) steps.push(step("kernelUpdate", kernel));
  if (h.packages && h.packages.fixable > 0) steps.push(step("packagesUpdate", h.packages.fixable));
  if (h.images.withSerious > 0) steps.push(step("imageFindings", h.images.withSerious));
  if (h.images.updates > 0) steps.push(step("imageUpdates", h.images.updates));
  if (h.earlyWarnings.open > 0) steps.push(step("earlyWarnings", h.earlyWarnings.open));
  if (behind(h.vulnDb)) steps.push(step("vulnDbStale"));
  return steps.length > 0 ? steps : [step("nothing")];
}

export function organizationNextSteps(o: Omit<OrganizationReport, "nextSteps">): NextStep[] {
  const steps: NextStep[] = [];
  if (o.findings.knownExploited > 0) steps.push(step("knownExploited", o.findings.knownExploited));
  if (o.findings.fixableCritical > 0) steps.push(step("fixCritical", o.findings.fixableCritical));
  if (o.gates.blocked > 0) steps.push(step("gatesBlocked", o.gates.blocked));
  if (o.accepted.expired > 0) steps.push(step("acceptedExpired", o.accepted.expired));
  const warnings = o.earlyWarnings.repositories + (o.earlyWarnings.runtime ?? 0);
  if (warnings > 0) steps.push(step("earlyWarnings", warnings));
  if (o.repositories.neverScannedCount > 0)
    steps.push(step("neverScanned", o.repositories.neverScannedCount));
  if (o.hosts && o.hosts.notReporting.length > 0)
    steps.push(step("hostsNotReporting", o.hosts.notReporting.length));
  if (o.websites) {
    const down = o.websites.filter((w) => w.availability.state === "down").length;
    if (down > 0) steps.push(step("websitesDown", down));
    const ending = o.websites.filter(
      (w) => w.certificateDays !== null && w.certificateDays <= ENDING_SOON_DAYS,
    ).length;
    if (ending > 0) steps.push(step("certificatesExpiring", ending));
  }
  if (behind(o.vulnDb)) steps.push(step("vulnDbStale"));
  return steps.length > 0 ? steps : [step("nothing")];
}

/** Whole days from `now` until `until` (negative once it passed). */
export function daysUntil(until: string | null, now: Date): number | null {
  if (!until) return null;
  const at = Date.parse(until);
  if (!Number.isFinite(at)) return null;
  return Math.floor((at - now.getTime()) / DAY_MS);
}

/** `garnetops-report-web-2026-10-21.pdf`: safe characters only. */
export function reportFileName(subject: string, date: string): string {
  const slug = subject
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60);
  return `garnetops-report${slug ? `-${slug}` : ""}-${date}.pdf`;
}

/** The zone of a person's report mail: their own if it is known, else the organisation's (nightly scan), else UTC. */
export function reportTimeZone(
  userZone: string | null | undefined,
  organizationZone: string | null | undefined,
): string {
  if (userZone && knownTimeZone(userZone)) return userZone;
  if (organizationZone && knownTimeZone(organizationZone)) return organizationZone;
  return "UTC";
}
