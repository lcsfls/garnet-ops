/**
 * URL search params of the list views. Filters live in the URL so every tile
 * can link to a filtered view, links can be shared and the back button works.
 * Invalid values fall back to the default instead of breaking the page.
 */
import { DEFAULT_PAGE_SIZE, FINDING_STATES, PAGE_SIZES, SEVERITIES } from "@garnetops/core";
import { GRADE_FILTER_VALUES } from "@garnetops/core/grades";
import { z } from "zod";

export { PAGE_SIZES };

const pageSize = z.coerce
  .number()
  .refine((n) => (PAGE_SIZES as readonly number[]).includes(n))
  .optional()
  .catch(undefined);
// The router's query-string decoder turns numeric-looking values into numbers ("1" -> 1,
// "2099" -> 2099); text params take them back as strings.
const asString = (v: unknown) => (typeof v === "number" ? String(v) : v);
const text = (max: number) =>
  z.preprocess(asString, z.string().trim().min(1).max(max).optional()).catch(undefined);
const flag = z.preprocess(asString, z.literal("1").optional()).catch(undefined);
/** A calendar day, YYYY-MM-DD. */
const day = z
  .preprocess(
    asString,
    z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/)
      .optional(),
  )
  .catch(undefined);
const sortOf = <T extends string>(columns: readonly [T, ...T[]]) =>
  z.enum(columns).optional().catch(undefined);
const dir = z.enum(["asc", "desc"]).optional().catch(undefined);

export const FINDING_SORTS = [
  "vulnerability",
  "cvss",
  "epss",
  "published",
  "package",
  "repository",
  "firstSeen",
] as const;
export const FIX_SORTS = [
  "severity",
  "package",
  "repository",
  "vulnerabilities",
  "ecosystem",
  "status",
] as const;
export const REPOSITORY_SORTS = ["name", "grade", "critical", "high", "medium", "lastScan"] as const;
export const PACKAGE_SORTS = ["name", "type", "repository", "findings", "severity"] as const;

/** Comma-separated severities, e.g. "critical,high". Unknown values are dropped. */
const severities = z
  .string()
  .optional()
  .transform((s) => {
    const list = (s ?? "").split(",").filter((v) => (SEVERITIES as readonly string[]).includes(v));
    return list.length ? list.join(",") : undefined;
  })
  .catch(undefined)
  // zod 4 makes a transformed key required in the output type; the filter stays optional.
  .optional();

/** One grade to filter a list by: "A" to "F", or "none" for what was never scanned (ADR 0018). */
const grade = z.enum(GRADE_FILTER_VALUES).optional().catch(undefined);

export const findingSearch = z.object({
  state: z
    .enum([...FINDING_STATES, "all"])
    .optional()
    .catch(undefined),
  severity: severities,
  repositoryId: text(40),
  scanId: text(40),
  kev: flag,
  fixable: flag,
  q: text(120),
  /** First seen or resolved on these calendar days of the viewer's zone, inclusive (a day or week of the statistics). */
  firstSeenFrom: day,
  firstSeenTo: day,
  resolvedFrom: day,
  resolvedTo: day,
  cursor: text(512),
  pageSize,
  /** The finding shown in the detail pane. */
  id: text(40),
  /** Opens the AI panel (a drawer below the xwide layout step). */
  ai: flag,
  sort: sortOf(FINDING_SORTS),
  dir,
});
export type FindingSearch = z.infer<typeof findingSearch>;

export const fixSearch = z.object({
  /** "prs": the pull requests GarnetOps opened. Anything else is the list of proposals. */
  view: z.enum(["proposals", "prs"]).optional().catch(undefined),
  action: z.enum(["all", "edit", "manual"]).optional().catch(undefined),
  severity: severities,
  ecosystem: z.enum(["npm", "pypi", "go", "cargo", "composer", "other"]).optional().catch(undefined),
  pr: z.enum(["all", "none", "open", "merged", "closed", "failed"]).optional().catch(undefined),
  repositoryId: text(40),
  q: text(120),
  cursor: text(512),
  pageSize,
  /** The proposal shown in the detail pane. */
  id: text(40),
  sort: sortOf(FIX_SORTS),
  dir,
  /** Pull request list: filter by state. */
  prState: z.enum(["queued", "running", "open", "merged", "closed", "failed"]).optional().catch(undefined),
});
export type FixSearch = z.infer<typeof fixSearch>;

export const repositorySearch = z.object({
  status: z.enum(["all", "blocked", "attention", "clean"]).optional().catch(undefined),
  grade,
  q: text(100),
  cursor: text(512),
  pageSize,
  /** Opens the "Add repository" dialog. */
  add: flag,
  sort: sortOf(REPOSITORY_SORTS),
  dir,
});
export type RepositorySearch = z.infer<typeof repositorySearch>;

/** The repository page has two lists, each with its own position in the URL. */
export const repositoryDetailSearch = z.object({
  scans: text(512),
  scansPageSize: pageSize,
  patches: text(512),
  patchesPageSize: pageSize,
});
export type RepositoryDetailSearch = z.infer<typeof repositoryDetailSearch>;

export const packageSearch = z.object({
  q: text(200),
  repositoryId: text(40),
  vulnerable: flag,
  cursor: text(512),
  pageSize,
  sort: sortOf(PACKAGE_SORTS),
  dir,
});
export type PackageSearch = z.infer<typeof packageSearch>;

export const AUDIT_FILTERS = [
  "auth",
  "directory",
  "account",
  "repository",
  "finding",
  "gate",
  "team",
  "notification",
  "ai",
  "organization",
  "update",
  "fix_pr",
  "forge_connection",
] as const;
export const auditSearch = z.object({
  /** Action group; the API filters by the prefix "<group>.". */
  group: z.enum(AUDIT_FILTERS).optional().catch(undefined),
  cursor: text(512),
  pageSize,
});
export type AuditSearch = z.infer<typeof auditSearch>;

/** The ranges the statistics page offers (STATISTICS_RANGES in packages/db). */
export const STATISTICS_RANGES = [30, 90, 365] as const;
export type StatisticsRange = (typeof STATISTICS_RANGES)[number];
export const statisticsSearch = z.object({
  days: z.coerce
    .number()
    .refine((n): n is StatisticsRange => (STATISTICS_RANGES as readonly number[]).includes(n))
    .optional()
    .catch(undefined),
});
export type StatisticsSearch = z.infer<typeof statisticsSearch>;

export const gateSearch = z.object({
  cursor: text(512),
  pageSize,
  /** The repository whose gate tokens and pipeline step are shown. */
  repositoryId: text(40),
});
export type GateSearch = z.infer<typeof gateSearch>;

export const SETTINGS_SECTIONS = [
  "scanning",
  "accounts",
  "signin",
  "notifications",
  "ai",
  "updates",
  "about",
] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];
export const settingsSearch = z.object({
  section: z.enum(SETTINGS_SECTIONS).optional().catch(undefined),
});

export const ACCOUNT_SECTIONS = [
  "profile",
  "password",
  "authenticator",
  "passkeys",
  "sessions",
  "notifications",
] as const;
export type AccountSection = (typeof ACCOUNT_SECTIONS)[number];
export const accountSearch = z.object({
  section: z.enum(ACCOUNT_SECTIONS).optional().catch(undefined),
});

/** Builds an API query string from search params, leaving out empty values and UI-only keys. */
export function toQuery(search: Record<string, unknown>, uiOnly: string[] = []): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    if (uiOnly.includes(key) || value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

export { DEFAULT_PAGE_SIZE };

/** Open pull requests with their gate result (ADR 0032). */
export const pullRequestSearch = z.object({
  repositoryId: text(40),
  gate: z.enum(["passed", "notes", "blocked", "checking", "none"]).optional().catch(undefined),
  q: text(120),
});
export type PullRequestSearch = z.infer<typeof pullRequestSearch>;

/** Early warnings (ADR 0029): open ones, or the ones a scan closed in the last 30 days. */
export const earlyWarningSearch = z.object({
  state: z.enum(["open", "closed"]).optional().catch(undefined),
  repositoryId: text(40),
});
export type EarlyWarningSearch = z.infer<typeof earlyWarningSearch>;
