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
  .catch(undefined);

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

export const HOST_SORTS = [
  "name",
  "grade",
  "address",
  "os",
  "packages",
  "critical",
  "high",
  "medium",
  "updates",
  "lastInventory",
] as const;

export const PROXMOX_SORTS = [
  "name",
  "vmid",
  "node",
  "status",
  "cpu",
  "mem",
  "disk",
  "uptime",
  "lastBackup",
  "snapshot",
] as const;

export const XDR_AGENT_STATUSES = [
  "active",
  "disconnected",
  "never_connected",
  "pending",
  "unknown",
] as const;
export const XDR_AGENT_SORTS = ["name", "status", "os", "version", "keepAlive", "vulnerabilities"] as const;
export const XDR_WINDOWS = ["24h", "7d", "30d"] as const;

/** The XDR page (ADR 0015): the period shown, and the agent list's filters and position. */
export const xdrSearch = z.object({
  period: z.enum(XDR_WINDOWS).optional().catch(undefined),
  q: text(100),
  status: z.enum(XDR_AGENT_STATUSES).optional().catch(undefined),
  group: z
    .preprocess(
      asString,
      z
        .string()
        .regex(/^[A-Za-z0-9._-]{1,128}$/)
        .optional(),
    )
    .catch(undefined),
  link: z.enum(["linked", "unlinked", "suggested"]).optional().catch(undefined),
  sort: sortOf(XDR_AGENT_SORTS),
  dir,
  cursor: text(512),
  pageSize,
  /** Opens the agent enrollment helper. */
  enroll: flag,
});
export type XdrSearch = z.infer<typeof xdrSearch>;

export const ATTACK_SORTS = ["count", "ip", "country", "asn", "firstSeen", "lastSeen", "score"] as const;

/** The Attacks page (ADR 0016): the period, and the filters, sort and position of the address table. */
export const attacksSearch = z.object({
  period: z.enum(XDR_WINDOWS).optional().catch(undefined),
  q: text(100),
  /** A country code, or "internal" / "unknown". */
  country: z
    .preprocess(
      asString,
      z
        .string()
        .regex(/^([A-Z]{2}|internal|unknown)$/)
        .optional(),
    )
    .catch(undefined),
  asn: z
    .preprocess(
      asString,
      z
        .string()
        .regex(/^\d{1,10}$/)
        .optional(),
    )
    .catch(undefined),
  agent: z
    .preprocess(
      asString,
      z
        .string()
        .regex(/^\d{1,8}$/)
        .optional(),
    )
    .catch(undefined),
  /** The agent's name, only to show on the filter chip. */
  agentName: text(128),
  group: z
    .preprocess(
      asString,
      z
        .string()
        .regex(/^[a-z_]{1,40}$/)
        .optional(),
    )
    .catch(undefined),
  sort: sortOf(ATTACK_SORTS),
  dir,
  cursor: text(512),
  pageSize,
});
export type AttacksSearch = z.infer<typeof attacksSearch>;

export const serverSearch = z.object({
  status: z.enum(["all", "vulnerable", "attention"]).optional().catch(undefined),
  grade,
  q: text(100),
  cursor: text(512),
  pageSize,
  /** Opens the "Add server" wizard; a server id continues the setup of that server. */
  add: z
    .preprocess(asString, z.union([z.literal("1"), z.string().regex(/^host_[a-z0-9]{10,40}$/)]).optional())
    .catch(undefined),
  /** Opens the CSV import. */
  import: flag,
  /** Opens the host key confirmation of this server. */
  key: text(40),
  sort: sortOf(HOST_SORTS),
  dir,
  /** "proxmox": the Proxmox tab (ADR 0012). Anything else is the list of servers. */
  view: z.enum(["servers", "proxmox", "wazuh"]).optional().catch(undefined),
  /** Wazuh tab: filters, sort and position of the agent list (ADR 0015). */
  wzQ: text(100),
  wzStatus: z.enum(XDR_AGENT_STATUSES).optional().catch(undefined),
  wzLink: z.enum(["linked", "unlinked", "suggested"]).optional().catch(undefined),
  wzSort: sortOf(XDR_AGENT_SORTS),
  wzDir: dir,
  wzCursor: text(512),
  wzPageSize: pageSize,
  /** Proxmox tab: filters, sort and position of the guest list. */
  pxQ: text(100),
  pxCluster: text(40),
  pxType: z.enum(["qemu", "lxc"]).optional().catch(undefined),
  pxStatus: z.enum(["running", "stopped", "paused", "other"]).optional().catch(undefined),
  pxNode: text(63),
  pxFlag: z.enum(["all", "stale", "untracked"]).optional().catch(undefined),
  pxSort: sortOf(PROXMOX_SORTS),
  pxDir: dir,
  pxCursor: text(512),
  pxPageSize: pageSize,
  /** The guest shown in the detail dialog. */
  guest: text(40),
  /** Opens "Add as server" for this guest. */
  addGuest: text(40),
});
export type ServerSearch = z.infer<typeof serverSearch>;

/** The server page has three lists, each with its own position in the URL. */
export const serverDetailSearch = z.object({
  findings: text(512),
  findingsPageSize: pageSize,
  findingState: z.enum(["open", "resolved", "all"]).optional().catch(undefined),
  /** Filters set by the grade link (ADR 0018): one severity, only those with a fix, only known exploited. */
  findingSeverity: z.enum(["critical", "high", "medium", "low"]).optional().catch(undefined),
  findingFixable: flag,
  findingKev: flag,
  findingSort: sortOf(["vulnerability", "cvss", "epss", "package", "firstSeen"] as const),
  findingDir: dir,
  packages: text(512),
  packagesPageSize: pageSize,
  packageQ: text(120),
  updates: flag,
  runs: text(512),
  runsPageSize: pageSize,
  key: flag,
});
export type ServerDetailSearch = z.infer<typeof serverDetailSearch>;

export const AUDIT_FILTERS = [
  "auth",
  "account",
  "repository",
  "host",
  "finding",
  "gate",
  "team",
  "notification",
  "proxmox",
  "xdr",
  "attacks",
  "ai",
  "organization",
  "update",
  "fix_pr",
] as const;
export const auditSearch = z.object({
  /** Action group; the API filters by the prefix "<group>.". */
  group: z.enum(AUDIT_FILTERS).optional().catch(undefined),
  cursor: text(512),
  pageSize,
});
export type AuditSearch = z.infer<typeof auditSearch>;

export const gateSearch = z.object({
  cursor: text(512),
  pageSize,
  /** The repository whose gate tokens and pipeline step are shown. */
  repositoryId: text(40),
});
export type GateSearch = z.infer<typeof gateSearch>;

export const SETTINGS_SECTIONS = [
  "scanning",
  "notifications",
  "proxmox",
  "xdr",
  "attacks",
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
