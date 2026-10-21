/**
 * URL search params of the list views. Filters live in the URL so every tile
 * can link to a filtered view, links can be shared and the back button works.
 * Invalid values fall back to the default instead of breaking the page.
 */
import { DEFAULT_PAGE_SIZE, FINDING_STATES, PAGE_SIZES, SEVERITIES } from "@garnetops/core";
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

/** Comma-separated severities, e.g. "critical,high". Unknown values are dropped. */
const severities = z
  .string()
  .optional()
  .transform((s) => {
    const list = (s ?? "").split(",").filter((v) => (SEVERITIES as readonly string[]).includes(v));
    return list.length ? list.join(",") : undefined;
  })
  .catch(undefined);

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
});
export type FindingSearch = z.infer<typeof findingSearch>;

export const repositorySearch = z.object({
  status: z.enum(["all", "blocked", "attention", "clean"]).optional().catch(undefined),
  q: text(100),
  cursor: text(512),
  pageSize,
  /** Opens the "Add repository" dialog. */
  add: flag,
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
});
export type PackageSearch = z.infer<typeof packageSearch>;

export const AUDIT_FILTERS = ["auth", "repository", "finding", "organization", "update"] as const;
export const auditSearch = z.object({
  /** Action group; the API filters by the prefix "<group>.". */
  group: z.enum(AUDIT_FILTERS).optional().catch(undefined),
  cursor: text(512),
  pageSize,
});
export type AuditSearch = z.infer<typeof auditSearch>;

export const SETTINGS_SECTIONS = ["scanning", "updates", "about"] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];
export const settingsSearch = z.object({
  section: z.enum(SETTINGS_SECTIONS).optional().catch(undefined),
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
