import { FINDING_STATES, SEVERITIES } from "@garnetops/core";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { isTimeZone, repositoryVisibleTo, schema, type Viewer, visibleRepository } from "@garnetops/db";
import { LANGUAGES, resources } from "@garnetops/i18n";
import { and, count, desc, eq, ilike, inArray, or, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { toCsv } from "../export/csv.ts";
import {
  CONTENT_TYPES,
  EXPORT_FORMATS,
  type ExportFormat,
  exportFileName,
  findingsReport,
} from "../export/findings-report.ts";
import { toPdf } from "../export/pdf.ts";
import { toText } from "../export/txt.ts";
import { toXlsx } from "../export/xlsx.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import {
  type KeysetSpec,
  keysetQuery,
  parseDate,
  parseInt10,
  parseNumber,
  parseText,
  type SortOption,
  sortSpec,
  toPage,
} from "../lib/paginate.ts";
import { notFound, ProblemError } from "../lib/problem.ts";

const f = schema.finding;
const v = schema.vulnerability;

const csv = <T extends string>(values: readonly T[]) =>
  z
    .string()
    .optional()
    .transform((s, ctx) => {
      if (!s) return [] as T[];
      const parts = s.split(",").filter(Boolean);
      for (const p of parts) {
        if (!(values as readonly string[]).includes(p)) {
          ctx.addIssue({ code: "custom", message: `Unknown value: ${p}` });
          return z.NEVER;
        }
      }
      return parts as T[];
    });

const day = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Expected YYYY-MM-DD")
  .refine((d) => {
    const date = new Date(`${d}T00:00:00Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().startsWith(d);
  }, "Not a calendar day");

/** Midnight at the start of a calendar day in a zone; the day after `to` ends an inclusive range. */
const startOf = (d: string, tz: string) => sql`(${d}::date)::timestamp at time zone ${tz}`;
const endOf = (d: string, tz: string) => sql`(${d}::date + 1)::timestamp at time zone ${tz}`;

/** Every filter a tile or link may set. Mirrors the web app's search params. */
export const findingFilters = z.object({
  state: z.enum([...FINDING_STATES, "all"]).default("open"),
  severity: csv(SEVERITIES),
  repositoryId: z.string().max(40).optional(),
  scanId: z.string().max(40).optional(),
  kev: z.enum(["1"]).optional(),
  fixable: z.enum(["1"]).optional(),
  q: z.string().trim().max(120).optional(),
  /** Calendar days, inclusive, in `tz`: first seen, or resolved, on these days (a day or week of the statistics). */
  firstSeenFrom: day.optional(),
  firstSeenTo: day.optional(),
  resolvedFrom: day.optional(),
  resolvedTo: day.optional(),
  tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC"),
});

/** Columns the list can be sorted by (table headers). Times are cut to milliseconds, which is what a cursor holds. */
const SORTS = {
  vulnerability: { keys: [f.vulnerabilityId], parse: [parseText], dir: "asc" },
  cvss: { keys: [sql`coalesce(${v.cvssScore}::numeric, -1)`], parse: [parseNumber], dir: "desc" },
  epss: { keys: [sql`coalesce(${v.epss}::numeric, -1)`], parse: [parseNumber], dir: "desc" },
  published: {
    keys: [sql`coalesce(date_trunc('milliseconds', ${v.publishedAt}), 'epoch'::timestamptz)`],
    parse: [parseDate],
    dir: "desc",
  },
  package: { keys: [f.packageName, f.packageVersion], parse: [parseText, parseText], dir: "asc" },
  repository: { keys: [schema.repository.name], parse: [parseText], dir: "asc" },
  firstSeen: { keys: [sql`date_trunc('milliseconds', ${f.firstSeenAt})`], parse: [parseDate], dir: "desc" },
} satisfies Record<string, SortOption>;

const listQuery = findingFilters.extend({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  /** Without a sort the list is worst first, then most recently seen. */
  sort: z.enum(Object.keys(SORTS) as [keyof typeof SORTS, ...(keyof typeof SORTS)[]]).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});
/**
 * Export of the list as it is filtered. The browser sends its zone (dates in the file)
 * and UI language (column names). A PDF holds fewer rows than a spreadsheet; the file
 * says when it does not contain every match.
 */
const exportQuery = findingFilters.extend({
  format: z.enum(EXPORT_FORMATS),
  lang: z.enum(LANGUAGES).default("en"),
});
const MAX_EXPORT_ROWS: Record<ExportFormat, number> = { csv: 50_000, xlsx: 50_000, txt: 50_000, pdf: 5_000 };
const WRITERS = { csv: toCsv, xlsx: toXlsx, pdf: toPdf, txt: toText } as const;

/** The state tabs show a count each, so counts ignore the state filter and apply all others. */
const countsQuery = findingFilters.omit({ state: true });

type Row = {
  id: string;
  severityRank: number;
  lastSeenAt: Date;
  severity: string;
  state: string;
  packageName: string;
  packageVersion: string;
  packageType: string;
  fixedIn: string[] | null;
  vulnerabilityId: string;
  knownExploited: boolean;
  cvssScore: number | null;
  epss: number | null;
  publishedAt: Date | null;
  repositoryId: string;
  repositoryName: string;
  firstSeenAt: Date;
};

// Worst first, then most recently seen. Matches the finding_list_idx index.
const spec: KeysetSpec<Row> = {
  keys: [f.severityRank, f.lastSeenAt, f.id],
  direction: "desc",
  keyOf: (row) => [row.severityRank, row.lastSeenAt, row.id],
  parse: [parseInt10, parseDate, parseText],
};

export function findingWhere(viewer: Viewer, input: z.infer<typeof findingFilters>) {
  const like = input.q ? `%${input.q.replace(/[%_\\]/g, "\\$&")}%` : null;
  return and(
    eq(f.organizationId, viewer.organizationId),
    visibleRepository(f.repositoryId, viewer),
    input.state === "all" ? undefined : eq(f.state, input.state),
    input.severity.length ? inArray(f.severity, input.severity) : undefined,
    input.repositoryId ? eq(f.repositoryId, input.repositoryId) : undefined,
    input.scanId ? eq(f.firstSeenScanId, input.scanId) : undefined,
    input.kev ? eq(v.knownExploited, true) : undefined,
    input.fixable ? sql`jsonb_array_length(coalesce(${f.fixedIn}, '[]'::jsonb)) > 0` : undefined,
    like ? or(ilike(f.packageName, like), ilike(f.vulnerabilityId, like)) : undefined,
    input.firstSeenFrom ? sql`${f.firstSeenAt} >= ${startOf(input.firstSeenFrom, input.tz)}` : undefined,
    input.firstSeenTo ? sql`${f.firstSeenAt} < ${endOf(input.firstSeenTo, input.tz)}` : undefined,
    input.resolvedFrom ? sql`${f.resolvedAt} >= ${startOf(input.resolvedFrom, input.tz)}` : undefined,
    input.resolvedTo ? sql`${f.resolvedAt} < ${endOf(input.resolvedTo, input.tz)}` : undefined,
  );
}

const acceptBody = z.object({
  reason: z.string().trim().min(10, "Explain in at least 10 characters why this risk is accepted").max(1000),
  /**
   * Instant the acceptance ends (ISO 8601 with offset); the web app sends the end of the
   * chosen day in the user's zone. Accepted risks reopen on the first scan after it.
   * At most one year: 366 days plus one more for the rest of the chosen day in any zone.
   */
  until: z.coerce
    .date()
    .refine((d) => d.getTime() > Date.now(), "The date must be in the future")
    .refine((d) => d.getTime() <= Date.now() + 367 * 24 * 3600 * 1000, "At most one year ahead"),
});

export const findingRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const where = findingWhere(actor, input);
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, f.id) : null;
    const activeSpec = (sorted?.spec ?? spec) as KeysetSpec<Row & { sortKeys?: (string | number | Date)[] }>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const base = db
      .select({
        sortKeys: sorted ? sorted.select : sql<null>`null`,
        id: f.id,
        severityRank: f.severityRank,
        lastSeenAt: f.lastSeenAt,
        severity: f.severity,
        state: f.state,
        packageName: f.packageName,
        packageVersion: f.packageVersion,
        packageType: f.packageType,
        fixedIn: f.fixedIn,
        vulnerabilityId: f.vulnerabilityId,
        knownExploited: v.knownExploited,
        cvssScore: v.cvssScore,
        epss: v.epss,
        publishedAt: v.publishedAt,
        repositoryId: f.repositoryId,
        repositoryName: schema.repository.name,
        firstSeenAt: f.firstSeenAt,
      })
      .from(f)
      .innerJoin(v, eq(v.id, f.vulnerabilityId))
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId));
    const [rows, totalRow] = await Promise.all([
      base
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(f).innerJoin(v, eq(v.id, f.vulnerabilityId)).where(where),
    ]);
    return c.json(
      toPage(
        activeSpec,
        q,
        rows as (Row & { sortKeys?: (string | number | Date)[] })[],
        totalRow[0]?.n ?? 0,
        input.pageSize,
        Boolean(input.cursor),
        ({ sortKeys: _keys, ...row }) => row,
      ),
    );
  })
  .get("/export", async (c) => {
    const actor = c.get("actor");
    const input = exportQuery.parse(c.req.query());
    const where = findingWhere(actor, input);
    const [repository] = input.repositoryId
      ? await db
          .select({ name: schema.repository.name })
          .from(schema.repository)
          .where(and(eq(schema.repository.id, input.repositoryId), repositoryVisibleTo(actor)))
      : [];
    if (input.repositoryId && !repository) throw notFound("Repository");
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          severity: f.severity,
          vulnerabilityId: f.vulnerabilityId,
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          packageType: f.packageType,
          fixedIn: f.fixedIn,
          cvssScore: v.cvssScore,
          epss: v.epss,
          knownExploited: v.knownExploited,
          publishedAt: v.publishedAt,
          state: f.state,
          repositoryName: schema.repository.name,
          firstSeenAt: f.firstSeenAt,
          lastSeenAt: f.lastSeenAt,
          resolvedAt: f.resolvedAt,
          acceptedUntil: f.acceptedUntil,
        })
        .from(f)
        .innerJoin(v, eq(v.id, f.vulnerabilityId))
        .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
        .where(where)
        .orderBy(desc(f.severityRank), desc(f.lastSeenAt), desc(f.id))
        .limit(MAX_EXPORT_ROWS[input.format]),
      db.select({ n: count() }).from(f).innerJoin(v, eq(v.id, f.vulnerabilityId)).where(where),
    ]);
    const total = totalRow[0]?.n ?? 0;

    // The filters in words, in the file's language.
    const m = resources[input.lang].translation;
    const words = (template: string, params: Record<string, string>) =>
      template.replace(/\{(\w+)\}/g, (match, name: string) => params[name] ?? match);
    const filters = [
      input.state !== "all" ? words(m.export.filterState, { state: m.findingState[input.state] }) : null,
      input.severity.length
        ? words(m.export.filterSeverity, { severity: input.severity.map((s) => m.severity[s]).join(", ") })
        : null,
      repository ? words(m.export.filterRepository, { repository: repository.name }) : null,
      input.kev ? m.findings.knownExploitedOnly : null,
      input.fixable ? m.findings.fixableOnly : null,
      input.q ? words(m.export.filterText, { text: input.q }) : null,
      input.scanId ? words(m.export.filterScan, { scan: input.scanId }) : null,
      input.firstSeenFrom || input.firstSeenTo
        ? words(m.export.filterFirstSeen, { from: input.firstSeenFrom ?? "…", to: input.firstSeenTo ?? "…" })
        : null,
      input.resolvedFrom || input.resolvedTo
        ? words(m.export.filterResolved, { from: input.resolvedFrom ?? "…", to: input.resolvedTo ?? "…" })
        : null,
    ].filter((x): x is string => x !== null);

    const now = new Date();
    const report = findingsReport(rows, {
      language: input.lang,
      timeZone: input.tz,
      filters,
      repositoryName: repository?.name ?? null,
      total,
      now,
    });
    const file = WRITERS[input.format](report);
    await audit(actor, "finding.exported", undefined, {
      format: input.format,
      count: rows.length,
      filters: filters.join(", ") || null,
    });
    return c.body(new Uint8Array(file), 200, {
      "content-type": CONTENT_TYPES[input.format],
      "content-disposition": `attachment; filename="${exportFileName(input.format, repository?.name ?? null, input.tz, now)}"`,
      "cache-control": "no-store",
    });
  })
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = countsQuery.parse(c.req.query());
    const rows = await db
      .select({ state: f.state, severity: f.severity, n: count() })
      .from(f)
      .innerJoin(v, eq(v.id, f.vulnerabilityId))
      .where(findingWhere(actor, { ...input, state: "all" }))
      .groupBy(f.state, f.severity);
    const states: Record<(typeof FINDING_STATES)[number], number> = { open: 0, accepted: 0, resolved: 0 };
    const open: Record<string, number> = {};
    for (const row of rows) {
      states[row.state] += row.n;
      if (row.state === "open") open[row.severity] = row.n;
    }
    return c.json({ states, open });
  })
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select({
        finding: f,
        vulnerability: v,
        repository: { id: schema.repository.id, name: schema.repository.name, url: schema.repository.url },
      })
      .from(f)
      .innerJoin(v, eq(v.id, f.vulnerabilityId))
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
      .where(
        and(
          eq(f.id, c.req.param("id")),
          eq(f.organizationId, actor.organizationId),
          visibleRepository(f.repositoryId, actor),
        ),
      )
      .limit(1);
    if (!row) throw notFound("Finding");
    const { dedupKey: _internal, ...finding } = row.finding;
    return c.json({ ...finding, vulnerability: row.vulnerability, repository: row.repository });
  })
  /** Notes on a finding, newest first. Today they come from people taking over an AI suggestion (ADR 0013). */
  .get("/:id/notes", async (c) => {
    const actor = c.get("actor");
    const id = c.req.param("id");
    const [finding] = await db
      .select({ id: f.id })
      .from(f)
      .where(
        and(
          eq(f.id, id),
          eq(f.organizationId, actor.organizationId),
          visibleRepository(f.repositoryId, actor),
        ),
      )
      .limit(1);
    if (!finding) throw notFound("Finding");
    const n = schema.findingNote;
    const rows = await db
      .select({
        id: n.id,
        body: n.body,
        source: n.source,
        meta: n.meta,
        createdAt: n.createdAt,
        author: schema.user.name,
      })
      .from(n)
      .leftJoin(schema.user, eq(schema.user.id, n.authorUserId))
      .where(and(eq(n.findingId, id), eq(n.organizationId, actor.organizationId)))
      .orderBy(desc(n.createdAt), desc(n.id))
      .limit(50);
    return c.json(rows);
  })
  .post("/:id/accept", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = acceptBody.parse(await c.req.json());
    const id = c.req.param("id");
    const [row] = await db
      .update(f)
      .set({
        state: "accepted",
        acceptedReason: input.reason,
        acceptedUntil: input.until,
        acceptedBy: actor.userId,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(f.id, id),
          eq(f.organizationId, actor.organizationId),
          visibleRepository(f.repositoryId, actor),
          eq(f.state, "open"),
        ),
      )
      .returning({ id: f.id });
    if (!row) throw new ProblemError(409, "not-open", "Only open findings can be accepted");
    await audit(actor, "finding.accepted", { type: "finding", id }, { until: input.until.toISOString() });
    return c.json({ ok: true });
  })
  .post("/:id/reopen", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const id = c.req.param("id");
    const [row] = await db
      .update(f)
      .set({
        state: "open",
        acceptedReason: null,
        acceptedUntil: null,
        acceptedBy: null,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(f.id, id),
          eq(f.organizationId, actor.organizationId),
          visibleRepository(f.repositoryId, actor),
          eq(f.state, "accepted"),
        ),
      )
      .returning({ id: f.id });
    if (!row) throw new ProblemError(409, "not-accepted", "Only accepted findings can be reopened");
    await audit(actor, "finding.reopened", { type: "finding", id });
    return c.json({ ok: true });
  });
