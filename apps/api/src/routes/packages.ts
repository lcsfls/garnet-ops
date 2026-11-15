import { SEVERITY_RANK } from "@garnetops/core";
import { GRADES, parseGradeFilter } from "@garnetops/core/grades";
import { pageSizeSchema } from "@garnetops/core/pagination";
import {
  type DeprecationView,
  deprecatedSql,
  deprecationView,
  isTimeZone,
  packageStatusMatch,
  repositoryVisibleTo,
  schema,
  visibleRepository,
} from "@garnetops/db";
import { LANGUAGES, resources } from "@garnetops/i18n";
import { and, count, eq, ilike, like, type SQL, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { toCsv } from "../export/csv.ts";
import {
  CONTENT_TYPES,
  EXPORT_FORMATS,
  type ExportFormat,
  exportFileName,
  fill,
} from "../export/findings-report.ts";
import { packagesReport } from "../export/packages-report.ts";
import { toPdf } from "../export/pdf.ts";
import { toText } from "../export/txt.ts";
import { toXlsx } from "../export/xlsx.ts";
import { audit } from "../lib/audit.ts";
import type { AppEnv } from "../lib/context.ts";
import { gradeDistribution, gradeFilterSql, packageGradeRankSql } from "../lib/grades.ts";
import {
  type KeysetSpec,
  keysetQuery,
  parseNumber,
  parseText,
  type SortOption,
  sortSpec,
  toPage,
} from "../lib/paginate.ts";
import { notFound } from "../lib/problem.ts";

const p = schema.repositoryPackage;
const f = schema.finding;
const r = schema.repository;

/** The filters every request of this page shares: the list, the counts, the grades and the export. */
const filterQuery = z.object({
  /** Package name (substring), optionally with a version prefix: "lodash" or "lodash@4.17". */
  q: z.string().trim().max(200).optional(),
  repositoryId: z.string().max(40).optional(),
  /** Package type as syft names it ("npm", "python", "go-module"), added in 0.1.8. */
  type: z.string().trim().max(40).optional(),
  /** "1" = only packages with open findings. */
  vulnerable: z.enum(["1"]).optional(),
  /** "1" = only packages their registry calls deprecated or yanked (ADR 0051; nothing while the module is off). */
  deprecated: z.enum(["1"]).optional(),
  /**
   * Added in 0.1.8, as on the repositories page: "blocked" = an open critical finding, "attention" = an open high one and no
   * critical, "clean" = neither.
   */
  status: z.enum(["all", "blocked", "attention", "clean"]).default("all"),
  /** The grade the package gives (ADR 0018), one or more, comma-separated: "F,E". Added in 0.1.8. */
  grade: z
    .string()
    .optional()
    .transform((value, ctx) => {
      if (value === undefined || value === "") return undefined;
      const parsed = parseGradeFilter(value);
      if (!parsed) {
        ctx.addIssue({ code: "custom", message: "Use grades A to F separated by commas" });
        return z.NEVER;
      }
      return parsed;
    }),
  /**
   * Packages of active repositories (the default), of the ones set aside (ADR 0043), or both. Added in 0.1.8. A chosen repository
   * is listed whatever its state.
   */
  activity: z.enum(["active", "inactive", "all"]).default("active"),
});
type Filters = z.infer<typeof filterQuery>;

const listQuery = filterQuery.extend({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  /** Without a sort the list is by name and version. */
  sort: z.enum(["name", "type", "repository", "findings", "severity", "grade"]).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

const exportQuery = filterQuery.extend({
  format: z.enum(EXPORT_FORMATS),
  lang: z.enum(LANGUAGES).default("en"),
  tz: z.string().max(64).refine(isTimeZone, "Unknown time zone").default("UTC"),
});
const MAX_EXPORT_ROWS: Record<ExportFormat, number> = { csv: 50_000, xlsx: 50_000, txt: 50_000, pdf: 5_000 };
const WRITERS = { csv: toCsv, xlsx: toXlsx, pdf: toPdf, txt: toText } as const;

type Row = {
  id: string;
  name: string;
  version: string;
  type: string;
  purl: string | null;
  licenses: string[] | null;
  repositoryId: string;
  repositoryName: string;
  openFindings: number;
  worstSeverityRank: number | null;
  gradeRank: number;
  deprecation: { state: string; message: string | null } | null;
};

const spec: KeysetSpec<Row> = {
  keys: [p.name, p.version, p.id],
  direction: "asc",
  keyOf: (r) => [r.name, r.version, r.id],
  parse: [parseText, parseText, parseText],
};

const escapeLike = (s: string) => s.replace(/[%_\\]/g, "\\$&");

/** Open findings of this package in this repository. */
const openFor = sql`${f.repositoryId} = ${p.repositoryId} and ${f.packageName} = ${p.name}
  and ${f.packageVersion} = ${p.version} and ${f.packageType} = ${p.type} and ${f.state} = 'open'`;
const openCount = sql<number>`(select count(*)::int from ${f} where ${openFor})`;
const worstRank = sql<number | null>`(select max(${f.severityRank}) from ${f} where ${openFor})`;
/** The grade the package gives (ADR 0018): the grade rules over its own open findings. */
const gradeRank = packageGradeRankSql(
  sql`f.repository_id = ${p.repositoryId} and f.package_name = ${p.name} and f.package_version = ${p.version} and f.package_type = ${p.type}`,
);

/** Columns the list can be sorted by (table headers). */
const SORTS: Record<NonNullable<z.infer<typeof listQuery>["sort"]>, SortOption> = {
  name: { keys: [p.name, p.version], parse: [parseText, parseText], dir: "asc" },
  type: { keys: [p.type, p.name], parse: [parseText, parseText], dir: "asc" },
  repository: { keys: [r.name, p.name], parse: [parseText, parseText], dir: "asc" },
  findings: { keys: [openCount], parse: [parseNumber], dir: "desc" },
  severity: { keys: [sql`coalesce(${worstRank}, -1)`], parse: [parseNumber], dir: "desc" },
  grade: { keys: [gradeRank], parse: [parseNumber], dir: "desc" },
};

const CRITICAL = SEVERITY_RANK.critical;
const HIGH = SEVERITY_RANK.high;
function statusFilter(status: Filters["status"]): SQL | undefined {
  if (status === "blocked") return sql`${worstRank} = ${CRITICAL}`;
  if (status === "attention") return sql`${worstRank} = ${HIGH}`;
  if (status === "clean") return sql`coalesce(${worstRank}, -1) < ${HIGH}`;
  return undefined;
}

const repositoryIn = (inactive: boolean) =>
  sql`${p.repositoryId} in (select ${r.id} from ${r} where ${r.inactiveAt} ${inactive ? sql`is not null` : sql`is null`})`;

/**
 * The condition of the filters. `leave` names the ones a count leaves out (the status counts ignore the status, the grade counts
 * the grade; both ignore the activity, which they count on their own).
 */
function where(
  actor: { organizationId: string; userId: string },
  input: Filters,
  view: DeprecationView,
  leave: { status?: boolean; grade?: boolean; activity?: boolean } = {},
): SQL | undefined {
  // "name@version": the last "@" separates them, so scoped npm names (@scope/name) still work.
  const at = input.q ? input.q.lastIndexOf("@") : -1;
  const name = input.q && at > 0 ? input.q.slice(0, at) : input.q;
  const version = input.q && at > 0 ? input.q.slice(at + 1) : undefined;
  const pkg = { type: p.type, name: p.name, version: p.version };
  return and(
    eq(p.organizationId, actor.organizationId),
    visibleRepository(p.repositoryId, actor),
    // Over the whole organisation, repositories set aside are left out unless asked for (ADR 0043).
    input.repositoryId || leave.activity || input.activity === "all"
      ? undefined
      : repositoryIn(input.activity === "inactive"),
    name ? ilike(p.name, `%${escapeLike(name)}%`) : undefined,
    version ? like(p.version, `${escapeLike(version)}%`) : undefined,
    input.repositoryId ? eq(p.repositoryId, input.repositoryId) : undefined,
    input.type ? eq(p.type, input.type) : undefined,
    input.vulnerable ? sql`exists (select 1 from ${f} where ${openFor})` : undefined,
    input.deprecated ? deprecatedSql(view, pkg) : undefined,
    leave.status ? undefined : statusFilter(input.status),
    leave.grade || !input.grade ? undefined : gradeFilterSql(gradeRank, input.grade),
  );
}

const deprecationOf = (view: DeprecationView) => {
  const ps = schema.packageStatus;
  /** Added in 0.1.7: what the registry said, when it is deprecated or yanked and the module is on (ADR 0051). */
  return view.enabled
    ? sql<{
        state: string;
        message: string | null;
      } | null>`(select jsonb_build_object('state', ${ps.state}, 'message', ${ps.message})
        from ${ps} where ${packageStatusMatch(view, { type: p.type, name: p.name, version: p.version })}
        and ${ps.state} in ('deprecated', 'yanked') limit 1)`
    : sql<null>`null`;
};

const filterInput = (query: Record<string, string>) => filterQuery.parse(query);

/** Package inventory across the organisation's repositories, from each one's latest scan. */
export const packageRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const view = await deprecationView(db, actor.organizationId);
    const condition = where(actor, input, view);
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, p.id) : null;
    const activeSpec = (sorted?.spec ?? spec) as KeysetSpec<Row & { sortKeys?: (string | number | Date)[] }>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          sortKeys: sorted ? sorted.select : sql<null>`null`,
          id: p.id,
          name: p.name,
          version: p.version,
          type: p.type,
          purl: p.purl,
          licenses: p.licenses,
          repositoryId: p.repositoryId,
          repositoryName: r.name,
          openFindings: openCount,
          worstSeverityRank: worstRank,
          gradeRank,
          deprecation: deprecationOf(view),
        })
        .from(p)
        .innerJoin(r, eq(r.id, p.repositoryId))
        .where(and(condition, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(p).where(condition),
    ]);
    return c.json(
      toPage(
        activeSpec,
        q,
        rows as (Row & { sortKeys?: (string | number | Date)[] })[],
        totalRow[0]?.n ?? 0,
        input.pageSize,
        Boolean(input.cursor),
        // Added in 0.1.8: the grade the package gives (ADR 0018).
        ({ sortKeys: _keys, gradeRank: rank, ...row }) => ({ ...row, grade: GRADES[rank] ?? null }),
      ),
    );
  })
  /**
   * Counts for the page's toggles and the menu (0.1.8): per status over the chosen activity, the packages of repositories set aside,
   * and the package types there are.
   */
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = filterInput(c.req.query());
    const view = await deprecationView(db, actor.organizationId);
    const condition = where(actor, input, view, { status: true });
    const [statuses, inactive, types] = await Promise.all([
      db.execute<{ all: number; blocked: number; attention: number; clean: number }>(sql`
        select count(*)::int as "all",
          (count(*) filter (where w = ${CRITICAL}))::int as blocked,
          (count(*) filter (where w = ${HIGH}))::int as attention,
          (count(*) filter (where coalesce(w, -1) < ${HIGH}))::int as clean
        from (select ${worstRank} as w from ${p} where ${condition}) t`),
      input.repositoryId
        ? Promise.resolve([{ n: 0 }])
        : db
            .select({ n: count() })
            .from(p)
            .where(and(where(actor, input, view, { status: true, activity: true }), repositoryIn(true))),
      db
        .selectDistinct({ type: p.type })
        .from(p)
        .where(and(eq(p.organizationId, actor.organizationId), visibleRepository(p.repositoryId, actor)))
        .orderBy(p.type)
        .limit(100),
    ]);
    const row = statuses.rows[0];
    return c.json({
      all: row?.all ?? 0,
      blocked: row?.blocked ?? 0,
      attention: row?.attention ?? 0,
      clean: row?.clean ?? 0,
      inactive: inactive[0]?.n ?? 0,
      types: types.map((t) => t.type),
    });
  })
  /** How many packages give each grade (ADR 0018), for the grade filter (0.1.8). */
  .get("/grades", async (c) => {
    const actor = c.get("actor");
    const input = filterInput(c.req.query());
    const view = await deprecationView(db, actor.organizationId);
    return c.json(
      await gradeDistribution(
        db,
        gradeRank,
        sql`${p}`,
        where(actor, input, view, { grade: true }) ?? sql`true`,
      ),
    );
  })
  /**
   * The list as it is filtered, as a file (CSV, XLSX, PDF or text), like the findings export (0.1.8). The browser sends its zone
   * (dates in the file) and UI language (column names).
   */
  .get("/export", async (c) => {
    const actor = c.get("actor");
    const input = exportQuery.parse(c.req.query());
    const [repository] = input.repositoryId
      ? await db
          .select({ name: r.name })
          .from(r)
          .where(and(eq(r.id, input.repositoryId), repositoryVisibleTo(actor)))
      : [];
    if (input.repositoryId && !repository) throw notFound("Repository");
    const view = await deprecationView(db, actor.organizationId);
    const condition = where(actor, input, view);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          name: p.name,
          version: p.version,
          type: p.type,
          purl: p.purl,
          licenses: p.licenses,
          repositoryName: r.name,
          openFindings: openCount,
          worstSeverityRank: worstRank,
          gradeRank,
          deprecation: deprecationOf(view),
        })
        .from(p)
        .innerJoin(r, eq(r.id, p.repositoryId))
        .where(condition)
        .orderBy(sql`coalesce(${worstRank}, -1) desc`, p.name, p.version, p.id)
        .limit(MAX_EXPORT_ROWS[input.format]),
      db.select({ n: count() }).from(p).where(condition),
    ]);
    const total = totalRow[0]?.n ?? 0;

    // The filters in words, in the file's language.
    const m = resources[input.lang].translation;
    const x = m.packages.export;
    const filters = [
      input.status !== "all" ? fill(x.filterStatus, { status: m.repositories.status[input.status] }) : null,
      input.grade ? fill(x.filterGrade, { grade: input.grade.join(", ") }) : null,
      input.type ? fill(x.filterType, { type: input.type }) : null,
      input.vulnerable ? m.packages.vulnerableOnly : null,
      input.deprecated && view.enabled ? m.deprecated.filter : null,
      !input.repositoryId && input.activity === "inactive" ? x.filterInactive : null,
      !input.repositoryId && input.activity === "all" ? x.filterAllActivity : null,
      repository ? fill(m.export.filterRepository, { repository: repository.name }) : null,
      input.q ? fill(m.export.filterText, { text: input.q }) : null,
    ].filter((v): v is string => v !== null);

    const now = new Date();
    const report = packagesReport(
      rows.map(({ gradeRank: rank, ...row }) => ({ ...row, grade: GRADES[rank] ?? null })),
      {
        language: input.lang,
        timeZone: input.tz,
        filters,
        repositoryName: repository?.name ?? null,
        total,
        now,
      },
    );
    const file = WRITERS[input.format](report);
    await audit(actor, "package.exported", undefined, {
      format: input.format,
      count: rows.length,
      filters: filters.join(", ") || null,
    });
    return c.body(new Uint8Array(file), 200, {
      "content-type": CONTENT_TYPES[input.format],
      "content-disposition": `attachment; filename="${exportFileName(input.format, repository?.name ?? null, input.tz, now, "packages")}"`,
      "cache-control": "no-store",
    });
  });
