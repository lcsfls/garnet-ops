import { SEVERITY_RANK } from "@garnetops/core";
import { GRADES, parseGradeFilter } from "@garnetops/core/grades";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { schemeOfPackageType, selectTarget } from "@garnetops/core/versions";
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
import { affectedPackagesReport, packagesReport } from "../export/packages-report.ts";
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
  /** "affected" (0.1.9): one row per package with open findings, as the affected view lists them. */
  view: z.enum(["inventory", "affected"]).default("inventory"),
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

/*
 * The affected view (0.1.9): one row per package (type, name and version) with open findings, over all the repositories that have
 * it, worst first. Grouped rows have no stable unique key across sort orders, so this list pages by offset; it holds only
 * vulnerable packages, which keeps it short.
 */
const AFFECTED_SORTS = ["severity", "findings", "repositories", "name"] as const;
const affectedQuery = filterQuery.extend({
  /** The offset of the page, as the previous answer's `next` or `prev` gave it. */
  cursor: z
    .string()
    .regex(/^\d{1,7}$/)
    .optional(),
  pageSize: pageSizeSchema,
  sort: z.enum(AFFECTED_SORTS).default("severity"),
  dir: z.enum(["asc", "desc"]).optional(),
});
/** How many repository names one row carries; the count says how many there are. */
const AFFECTED_REPOSITORIES = 20;

interface AffectedRow {
  type: string;
  name: string;
  version: string;
  repositories: number;
  repositoryList: { id: string; name: string }[];
  openFindings: number;
  worstSeverityRank: number;
  gradeRank: number;
  deprecation: { state: string; message: string | null } | null;
}

/** The grouped packages with open findings, before the status and grade filters (they read the group's worst values). */
function affectedGroups(
  actor: { organizationId: string; userId: string },
  input: Filters,
  view: DeprecationView,
): SQL {
  const ps = schema.packageStatus;
  const g = { type: sql`g.type`, name: sql`g.name`, version: sql`g.version` };
  const deprecation = view.enabled
    ? sql`(select jsonb_build_object('state', ${ps.state}, 'message', ${ps.message}) from ${ps}
        where ${packageStatusMatch(view, g)} and ${ps.state} in ('deprecated', 'yanked') limit 1)`
    : sql`null`;
  const rows = sql`select ${p.type} as type, ${p.name} as name, ${p.version} as version, ${r.id} as repository_id,
      ${r.name} as repository_name, ${openCount} as open, ${worstRank} as worst, ${gradeRank} as grade_rank
    from ${p} join ${r} on ${r.id} = ${p.repositoryId}
    where ${where(actor, { ...input, vulnerable: "1" }, view, { status: true, grade: true }) ?? sql`true`}`;
  return sql`select g.*, ${deprecation} as deprecation from (
    select type, name, version, count(*)::int as repositories, sum(open)::int as open_findings, max(worst)::int as worst,
      max(grade_rank)::int as grade_rank,
      to_jsonb((array_agg(jsonb_build_object('id', repository_id, 'name', repository_name) order by repository_name, repository_id))[1:${sql.raw(String(AFFECTED_REPOSITORIES))}]) as repository_list
    from (${rows}) t group by type, name, version) g`;
}

function affectedStatus(status: Filters["status"]): SQL {
  if (status === "blocked") return sql`a.worst = ${CRITICAL}`;
  if (status === "attention") return sql`a.worst = ${HIGH}`;
  if (status === "clean") return sql`a.worst < ${HIGH}`;
  return sql`true`;
}

function affectedOrder(sort: (typeof AFFECTED_SORTS)[number], dir: "asc" | "desc" | undefined): SQL {
  const d = (natural: "asc" | "desc") => sql.raw((dir ?? natural) === "asc" ? "asc" : "desc");
  const tail = sql`a.name asc, a.version asc, a.type asc`;
  if (sort === "name") return sql`a.name ${d("asc")}, a.version ${d("asc")}, a.type asc`;
  if (sort === "findings") return sql`a.open_findings ${d("desc")}, a.worst desc, ${tail}`;
  if (sort === "repositories") return sql`a.repositories ${d("desc")}, a.worst desc, ${tail}`;
  // What to fix first: the grade (known exploited and fixable first), then the worst severity and the number of findings.
  return sql`a.grade_rank ${d("desc")}, a.worst ${d("desc")}, a.open_findings ${d("desc")}, a.repositories desc, ${tail}`;
}

async function affectedPage(
  actor: { organizationId: string; userId: string },
  input: Filters & { sort: (typeof AFFECTED_SORTS)[number]; dir?: "asc" | "desc" },
  view: DeprecationView,
  limit: number,
  offset: number,
): Promise<{ rows: AffectedRow[]; total: number }> {
  const filtered = sql`from (${affectedGroups(actor, input, view)}) a where ${affectedStatus(input.status)}
    and ${input.grade ? gradeFilterSql(sql<number>`a.grade_rank`, input.grade) : sql`true`}`;
  const [result, totalResult] = await Promise.all([
    db.execute<{
      type: string;
      name: string;
      version: string;
      repositories: number;
      repository_list: { id: string; name: string }[];
      open_findings: number;
      worst: number;
      grade_rank: number;
      deprecation: { state: string; message: string | null } | null;
    }>(
      sql`select a.* ${filtered} order by ${affectedOrder(input.sort, input.dir)} limit ${limit} offset ${offset}`,
    ),
    db.execute<{ n: number }>(sql`select count(*)::int as n ${filtered}`),
  ]);
  return {
    rows: result.rows.map((row) => ({
      type: row.type,
      name: row.name,
      version: row.version,
      repositories: row.repositories,
      repositoryList: row.repository_list ?? [],
      openFindings: row.open_findings,
      worstSeverityRank: row.worst,
      gradeRank: row.grade_rank,
      deprecation: row.deprecation,
    })),
    total: totalResult.rows[0]?.n ?? 0,
  };
}

/**
 * The lowest version that fixes every open finding of each package (the rule of the fix proposals, ADR 0014), from the findings
 * of the repositories the filters cover.
 */
async function fixesOf(
  actor: { organizationId: string; userId: string },
  input: Filters,
  rows: { type: string; name: string; version: string }[],
): Promise<Map<string, { version: string; majorUpgrade: boolean; unresolved: number } | null>> {
  const key = (t: string, n: string, v: string) => `${t}\u0000${n}\u0000${v}`;
  const vulnerabilities = new Map<string, Map<string, Set<string>>>();
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    const found = await db
      .select({
        type: f.packageType,
        name: f.packageName,
        version: f.packageVersion,
        id: f.vulnerabilityId,
        fixedIn: f.fixedIn,
      })
      .from(f)
      .where(
        and(
          eq(f.organizationId, actor.organizationId),
          eq(f.state, "open"),
          visibleRepository(f.repositoryId, actor),
          input.repositoryId
            ? eq(f.repositoryId, input.repositoryId)
            : input.activity === "all"
              ? undefined
              : sql`${f.repositoryId} in (select ${r.id} from ${r} where ${r.inactiveAt} ${input.activity === "inactive" ? sql`is not null` : sql`is null`})`,
          sql`(${f.packageType}, ${f.packageName}, ${f.packageVersion}) in (${sql.join(
            chunk.map((row) => sql`(${row.type}, ${row.name}, ${row.version})`),
            sql`, `,
          )})`,
        ),
      );
    for (const finding of found) {
      const k = key(finding.type, finding.name, finding.version);
      const byId = vulnerabilities.get(k) ?? new Map<string, Set<string>>();
      const fixes = byId.get(finding.id) ?? new Set<string>();
      for (const v of finding.fixedIn ?? []) fixes.add(v);
      byId.set(finding.id, fixes);
      vulnerabilities.set(k, byId);
    }
  }
  const out = new Map<string, { version: string; majorUpgrade: boolean; unresolved: number } | null>();
  for (const row of rows) {
    const k = key(row.type, row.name, row.version);
    const target = selectTarget({
      scheme: schemeOfPackageType(row.type),
      installed: row.version,
      vulnerabilities: [...(vulnerabilities.get(k) ?? new Map<string, Set<string>>())].map(([id, fixes]) => ({
        id,
        fixedIn: [...fixes],
      })),
    });
    out.set(
      k,
      target
        ? { version: target.version, majorUpgrade: target.majorUpgrade, unresolved: target.unresolved.length }
        : null,
    );
  }
  return out;
}
const fixKey = (row: { type: string; name: string; version: string }) =>
  `${row.type}\u0000${row.name}\u0000${row.version}`;

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
  /**
   * Added in 0.1.9: the affected view. One row per package with open findings over the repositories it is in, worst first, with
   * the version that fixes all of them.
   */
  .get("/affected", async (c) => {
    const actor = c.get("actor");
    const input = affectedQuery.parse(c.req.query());
    const view = await deprecationView(db, actor.organizationId);
    const offset = input.cursor ? Number(input.cursor) : 0;
    const { rows, total } = await affectedPage(actor, input, view, input.pageSize, offset);
    const fixes = await fixesOf(actor, input, rows);
    return c.json({
      items: rows.map(({ gradeRank: rank, ...row }) => ({
        ...row,
        grade: GRADES[rank] ?? null,
        fix: fixes.get(fixKey(row)) ?? null,
      })),
      total,
      pageSize: input.pageSize,
      next: offset + rows.length < total ? String(offset + input.pageSize) : null,
      prev: offset > 0 ? String(Math.max(0, offset - input.pageSize)) : null,
    });
  })
  /** Counts for the affected view's toggles, its grade filter and the menu (0.1.9): packages, not rows per repository. */
  .get("/affected/counts", async (c) => {
    const actor = c.get("actor");
    const input = filterInput(c.req.query());
    const view = await deprecationView(db, actor.organizationId);
    const grade = (n: number) => sql`(count(*) filter (where a.grade_rank = ${n}))::int`;
    const result = await db.execute<Record<string, number>>(sql`select count(*)::int as "all",
        (count(*) filter (where a.worst = ${CRITICAL}))::int as blocked,
        (count(*) filter (where a.worst = ${HIGH}))::int as attention,
        (count(*) filter (where a.worst < ${HIGH}))::int as clean,
        ${grade(0)} as "A", ${grade(1)} as "B", ${grade(2)} as "C", ${grade(3)} as "D", ${grade(4)} as "E", ${grade(5)} as "F"
      from (${affectedGroups(actor, input, view)}) a`);
    const row = result.rows[0] ?? {};
    const n = (k: string) => row[k] ?? 0;
    return c.json({
      all: n("all"),
      blocked: n("blocked"),
      attention: n("attention"),
      clean: n("clean"),
      grades: { A: n("A"), B: n("B"), C: n("C"), D: n("D"), E: n("E"), F: n("F"), none: 0 },
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
    const m = resources[input.lang].translation;
    const x = m.packages.export;
    const now = new Date();
    const context = (filters: string[], total: number) => ({
      language: input.lang,
      timeZone: input.tz,
      filters,
      repositoryName: repository?.name ?? null,
      total,
      now,
    });
    const send = async (report: Parameters<(typeof WRITERS)["csv"]>[0], count: number, filters: string[]) => {
      const file = WRITERS[input.format](report);
      await audit(actor, "package.exported", undefined, {
        format: input.format,
        view: input.view,
        count,
        filters: filters.join(", ") || null,
      });
      return c.body(new Uint8Array(file), 200, {
        "content-type": CONTENT_TYPES[input.format],
        "content-disposition": `attachment; filename="${exportFileName(input.format, repository?.name ?? null, input.tz, now, "packages")}"`,
        "cache-control": "no-store",
      });
    };
    // The filters in words, in the file's language.
    const filterWords = (statusLabels: Record<Filters["status"], string>) =>
      [
        input.status !== "all" ? fill(x.filterStatus, { status: statusLabels[input.status] }) : null,
        input.grade ? fill(x.filterGrade, { grade: input.grade.join(", ") }) : null,
        input.type ? fill(x.filterType, { type: input.type }) : null,
        input.vulnerable && input.view === "inventory" ? m.packages.vulnerableOnly : null,
        input.deprecated && view.enabled ? m.deprecated.filter : null,
        !input.repositoryId && input.activity === "inactive" ? x.filterInactive : null,
        !input.repositoryId && input.activity === "all" ? x.filterAllActivity : null,
        repository ? fill(m.export.filterRepository, { repository: repository.name }) : null,
        input.q ? fill(m.export.filterText, { text: input.q }) : null,
      ].filter((v): v is string => v !== null);

    if (input.view === "affected") {
      const filters = filterWords({ ...m.repositories.status, clean: m.packages.statusLower });
      const { rows, total } = await affectedPage(
        actor,
        { ...input, sort: "severity" },
        view,
        MAX_EXPORT_ROWS[input.format],
        0,
      );
      const fixes = await fixesOf(actor, input, rows);
      const report = affectedPackagesReport(
        rows.map(({ gradeRank: rank, ...row }) => ({
          ...row,
          grade: GRADES[rank] ?? null,
          fix: fixes.get(fixKey(row)) ?? null,
        })),
        context(filters, total),
      );
      return send(report, rows.length, filters);
    }

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
    const filters = filterWords(m.repositories.status);
    const report = packagesReport(
      rows.map(({ gradeRank: rank, ...row }) => ({ ...row, grade: GRADES[rank] ?? null })),
      context(filters, total),
    );
    return send(report, rows.length, filters);
  });
