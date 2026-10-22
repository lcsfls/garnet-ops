/**
 * Grades A to F (ADR 0018) in SQL. The rules live in packages/core/src/grades.ts; this module
 * computes their inputs at query time, so accepted risks that expired count again without any
 * job having to reopen them first, and so lists can be sorted and filtered by grade.
 *
 * The same code serves repositories (`finding`) and servers (`host_finding`). Table and column
 * names below are constants, never user input.
 */
import {
  emptyGradeCounts,
  GRADE_RANK,
  GRADES,
  type Grade,
  type GradeCounts,
  type GradeFilterValue,
  type GradeRule,
  gradeOf,
  NOT_SCANNED_RANK,
} from "@garnetops/core/grades";
import type { Database } from "@garnetops/db";
import { type SQL, sql } from "drizzle-orm";

interface FindingSource {
  table: SQL;
  /** The column that points at the repository or server. */
  owner: SQL;
  /** Which rows are open for grading, over the alias `f`. */
  open: SQL;
}

/**
 * A finding of a repository counts while it is open, and also when an acceptance has run out
 * (the nightly scan only reopens it later). An acceptance without an end date does not expire,
 * as in the gate evaluation (apps/worker/src/scan.ts).
 */
export const REPOSITORY_FINDINGS: FindingSource = {
  table: sql.raw("finding"),
  owner: sql.raw("repository_id"),
  open: sql.raw(
    "(f.state = 'open' or (f.state = 'accepted' and f.accepted_until is not null and f.accepted_until <= now()))",
  ),
};

/** Server findings have no accepted state. */
export const HOST_FINDINGS: FindingSource = {
  table: sql.raw("host_finding"),
  owner: sql.raw("host_id"),
  open: sql.raw("f.state = 'open'"),
};

const hasFix = sql.raw("jsonb_array_length(coalesce(f.fixed_in, '[]'::jsonb)) > 0");

/** What each rule matches, over the aliases `f` (finding) and `v` (vulnerability). */
const RULE_MATCH: Record<Exclude<GradeRule, "none">, SQL> = {
  "known-exploited-with-fix": sql`(v.known_exploited and ${hasFix})`,
  "critical-with-fix": sql`(f.severity = 'critical' and ${hasFix})`,
  "high-with-fix": sql`(f.severity = 'high' and ${hasFix})`,
  "critical-without-fix": sql`(f.severity = 'critical' and not ${hasFix})`,
  "medium-with-fix": sql`(f.severity = 'medium' and ${hasFix})`,
  "high-without-fix": sql`(f.severity = 'high' and not ${hasFix})`,
  "other-open": sql`true`,
};

/** The grade rank (0 = A to 5 = F) one open finding gives, as a SQL expression. */
const findingRank = sql`(case
  when v.known_exploited and ${hasFix} then 5
  when f.severity = 'critical' and ${hasFix} then 4
  when (f.severity = 'high' and ${hasFix}) or f.severity = 'critical' then 3
  when (f.severity = 'medium' and ${hasFix}) or f.severity = 'high' then 2
  else 1 end)`;

/**
 * The grade rank of one repository or server: 0 (A) to 5 (F) from its worst open finding,
 * or -1 when it was never scanned. `owner` is the id column of the outer row, `scanned` a
 * condition over the outer row that is true once a scan or inventory succeeded.
 */
export function gradeRankSql(source: FindingSource, owner: SQL, scanned: SQL): SQL<number> {
  return sql<number>`(case when ${scanned} then coalesce((
    select max(${findingRank})
    from ${source.table} f join vulnerability v on v.id = f.vulnerability_id
    where f.${source.owner} = ${owner} and ${source.open}
  ), 0) else ${sql.raw(String(NOT_SCANNED_RANK))} end)`;
}

/** A condition on the rank expression for a grade filter ("F,E", "none"). */
export function gradeFilterSql(rank: SQL<number>, values: readonly GradeFilterValue[]): SQL {
  const ranks = values.map((v) => (v === "none" ? NOT_SCANNED_RANK : GRADE_RANK[v]));
  return sql`${rank} in (${sql.join(
    ranks.map((n) => sql.raw(String(n))),
    sql`, `,
  )})`;
}

/** Open findings per repository or server, in the buckets the grade rules read. */
export async function gradeCounts(
  db: Database,
  source: FindingSource,
  organizationId: string,
  ownerIds: readonly string[],
): Promise<Map<string, GradeCounts>> {
  const map = new Map<string, GradeCounts>();
  if (ownerIds.length === 0) return map;
  const result = await db.execute<{
    owner_id: string;
    kev_with_fix: number;
    critical_with_fix: number;
    critical_without_fix: number;
    high_with_fix: number;
    high_without_fix: number;
    medium_with_fix: number;
    medium_without_fix: number;
    other_open: number;
  }>(sql`
    select f.${source.owner} as owner_id,
      (count(*) filter (where ${RULE_MATCH["known-exploited-with-fix"]}))::int as kev_with_fix,
      (count(*) filter (where ${RULE_MATCH["critical-with-fix"]}))::int as critical_with_fix,
      (count(*) filter (where ${RULE_MATCH["critical-without-fix"]}))::int as critical_without_fix,
      (count(*) filter (where ${RULE_MATCH["high-with-fix"]}))::int as high_with_fix,
      (count(*) filter (where ${RULE_MATCH["high-without-fix"]}))::int as high_without_fix,
      (count(*) filter (where ${RULE_MATCH["medium-with-fix"]}))::int as medium_with_fix,
      (count(*) filter (where f.severity = 'medium' and not ${hasFix}))::int as medium_without_fix,
      (count(*) filter (where f.severity not in ('critical', 'high', 'medium')))::int as other_open
    from ${source.table} f join vulnerability v on v.id = f.vulnerability_id
    where f.organization_id = ${organizationId}
      and f.${source.owner} in (${sql.join(
        ownerIds.map((id) => sql`${id}`),
        sql`, `,
      )})
      and ${source.open}
    group by f.${source.owner}
  `);
  for (const row of result.rows) {
    map.set(row.owner_id, {
      kevWithFix: row.kev_with_fix,
      criticalWithFix: row.critical_with_fix,
      criticalWithoutFix: row.critical_without_fix,
      highWithFix: row.high_with_fix,
      highWithoutFix: row.high_without_fix,
      mediumWithFix: row.medium_with_fix,
      mediumWithoutFix: row.medium_without_fix,
      otherOpen: row.other_open,
    });
  }
  return map;
}

/**
 * One package that shows what the deciding rule is about: the one with the highest CVSS score
 * among the findings that match it, then by name, so the example does not jump around.
 */
async function examplePackages(
  db: Database,
  source: FindingSource,
  organizationId: string,
  rule: Exclude<GradeRule, "none">,
  ownerIds: readonly string[],
): Promise<Map<string, string>> {
  const result = await db.execute<{ owner_id: string; package_name: string }>(sql`
    select distinct on (f.${source.owner}) f.${source.owner} as owner_id, f.package_name
    from ${source.table} f join vulnerability v on v.id = f.vulnerability_id
    where f.organization_id = ${organizationId}
      and f.${source.owner} in (${sql.join(
        ownerIds.map((id) => sql`${id}`),
        sql`, `,
      )})
      and ${source.open} and ${RULE_MATCH[rule]}
    order by f.${source.owner}, v.cvss_score desc nulls last, f.package_name, f.id
  `);
  return new Map(result.rows.map((row) => [row.owner_id, row.package_name]));
}

/** What the API adds to a repository or server (additive fields, ADR 0018). */
export interface GradeFields {
  /** Null: never scanned, so there is nothing to grade. */
  grade: Grade | null;
  gradeReason: { rule: GradeRule; count: number; example: string | null } | null;
  /** The latest scan or inventory failed: the grade is that of the last successful one. */
  gradeStale: boolean;
}

const EXAMPLE_MAX = 200;

/**
 * The grade fields of the repositories or servers on one page. `scanned` is false before the
 * first successful scan, `failed` when the latest attempt after it failed.
 */
export async function gradeFieldsOf(
  db: Database,
  source: FindingSource,
  organizationId: string,
  owners: readonly { id: string; scanned: boolean; failed: boolean }[],
): Promise<Map<string, GradeFields>> {
  const scannedIds = owners.filter((o) => o.scanned).map((o) => o.id);
  const counts = await gradeCounts(db, source, organizationId, scannedIds);
  const decided = new Map<string, ReturnType<typeof gradeOf>>();
  for (const id of scannedIds) decided.set(id, gradeOf(counts.get(id) ?? emptyGradeCounts()));

  // One query per rule that decided something on this page, for the example package.
  const byRule = new Map<Exclude<GradeRule, "none">, string[]>();
  for (const [id, result] of decided) {
    if (result.rule === "none") continue;
    byRule.set(result.rule, [...(byRule.get(result.rule) ?? []), id]);
  }
  const examples = new Map<string, string>();
  await Promise.all(
    [...byRule].map(async ([rule, ids]) => {
      for (const [id, name] of await examplePackages(db, source, organizationId, rule, ids)) {
        examples.set(id, name.slice(0, EXAMPLE_MAX));
      }
    }),
  );

  const out = new Map<string, GradeFields>();
  for (const owner of owners) {
    const result = decided.get(owner.id);
    out.set(
      owner.id,
      result
        ? {
            grade: result.grade,
            gradeReason: { rule: result.rule, count: result.count, example: examples.get(owner.id) ?? null },
            gradeStale: owner.failed,
          }
        : { grade: null, gradeReason: null, gradeStale: false },
    );
  }
  return out;
}

/**
 * How many repositories or servers have each grade, and how many none. `rank` is the grade
 * rank expression over the owner table `from`, `where` its filter.
 */
export async function gradeDistribution(
  db: Database,
  rank: SQL<number>,
  from: SQL,
  where: SQL,
): Promise<Record<Grade | "none", number>> {
  const result = await db.execute<{ g: number; n: number }>(
    sql`select g, count(*)::int as n from (select ${rank} as g from ${from} where ${where}) t group by g`,
  );
  const out = Object.fromEntries([...GRADES, "none" as const].map((g) => [g, 0])) as Record<
    Grade | "none",
    number
  >;
  for (const row of result.rows) {
    const grade = GRADES.find((g) => GRADE_RANK[g] === row.g);
    if (grade) out[grade] = row.n;
    else if (row.g === NOT_SCANNED_RANK) out.none = row.n;
  }
  return out;
}
