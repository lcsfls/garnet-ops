import { isTimeZone, openFindingsTrend, schema } from "@garnetops/db";
import { and, count, desc, eq, inArray, isNull, or, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";

const f = schema.finding;

/**
 * Everything the overview page shows. Each number has a matching filter in the
 * web app, so every tile links to the list that explains it.
 */
/**
 * Organisation events every member may see on the overview (mockup "Activity"). Only
 * actions whose subject the viewer can see anyway; sign-ins, IP addresses and export
 * details stay in the audit log, which only admins read.
 */
const ACTIVITY_ACTIONS = [
  "repository.created",
  "repository.deleted",
  "finding.accepted",
  "finding.reopened",
  "organization.scan_schedule_changed",
  "update.succeeded",
  "update.failed",
];
const ACTIVITY_LIMIT = 8;

type ActivityItem = {
  kind: string;
  at: Date;
  actorName: string | null;
  /** What it was about: a repository name, a vulnerability id or a version. */
  subject: string | null;
  /** For nightly scans: how many repositories were queued. */
  count: number | null;
};

function repositoryNameOf(url: unknown): string | null {
  if (typeof url !== "string") return null;
  return (
    url
      .replace(/\.git$/, "")
      .split(/[/:]/)
      .filter(Boolean)
      .pop() ?? null
  );
}

async function activity(organizationId: string): Promise<ActivityItem[]> {
  const a = schema.auditLog;
  const [entries, runs] = await Promise.all([
    db
      .select({
        action: a.action,
        at: a.createdAt,
        data: a.data,
        targetId: a.targetId,
        actorName: schema.user.name,
      })
      .from(a)
      .leftJoin(schema.user, eq(schema.user.id, a.actorUserId))
      .where(
        and(
          inArray(a.action, ACTIVITY_ACTIONS),
          or(eq(a.organizationId, organizationId), and(isNull(a.organizationId), eq(a.source, "updater"))),
        ),
      )
      .orderBy(desc(a.createdAt), desc(a.id))
      .limit(ACTIVITY_LIMIT),
    db
      .select({ at: schema.scanScheduleRun.createdAt, queued: schema.scanScheduleRun.queuedScans })
      .from(schema.scanScheduleRun)
      .where(eq(schema.scanScheduleRun.organizationId, organizationId))
      .orderBy(desc(schema.scanScheduleRun.createdAt))
      .limit(ACTIVITY_LIMIT),
  ]);
  const findingIds = entries
    .filter((e) => e.action.startsWith("finding.") && e.targetId)
    .map((e) => e.targetId as string);
  const vulns = findingIds.length
    ? await db
        .select({ id: f.id, vulnerabilityId: f.vulnerabilityId })
        .from(f)
        .where(and(eq(f.organizationId, organizationId), inArray(f.id, findingIds)))
    : [];
  const vulnOf = new Map(vulns.map((v) => [v.id, v.vulnerabilityId]));
  const items: ActivityItem[] = [
    ...entries.map((e) => {
      const data = (e.data ?? {}) as Record<string, unknown>;
      const subject = e.action.startsWith("repository.")
        ? repositoryNameOf(data.url)
        : e.action.startsWith("finding.")
          ? (vulnOf.get(e.targetId ?? "") ?? null)
          : typeof data.version === "string"
            ? data.version
            : null;
      return { kind: e.action, at: e.at, actorName: e.actorName ?? null, subject, count: null };
    }),
    ...runs.map((r) => ({
      kind: "schedule.run",
      at: r.at,
      actorName: null,
      subject: null,
      count: r.queued,
    })),
  ];
  return items.sort((x, y) => y.at.getTime() - x.at.getTime()).slice(0, ACTIVITY_LIMIT);
}

const query = z.object({
  tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC"),
});

export const overviewRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const { organizationId } = c.get("actor");
  // Calendar days of the trend are the viewer's days; the browser sends its IANA zone.
  const { tz: timeZone } = query.parse(c.req.query());

  const [
    bySeverity,
    byState,
    kevOpen,
    fixableBySeverity,
    repoStats,
    fixFirst,
    recentScans,
    trend,
    lastDb,
    events,
    vulnDb,
  ] = await Promise.all([
    db
      .select({ severity: f.severity, n: count() })
      .from(f)
      .where(and(eq(f.organizationId, organizationId), eq(f.state, "open")))
      .groupBy(f.severity),
    db
      .select({ state: f.state, n: count() })
      .from(f)
      .where(eq(f.organizationId, organizationId))
      .groupBy(f.state),
    db
      .select({ n: count() })
      .from(f)
      .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, f.vulnerabilityId))
      .where(
        and(
          eq(f.organizationId, organizationId),
          eq(f.state, "open"),
          eq(schema.vulnerability.knownExploited, true),
        ),
      ),
    db
      .select({ severity: f.severity, n: count() })
      .from(f)
      .where(
        and(
          eq(f.organizationId, organizationId),
          eq(f.state, "open"),
          sql`jsonb_array_length(coalesce(${f.fixedIn}, '[]'::jsonb)) > 0`,
        ),
      )
      .groupBy(f.severity),
    db.execute<{ total: number; blocked: number; attention: number; never_scanned: number }>(sql`
      select
        count(*)::int as total,
        count(*) filter (where exists (
          select 1 from finding x where x.repository_id = r.id and x.state = 'open' and x.severity = 'critical'))::int as blocked,
        count(*) filter (where exists (
          select 1 from finding x where x.repository_id = r.id and x.state = 'open' and x.severity = 'high')
          and not exists (
          select 1 from finding x where x.repository_id = r.id and x.state = 'open' and x.severity = 'critical'))::int as attention,
        count(*) filter (where r.last_scan_at is null)::int as never_scanned
      from repository r where r.organization_id = ${organizationId}`),
    db
      .select({
        id: f.id,
        severity: f.severity,
        packageName: f.packageName,
        packageVersion: f.packageVersion,
        packageType: f.packageType,
        vulnerabilityId: f.vulnerabilityId,
        repositoryId: f.repositoryId,
        repositoryName: schema.repository.name,
        fixedIn: f.fixedIn,
        knownExploited: schema.vulnerability.knownExploited,
      })
      .from(f)
      .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, f.vulnerabilityId))
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
      .where(and(eq(f.organizationId, organizationId), eq(f.state, "open")))
      .orderBy(
        desc(schema.vulnerability.knownExploited),
        desc(f.severityRank),
        desc(f.lastSeenAt),
        desc(f.id),
      )
      .limit(5),
    db
      .select({
        id: schema.scan.id,
        state: schema.scan.state,
        repositoryId: schema.scan.repositoryId,
        repositoryName: schema.repository.name,
        newFindings: schema.scan.newFindings,
        resolvedFindings: schema.scan.resolvedFindings,
        finishedAt: schema.scan.finishedAt,
        createdAt: schema.scan.createdAt,
        error: schema.scan.error,
      })
      .from(schema.scan)
      .innerJoin(schema.repository, eq(schema.repository.id, schema.scan.repositoryId))
      .where(eq(schema.scan.organizationId, organizationId))
      .orderBy(desc(schema.scan.createdAt), desc(schema.scan.id))
      .limit(6),
    openFindingsTrend(db, { organizationId, timeZone }),
    // The vulnerability database and scanner versions the latest successful scan used.
    db
      .select({
        builtAt: schema.scan.vulnDbBuiltAt,
        scannerVersions: schema.scan.scannerVersions,
        scannedAt: schema.scan.finishedAt,
      })
      .from(schema.scan)
      .where(and(eq(schema.scan.organizationId, organizationId), eq(schema.scan.state, "succeeded")))
      .orderBy(desc(schema.scan.finishedAt), desc(schema.scan.id))
      .limit(1),
    activity(organizationId),
    // The advisory sources behind the findings so far (grype namespaces such as
    // "github:language:javascript" or "debian:distro:debian:12"). The table only holds
    // vulnerabilities that were found, so it says nothing about the database's size.
    db.execute<{ source: string }>(sql`
        select distinct split_part(v.namespace, ':', 1) as source
        from vulnerability v
        where v.namespace is not null
          and exists (select 1 from finding x where x.vulnerability_id = v.id and x.organization_id = ${organizationId})
        order by 1`),
  ]);

  const open: Record<string, number> = {};
  for (const row of bySeverity) open[row.severity] = row.n;
  const states: Record<string, number> = {};
  for (const row of byState) states[row.state] = row.n;

  return c.json({
    open,
    states,
    knownExploitedOpen: kevOpen[0]?.n ?? 0,
    fixableOpen: fixableBySeverity.reduce((sum, row) => sum + row.n, 0),
    fixableBySeverity: Object.fromEntries(fixableBySeverity.map((row) => [row.severity, row.n])),
    repositories: repoStats.rows[0] ?? { total: 0, blocked: 0, attention: 0, never_scanned: 0 },
    fixFirst,
    recentScans,
    trend: { timeZone, days: trend },
    vulnerabilityData: lastDb[0] ?? null,
    vulnerabilitySources: vulnDb.rows.map((row) => row.source),
    activity: events,
    generatedAt: new Date(),
  });
});
