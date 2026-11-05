import {
  groupRemedies,
  headlineFacts,
  type Remedy,
  type RemedyFinding,
  summarizeRemedies,
} from "@garnetops/core/remedies";
import {
  activeRepository,
  isTimeZone,
  openFindingsTrend,
  schema,
  type Viewer,
  visibleRepository,
} from "@garnetops/db";
import { and, count, desc, eq, inArray, isNull, or, type SQL, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";
import { loadProposals } from "../lib/fix-proposals.ts";

const f = schema.finding;

/**
 * What happened recently (the overview's "Activity"), newest first: scans that finished or failed, gate checks a pipeline
 * asked for, and organisation events every member may see. The same visibility as the rest of the overview: only
 * repositories the viewer sees, and only active ones (ADR 0030, 0043). Sign-ins, IP addresses and export details stay in
 * the audit log, which only admins read.
 *
 * Every successful scan also writes a gate run; the feed shows it once, as the scan. A gate check from a pipeline ("ci")
 * shows as the gate run. Nightly scans are one line per run ("Nightly scan of 12 repositories"); a nightly scan of one
 * repository shows on its own only when it failed or changed something.
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
const ACTIVITY_LIMIT = 10;

type ActivityItem = {
  /** "scan", "gate", "schedule.run" or an audit action such as "finding.accepted". */
  kind: string;
  at: Date;
  actorName: string | null;
  /** What it was about: a repository name, a vulnerability id or a version. */
  subject: string | null;
  /** For nightly scans: how many repositories were queued. */
  count: number | null;
  /** Added in 0.1.1, for scans and gate runs: the repository, the scan or gate state, the trigger and the changes. */
  id?: string;
  repositoryId?: string | null;
  status?: string | null;
  trigger?: string | null;
  added?: number | null;
  resolved?: number | null;
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

async function activity(viewer: Viewer): Promise<ActivityItem[]> {
  const { organizationId } = viewer;
  const a = schema.auditLog;
  const sc = schema.scan;
  const gr = schema.gateRun;
  const scanAt = sql<Date>`coalesce(${sc.finishedAt}, ${sc.createdAt})`;
  const [entries, runs, scans, gates] = await Promise.all([
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
          // Someone else's private repository (ADR 0030) is not news for everybody.
          sql`not (coalesce(${a.data}->>'visibility', '') = 'private' and ${a.actorUserId} is distinct from ${viewer.userId})`,
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
    db
      .select({
        id: sc.id,
        state: sc.state,
        trigger: sc.trigger,
        repositoryId: sc.repositoryId,
        repositoryName: schema.repository.name,
        added: sc.newFindings,
        resolved: sc.resolvedFindings,
        at: scanAt,
        actorName: schema.user.name,
      })
      .from(sc)
      .innerJoin(schema.repository, eq(schema.repository.id, sc.repositoryId))
      .leftJoin(schema.user, eq(schema.user.id, sc.requestedBy))
      .where(
        and(
          eq(sc.organizationId, organizationId),
          visibleRepository(sc.repositoryId, viewer),
          activeRepository(sc.repositoryId),
          inArray(sc.state, ["succeeded", "failed"]),
          // A pipeline's check shows as its gate run; one that failed has none, so it shows as the scan.
          or(sql`${sc.trigger} <> 'ci'`, eq(sc.state, "failed")),
          // Nightly scans are summed up per run; one shows on its own when it failed or changed something.
          or(
            sql`${sc.trigger} <> 'schedule'`,
            eq(sc.state, "failed"),
            sql`coalesce(${sc.newFindings}, 0) + coalesce(${sc.resolvedFindings}, 0) > 0`,
          ),
        ),
      )
      .orderBy(desc(scanAt), desc(sc.id))
      .limit(ACTIVITY_LIMIT),
    db
      .select({
        id: gr.id,
        result: gr.result,
        repositoryId: gr.repositoryId,
        repositoryName: schema.repository.name,
        at: gr.createdAt,
      })
      .from(gr)
      .innerJoin(schema.repository, eq(schema.repository.id, gr.repositoryId))
      .innerJoin(sc, eq(sc.id, gr.scanId))
      .where(
        and(
          eq(gr.organizationId, organizationId),
          visibleRepository(gr.repositoryId, viewer),
          activeRepository(gr.repositoryId),
          eq(sc.trigger, "ci"),
        ),
      )
      .orderBy(desc(gr.createdAt), desc(gr.id))
      .limit(ACTIVITY_LIMIT),
  ]);
  const findingIds = entries
    .filter((e) => e.action.startsWith("finding.") && e.targetId)
    .map((e) => e.targetId as string);
  const vulns = findingIds.length
    ? await db
        .select({ id: f.id, vulnerabilityId: f.vulnerabilityId })
        .from(f)
        .where(
          and(
            eq(f.organizationId, organizationId),
            visibleRepository(f.repositoryId, viewer),
            activeRepository(f.repositoryId),
            inArray(f.id, findingIds),
          ),
        )
    : [];
  const vulnOf = new Map(vulns.map((v) => [v.id, v.vulnerabilityId]));
  const items: ActivityItem[] = [
    // A finding of a repository the viewer does not see, or of one set aside, is left out.
    ...entries
      .filter((e) => !e.action.startsWith("finding.") || vulnOf.has(e.targetId ?? ""))
      .map((e) => {
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
    ...scans.map((s) => ({
      kind: "scan",
      at: new Date(s.at),
      actorName: s.trigger === "manual" ? (s.actorName ?? null) : null,
      subject: s.repositoryName,
      count: null,
      id: s.id,
      repositoryId: s.repositoryId,
      status: s.state,
      trigger: s.trigger,
      added: s.added,
      resolved: s.resolved,
    })),
    ...gates.map((g) => ({
      kind: "gate",
      at: g.at,
      actorName: null,
      subject: g.repositoryName,
      count: null,
      id: g.id,
      repositoryId: g.repositoryId,
      status: g.result,
      trigger: "ci",
    })),
  ];
  return items.sort((x, y) => y.at.getTime() - x.at.getTime()).slice(0, ACTIVITY_LIMIT);
}

/** How many upgrades "Fix first" lists; the summary below it counts all of them. */
const REMEDY_LIMIT = 6;
/** Repository names per upgrade; the count says how many there are in all. */
const REMEDY_REPOSITORY_NAMES = 5;

type ProposalRef = { count: number; key: string | null; repositoryId: string | null };

/** The fix proposals that carry out a remedy: same package, a target version, and at least one finding it closes. */
function proposalsFor(
  remedy: { packageType: string; packageName: string; findingIds: string[] },
  proposals: Awaited<ReturnType<typeof loadProposals>>["proposals"],
): ProposalRef {
  const ids = new Set(remedy.findingIds);
  const matching = proposals.filter(
    (p) =>
      p.targetVersion !== null &&
      p.packageType === remedy.packageType &&
      p.packageName === remedy.packageName &&
      p.findingIds.some((id) => ids.has(id)),
  );
  const only = matching.length === 1 ? matching[0] : undefined;
  return { count: matching.length, key: only?.key ?? null, repositoryId: only?.repositoryId ?? null };
}

function remedyDto(remedy: Remedy, proposals: ProposalRef) {
  return {
    key: remedy.key,
    packageType: remedy.packageType,
    packageName: remedy.packageName,
    ecosystem: remedy.ecosystem,
    fromVersion: remedy.fromVersion,
    toVersion: remedy.toVersion,
    complete: remedy.complete,
    laterVersion: remedy.laterVersion,
    closes: {
      total: remedy.closes.total,
      bySeverity: remedy.closes.bySeverity,
      knownExploited: remedy.closes.knownExploited,
      vulnerabilityIds: remedy.closes.vulnerabilityIds,
    },
    remainingVulnerabilityIds: remedy.remainingVulnerabilityIds,
    findings: remedy.findings,
    knownExploited: remedy.knownExploited,
    repositoryCount: remedy.repositories.length,
    repositories: remedy.repositories.slice(0, REMEDY_REPOSITORY_NAMES),
    proposals,
  };
}

/**
 * Everything the overview page shows. Each number has a matching filter in the web app, so every tile links to the list
 * that explains it.
 *
 * Since 0.1.1 the page reads `headline`, `remedies`, `remedySummary` and the scans and gate runs in `activity`.
 * `fixFirst` (the five worst findings) and `recentScans` stay in the answer unchanged for clients of 0.1.0; they will
 * be removed in a major release (AGENTS.md rule 2).
 */
const query = z.object({
  tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC"),
});

export const overviewRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const { organizationId } = actor;
  // The overview counts active repositories only; the ones set aside are left out (ADR 0043).
  const seen = and(visibleRepository(f.repositoryId, actor), activeRepository(f.repositoryId)) as SQL;
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
    remedyRows,
    { proposals },
  ] = await Promise.all([
    db
      .select({ severity: f.severity, n: count() })
      .from(f)
      .where(and(eq(f.organizationId, organizationId), seen, eq(f.state, "open")))
      .groupBy(f.severity),
    db
      .select({ state: f.state, n: count() })
      .from(f)
      .where(and(eq(f.organizationId, organizationId), seen))
      .groupBy(f.state),
    db
      .select({ n: count() })
      .from(f)
      .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, f.vulnerabilityId))
      .where(
        and(
          eq(f.organizationId, organizationId),
          seen,
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
          seen,
          eq(f.state, "open"),
          sql`jsonb_array_length(coalesce(${f.fixedIn}, '[]'::jsonb)) > 0`,
        ),
      )
      .groupBy(f.severity),
    db.execute<{
      total: number;
      blocked: number;
      attention: number;
      never_scanned: number;
      last_scan_at: string | null;
    }>(sql`
      select
        count(*)::int as total,
        count(*) filter (where exists (
          select 1 from finding x where x.repository_id = r.id and x.state = 'open' and x.severity = 'critical'))::int as blocked,
        count(*) filter (where exists (
          select 1 from finding x where x.repository_id = r.id and x.state = 'open' and x.severity = 'high')
          and not exists (
          select 1 from finding x where x.repository_id = r.id and x.state = 'open' and x.severity = 'critical'))::int as attention,
        count(*) filter (where r.last_scan_at is null)::int as never_scanned,
        max(r.last_scan_at) as last_scan_at
      from repository r where r.organization_id = ${organizationId} and r.inactive_at is null
        and (r.visibility = 'organization' or r.owner_user_id = ${actor.userId})`),
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
      .where(and(eq(f.organizationId, organizationId), seen, eq(f.state, "open")))
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
      .where(
        and(
          eq(schema.scan.organizationId, organizationId),
          visibleRepository(schema.scan.repositoryId, actor),
          // Like everything else here, without the repositories set aside (ADR 0043).
          activeRepository(schema.scan.repositoryId),
        ),
      )
      .orderBy(desc(schema.scan.createdAt), desc(schema.scan.id))
      .limit(6),
    openFindingsTrend(db, { organizationId, userId: actor.userId, timeZone }),
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
    activity(actor),
    // The advisory sources behind the findings so far (grype namespaces such as
    // "github:language:javascript" or "debian:distro:debian:12"). The table only holds
    // vulnerabilities that were found, so it says nothing about the database's size.
    db.execute<{ source: string }>(sql`
        select distinct split_part(v.namespace, ':', 1) as source
        from vulnerability v
        where v.namespace is not null
          and exists (select 1 from finding x where x.vulnerability_id = v.id and x.organization_id = ${organizationId})
        order by 1`),
    // The open findings behind "Fix first" and the top statement: every one with a fixed version, and every critical
    // and high one (with or without).
    db
      .select({
        id: f.id,
        repositoryId: f.repositoryId,
        repositoryName: schema.repository.name,
        vulnerabilityId: f.vulnerabilityId,
        severity: f.severity,
        severityRank: f.severityRank,
        packageType: f.packageType,
        packageName: f.packageName,
        packageVersion: f.packageVersion,
        fixedIn: f.fixedIn,
        knownExploited: schema.vulnerability.knownExploited,
      })
      .from(f)
      .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, f.vulnerabilityId))
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
      .where(
        and(
          eq(f.organizationId, organizationId),
          seen,
          eq(f.state, "open"),
          or(
            sql`jsonb_array_length(coalesce(${f.fixedIn}, '[]'::jsonb)) > 0`,
            inArray(f.severity, ["critical", "high"]),
          ),
        ),
      ),
    // The same proposals as the Fix proposals page, so "Open 2 fix proposals" finds two there.
    loadProposals(actor),
  ]);

  const open: Record<string, number> = {};
  for (const row of bySeverity) open[row.severity] = row.n;
  const states: Record<string, number> = {};
  for (const row of byState) states[row.state] = row.n;

  const remedyFindings: RemedyFinding[] = remedyRows.map((r) => ({ ...r, fixedIn: r.fixedIn ?? [] }));
  const remedies = groupRemedies(remedyFindings);
  const facts = headlineFacts(remedyFindings, remedies);
  const openTotal = Object.values(open).reduce((sum, n) => sum + n, 0);
  const proposalsOf = (remedy: Remedy) =>
    proposalsFor({ ...remedy, findingIds: remedy.closes.findingIds }, proposals);
  const one = facts.oneUpgrade ? remedies.find((r) => r.key === facts.oneUpgrade?.remedyKey) : undefined;

  return c.json({
    /** The top statement: the worst open severity, where it comes from and what fixes it (0.1.1). */
    headline: {
      ...facts,
      oneUpgrade: facts.oneUpgrade && one ? { ...facts.oneUpgrade, proposals: proposalsOf(one) } : null,
      /** False until one of the viewer's repositories was scanned: "nothing open" then means nothing yet. */
      scanned: (repoStats.rows[0]?.never_scanned ?? 0) < (repoStats.rows[0]?.total ?? 0),
    },
    /** "Fix first": open findings grouped by the upgrade that closes them, in the order to fix them (0.1.1). */
    remedies: remedies.slice(0, REMEDY_LIMIT).map((r) => remedyDto(r, proposalsOf(r))),
    remedySummary: summarizeRemedies(remedies, openTotal),
    open,
    states,
    knownExploitedOpen: kevOpen[0]?.n ?? 0,
    fixableOpen: fixableBySeverity.reduce((sum, row) => sum + row.n, 0),
    fixableBySeverity: Object.fromEntries(fixableBySeverity.map((row) => [row.severity, row.n])),
    // last_scan_at (0.1.1): the latest successful scan of the repositories the viewer sees ("Last scan 2 hours ago").
    repositories: repoStats.rows[0] ?? {
      total: 0,
      blocked: 0,
      attention: 0,
      never_scanned: 0,
      last_scan_at: null,
    },
    fixFirst,
    recentScans,
    trend: { timeZone, days: trend },
    vulnerabilityData: lastDb[0] ?? null,
    vulnerabilitySources: vulnDb.rows.map((row) => row.source),
    activity: events,
    generatedAt: new Date(),
  });
});
