/**
 * Data of the organisation report and of the websites at a glance (ADR 0047), shared by the API (download, page) and the
 * worker (report mail). Everything about repositories goes through the visibility conditions of ADR 0030 for the one person
 * the report is for, and leaves inactive repositories out (ADR 0043), exactly as the statistics do. Hosts and websites belong
 * to the whole organisation (ADR 0033, 0034) and are only included while their module is on.
 *
 * Calendar days are the reader's, cut by PostgreSQL with `AT TIME ZONE` (ADR 0005).
 */

import { effectiveVerification, type PassiveSnapshot, type VerifiableAsset } from "@garnetops/core/exposure";
import {
  compareCounts,
  compareWebsites,
  daysUntil,
  ENDING_SOON_DAYS,
  emptyCounts,
  HOST_STALE_AFTER_MS,
  isReportSeverity,
  type OrganizationReport,
  organizationNextSteps,
  type ReportPeriod,
  type ReportSeverity,
  type RiskRow,
  type SeverityCounts,
  vulnDbState,
  type WebsiteOverviewRow,
  worstOf,
} from "@garnetops/core/reports";
import { detectSoftware, judgeSoftware, SOFTWARE_NAMES } from "@garnetops/core/software";
import { vulnDbReportSchema } from "@garnetops/core/system-status";
import { type SQL, sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import * as schema from "./schema.ts";
import { isTimeZone } from "./trend.ts";
import { activeRepository, type Viewer, visibleRepository } from "./visibility.ts";

const SEVERITIES = sql`('critical', 'high', 'medium', 'low')`;
const TOP = 5;
const NAMES_MAX = 20;

/** Which modules are on for an organisation (ADR 0033, 0034). */
export async function reportModules(db: Database, organizationId: string) {
  const rows = await db.execute<{ websites: boolean | null; hosts: boolean | null }>(sql`
    select
      (select enabled from ${schema.exposureSettings} where organization_id = ${organizationId}) as websites,
      (select enabled from ${schema.hostSettings} where organization_id = ${organizationId}) as hosts`);
  const row = rows.rows[0];
  return { websites: row?.websites === true, hosts: row?.hosts === true };
}

/** The build time of the vulnerability database the worker reported last, or null. */
export async function currentVulnDbBuiltAt(db: Database): Promise<string | null> {
  const rows = await db.execute<{ data: unknown }>(
    sql`select data from ${schema.systemReport} where key = 'vulndb'`,
  );
  const parsed = vulnDbReportSchema.safeParse(rows.rows[0]?.data);
  return parsed.success && parsed.data.valid ? parsed.data.builtAt : null;
}

const counts = (rows: { severity: string; n: number }[]): SeverityCounts => {
  const out = emptyCounts();
  for (const row of rows) if (isReportSeverity(row.severity)) out[row.severity] += Number(row.n);
  return out;
};

/* -------------------------------------------------------------------------- */
/* Websites at a glance                                                        */
/* -------------------------------------------------------------------------- */

const record = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/** The certificate that ends first among the snapshot's TLS answers. */
function firstExpiry(tls: unknown): string | null {
  if (!Array.isArray(tls)) return null;
  const ends = tls.flatMap((t) => {
    const validTo = record(record(t)?.cert)?.validTo;
    return typeof validTo === "string" ? [validTo] : [];
  });
  return ends.sort()[0] ?? null;
}

/** Software of a snapshot's home page that is behind its line or on a line without fixes (ADR 0038). */
function softwareOf(http: unknown, now: Date): WebsiteOverviewRow["software"] {
  const h = record(http) as PassiveSnapshot["http"] | null;
  const out: WebsiteOverviewRow["software"] = { outdated: [], endOfLife: [] };
  if (!h || h.status === null) return out;
  for (const found of detectSoftware(h)) {
    const judged = judgeSoftware(found, now);
    const name = `${SOFTWARE_NAMES[found.product]} ${found.version}`;
    if (judged.status === "endOfLife") out.endOfLife.push(name);
    else if (judged.status === "outdated") out.outdated.push(name);
  }
  return out;
}

/**
 * Every website of the organisation with the state of its daily look, worst first: availability, the certificate's days
 * left, the worst open finding, software behind or without fixes, verification and when it was last looked at.
 */
export async function websitesOverview(
  db: Database,
  organizationId: string,
  now = new Date(),
): Promise<WebsiteOverviewRow[]> {
  const a = schema.exposureAsset;
  const f = schema.exposureFinding;
  const [assets, open, worst] = await Promise.all([
    db
      .select({
        id: a.id,
        kind: a.kind,
        value: a.value,
        verifyState: a.verifyState,
        includeSubdomains: a.includeSubdomains,
        uptimeEnabled: a.uptimeEnabled,
        uptimeState: a.uptimeState,
        uptimeSince: a.uptimeSince,
        lastPassiveAt: a.lastPassiveAt,
        passiveError: a.passiveError,
        tls: sql<unknown>`${a.passive} -> 'tls'`,
        http: sql<unknown>`${a.passive} -> 'http'`,
      })
      .from(a)
      .where(sql`${a.organizationId} = ${organizationId}`),
    db.execute<{ asset_id: string; severity: string; n: number }>(sql`
      select asset_id, severity, count(*)::int as n from ${f}
      where organization_id = ${organizationId} and state = 'open'
      group by asset_id, severity`),
    db.execute<{ asset_id: string; rule: string }>(sql`
      select distinct on (asset_id) asset_id, rule from ${f}
      where organization_id = ${organizationId} and state = 'open'
      order by asset_id, severity_rank desc, first_seen_at, id`),
  ]);
  const openBy = new Map<string, { severity: string; n: number }[]>();
  for (const row of open.rows) openBy.set(row.asset_id, [...(openBy.get(row.asset_id) ?? []), row]);
  const ruleBy = new Map(worst.rows.map((r) => [r.asset_id, r.rule]));
  const all: VerifiableAsset[] = assets.map((x) => ({
    id: x.id,
    kind: x.kind,
    value: x.value,
    verifyState: x.verifyState,
    includeSubdomains: x.includeSubdomains,
  }));

  const rows = assets.map((x, i): WebsiteOverviewRow => {
    const openCounts = counts(openBy.get(x.id) ?? []);
    const down = x.uptimeEnabled && x.uptimeState === "down";
    const findingsWorst = worstOf(openCounts);
    const worstSeverity: ReportSeverity | null =
      down && (findingsWorst === null || findingsWorst === "medium" || findingsWorst === "low")
        ? "high"
        : findingsWorst;
    const certificateExpires = firstExpiry(x.tls);
    return {
      id: x.id,
      value: x.value,
      kind: x.kind,
      verifyState: x.verifyState,
      verified: effectiveVerification(all[i] as VerifiableAsset, all).verified,
      availability: {
        enabled: x.uptimeEnabled,
        state: x.uptimeEnabled ? x.uptimeState : null,
        since: x.uptimeSince?.toISOString() ?? null,
      },
      certificateExpires,
      certificateDays: daysUntil(certificateExpires, now),
      open: openCounts,
      worst: worstSeverity,
      // The rule only names the worst when a finding is the worst, not when the site being down is.
      worstRule: worstSeverity === findingsWorst ? (ruleBy.get(x.id) ?? null) : null,
      software: softwareOf(x.http, now),
      lastCheckedAt: x.lastPassiveAt?.toISOString() ?? null,
      checkError: x.passiveError,
    };
  });
  return rows.sort(compareWebsites);
}

/* -------------------------------------------------------------------------- */
/* The organisation for a period                                               */
/* -------------------------------------------------------------------------- */

export interface OrganizationReportInput extends Viewer {
  period: ReportPeriod;
  now?: Date;
}

/**
 * The organisation report for one person and one period. `period.timeZone` decides the calendar days; "now" is the
 * instant of the counts that are not about the period (open now, accepted risks, hosts reporting).
 */
export async function organizationReport(
  db: Database,
  input: OrganizationReportInput,
): Promise<OrganizationReport> {
  const { period } = input;
  if (!isTimeZone(period.timeZone)) throw new RangeError(`Unknown time zone: ${period.timeZone}`);
  const now = input.now ?? new Date();
  const org = input.organizationId;
  const viewer: Viewer = { organizationId: input.organizationId, userId: input.userId };
  const tz = period.timeZone;
  const seen = (column: SQL) => sql`(${visibleRepository(column, viewer)} and ${activeRepository(column)})`;
  const local = (column: SQL) => sql`(${column} at time zone ${tz})::date`;
  const inPeriod = (column: SQL) => sql`${local(column)} between ${period.from}::date and ${period.to}::date`;
  const nowSql = sql`${now.toISOString()}::timestamptz`;

  const [orgRow, findings, accepted, repositories, gates, warnings, top, modules, builtAt] =
    await Promise.all([
      db.execute<{ name: string }>(sql`select name from ${schema.organization} where id = ${org}`),
      db.execute<{
        severity: string;
        open: number;
        fixable: number;
        exploited: number;
        opened: number;
        fixed: number;
      }>(sql`
      select x.severity,
        count(*) filter (where x.state = 'open')::int as open,
        count(*) filter (where x.state = 'open' and jsonb_array_length(coalesce(x.fixed_in, '[]'::jsonb)) > 0)::int as fixable,
        count(*) filter (where x.state = 'open' and v.known_exploited)::int as exploited,
        count(*) filter (where ${inPeriod(sql`x.first_seen_at`)})::int as opened,
        count(*) filter (where x.resolved_at is not null and ${inPeriod(sql`x.resolved_at`)})::int as fixed
      from ${schema.finding} x join ${schema.vulnerability} v on v.id = x.vulnerability_id
      where x.organization_id = ${org} and ${seen(sql`x.repository_id`)} and x.severity in ${SEVERITIES}
      group by x.severity`),
      db.execute<{ total: number; expired: number; soon: number }>(sql`
      select count(*)::int as total,
        count(*) filter (where x.accepted_until is not null and x.accepted_until <= ${nowSql})::int as expired,
        count(*) filter (where x.accepted_until > ${nowSql}
          and x.accepted_until <= ${nowSql} + ${`${ENDING_SOON_DAYS} days`}::interval)::int as soon
      from ${schema.finding} x
      where x.organization_id = ${org} and ${seen(sql`x.repository_id`)} and x.state = 'accepted'`),
      db.execute<{ id: string; name: string; ever: boolean; in_period: boolean; failed: number }>(sql`
      select r.id, r.name,
        exists (select 1 from ${schema.scan} s where s.repository_id = r.id and s.state = 'succeeded') as ever,
        exists (select 1 from ${schema.scan} s where s.repository_id = r.id and s.state = 'succeeded'
          and ${inPeriod(sql`coalesce(s.finished_at, s.created_at)`)}) as in_period,
        (select count(*) from ${schema.scan} s where s.repository_id = r.id and s.state = 'failed'
          and ${inPeriod(sql`coalesce(s.finished_at, s.created_at)`)})::int as failed
      from ${schema.repository} r
      where r.organization_id = ${org} and ${seen(sql`r.id`)}
      order by r.name, r.id`),
      db.execute<{ result: string; n: number }>(sql`
      select g.result, count(*)::int as n from ${schema.gateRun} g
      where g.organization_id = ${org} and ${seen(sql`g.repository_id`)} and ${inPeriod(sql`g.created_at`)}
      group by g.result`),
      db.execute<{ n: number }>(sql`
      select count(*)::int as n from ${schema.earlyWarning} w
      where w.organization_id = ${org} and w.state = 'open' and ${seen(sql`w.repository_id`)}`),
      db.execute<{ id: string; name: string; severity: string; n: number }>(sql`
      with ranked as (
        select x.repository_id as id,
          count(*) filter (where x.severity = 'critical') as c,
          count(*) filter (where x.severity = 'high') as h,
          count(*) filter (where x.severity = 'medium') as m,
          count(*) filter (where x.severity = 'low') as l
        from ${schema.finding} x
        where x.organization_id = ${org} and ${seen(sql`x.repository_id`)} and x.state = 'open' and x.severity in ${SEVERITIES}
        group by x.repository_id
        order by c desc, h desc, m desc, l desc, x.repository_id
        limit ${TOP}
      )
      select k.id, r.name, x.severity, count(*)::int as n
      from ranked k join ${schema.repository} r on r.id = k.id
      join ${schema.finding} x on x.repository_id = k.id and x.state = 'open' and x.severity in ${SEVERITIES}
      group by k.id, r.name, x.severity`),
      reportModules(db, org),
      currentVulnDbBuiltAt(db),
    ]);

  const findingsBy = (key: "open" | "opened" | "fixed" | "fixable" | "exploited") =>
    counts(findings.rows.map((r) => ({ severity: r.severity, n: r[key] })));
  const neverScanned = repositories.rows.filter((r) => !r.ever);
  const gateBy = Object.fromEntries(gates.rows.map((g) => [g.result, g.n]));
  const topRepositories = riskRows(top.rows);

  const [hosts, websites] = await Promise.all([
    modules.hosts ? hostsPart(db, org, now) : null,
    modules.websites ? websitesOverview(db, org, now) : null,
  ]);

  const exploited = findingsBy("exploited");
  const base: Omit<OrganizationReport, "nextSteps"> = {
    kind: "organization",
    generatedAt: now.toISOString(),
    organization: orgRow.rows[0]?.name ?? "",
    period,
    findings: {
      open: findingsBy("open"),
      opened: findingsBy("opened"),
      fixed: findingsBy("fixed"),
      fixableCritical: findingsBy("fixable").critical,
      knownExploited: exploited.critical + exploited.high + exploited.medium + exploited.low,
    },
    repositories: {
      total: repositories.rows.length,
      scanned: repositories.rows.filter((r) => r.in_period).length,
      failedScans: repositories.rows.reduce((sum, r) => sum + Number(r.failed), 0),
      neverScanned: neverScanned.slice(0, NAMES_MAX).map((r) => ({ id: r.id, name: r.name })),
      neverScannedCount: neverScanned.length,
    },
    gates: { passed: gateBy.passed ?? 0, notes: gateBy.notes ?? 0, blocked: gateBy.blocked ?? 0 },
    earlyWarnings: { repositories: warnings.rows[0]?.n ?? 0, runtime: hosts ? hosts.warnings : null },
    accepted: {
      total: accepted.rows[0]?.total ?? 0,
      expired: accepted.rows[0]?.expired ?? 0,
      endingSoon: accepted.rows[0]?.soon ?? 0,
    },
    top: { repositories: topRepositories, hosts: hosts ? hosts.top : null },
    hosts: hosts ? { total: hosts.total, notReporting: hosts.notReporting } : null,
    websites,
    vulnDb: vulnDbState(builtAt, now),
  };
  return { ...base, nextSteps: organizationNextSteps(base) };
}

function riskRows(rows: { id: string; name: string; severity: string; n: number }[]): RiskRow[] {
  const by = new Map<string, RiskRow>();
  for (const row of rows) {
    const entry = by.get(row.id) ?? { id: row.id, name: row.name, open: emptyCounts() };
    if (isReportSeverity(row.severity)) entry.open[row.severity] += Number(row.n);
    by.set(row.id, entry);
  }
  return [...by.values()].sort((a, b) => compareCounts(a.open, b.open) || a.name.localeCompare(b.name));
}

/**
 * Open findings per host from all three sources: its kernel, its own packages and the images of its containers (an image
 * that runs in several containers counts once).
 */
export function hostFindingsSql(organizationId: string, hostId?: string): SQL {
  const one = (column: SQL) => (hostId ? sql` and ${column} = ${hostId}` : sql``);
  return sql`(
    select k.host_id, k.severity from ${schema.hostKernelFinding} k
    where k.organization_id = ${organizationId}${one(sql`k.host_id`)}
    union all
    select p.host_id, p.severity from ${schema.hostPackageFinding} p
    where p.organization_id = ${organizationId}${one(sql`p.host_id`)}
    union all
    select i.host_id, cf.severity
    from (select distinct hc.host_id, hc.image_id from ${schema.hostContainer} hc
          where hc.organization_id = ${organizationId}${one(sql`hc.host_id`)}) i
    join ${schema.containerImageFinding} cf on cf.organization_id = ${organizationId} and cf.image_id = i.image_id
  )`;
}

async function hostsPart(db: Database, organizationId: string, now: Date) {
  const staleBefore = new Date(now.getTime() - HOST_STALE_AFTER_MS);
  const [hosts, open, warnings] = await Promise.all([
    db
      .select({
        id: schema.agentHost.id,
        name: schema.agentHost.name,
        last: schema.agentHost.lastInventoryAt,
      })
      .from(schema.agentHost)
      .where(sql`${schema.agentHost.organizationId} = ${organizationId}`)
      .orderBy(schema.agentHost.name, schema.agentHost.id),
    db.execute<{ host_id: string; severity: string; n: number }>(sql`
      select f.host_id, f.severity, count(*)::int as n from ${hostFindingsSql(organizationId)} f
      where f.severity in ${SEVERITIES} group by f.host_id, f.severity`),
    db.execute<{ n: number }>(sql`
      select count(*)::int as n from ${schema.runtimeEarlyWarning}
      where organization_id = ${organizationId} and state = 'open'`),
  ]);
  const names = new Map(hosts.map((h) => [h.id, h.name]));
  const top = riskRows(
    open.rows.flatMap((r) => {
      const name = names.get(r.host_id);
      return name === undefined ? [] : [{ id: r.host_id, name, severity: r.severity, n: r.n }];
    }),
  )
    .filter((r) => worstOf(r.open) !== null)
    .slice(0, TOP);
  return {
    total: hosts.length,
    notReporting: hosts
      .filter((h) => !h.last || h.last < staleBefore)
      .map((h) => ({ id: h.id, name: h.name, lastReportAt: h.last?.toISOString() ?? null })),
    top,
    warnings: warnings.rows[0]?.n ?? 0,
  };
}
