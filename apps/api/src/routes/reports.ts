import { imageRefKey } from "@garnetops/core/agent";
import {
  hostReportDocument,
  organizationReportDocument,
  type RenderContext,
  type ReportMessages,
  repositoryReportDocument,
  toReportPdf,
} from "@garnetops/core/report-documents";
import {
  addCounts,
  emptyCounts,
  HOST_STALE_AFTER_MS,
  type HostReport,
  hostNextSteps,
  isReportSeverity,
  localParts,
  REPORT_FREQUENCIES,
  REPORT_RANGES,
  type ReportFindingRow,
  type RepositoryReport,
  rangePeriod,
  reportFileName,
  reportTimeZone,
  repositoryNextSteps,
  type SeverityCounts,
  vulnDbState,
} from "@garnetops/core/reports";
import {
  isTimeZone,
  mailChannelAvailable,
  organizationReport,
  repositoryVisibleTo,
  schema,
  websitesOverview,
} from "@garnetops/db";
import { LANGUAGES, resources } from "@garnetops/i18n";
import { and, desc, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import type { Actor, AppEnv } from "../lib/context.ts";
import { gradeFieldsOf, REPOSITORY_FINDINGS } from "../lib/grades.ts";
import { modulesOf } from "../lib/modules.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { updateOf, updatesByRef } from "./hosts.ts";

/**
 * Reports (ADR 0047): one repository, one host, the websites at a glance and the organisation for a period, as JSON for the
 * web app and as PDF to download. Every report is built for the person asking, with the same visibility as the rest of the
 * API: a repository they cannot see is a 404, and the organisation report only counts the repositories they see (ADR 0030).
 * Hosts and websites belong to the whole organisation and answer 409 `module-off` while their module is off.
 *
 * Downloads are audited and limited per person; they never contain secrets. The report mail settings live under `/me`.
 */

const TOP = 10;
const SEVERITIES = sql`('critical', 'high', 'medium', 'low')`;

const fileQuery = z.object({
  format: z.enum(["json", "pdf"]).default("json"),
  tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC"),
  lang: z.enum(LANGUAGES).default("en"),
});
const organizationQuery = fileQuery.extend({
  days: z.coerce
    .number()
    .int()
    .refine((d) => (REPORT_RANGES as readonly number[]).includes(d), "Unknown range")
    .default(7),
});

const messages = (lang: (typeof LANGUAGES)[number]): ReportMessages =>
  resources[lang].translation as unknown as ReportMessages;

async function requireModuleOn(organizationId: string, module: "hosts" | "websites") {
  const modules = await modulesOf(organizationId);
  if (!modules[module]) {
    throw new ProblemError(409, "module-off", "This module is switched off", undefined, { module });
  }
}

function pdfResponse(
  file: Buffer,
  name: string,
  ctx: RenderContext,
  now: Date,
): [Uint8Array<ArrayBuffer>, 200, Record<string, string>] {
  return [
    new Uint8Array(file),
    200,
    {
      "content-type": "application/pdf",
      "content-disposition": `attachment; filename="${reportFileName(name, localParts(now, ctx.timeZone).date)}"`,
      "cache-control": "no-store",
    },
  ];
}

const countsOf = (rows: { severity: string; n: number }[]): SeverityCounts => {
  const out = emptyCounts();
  for (const row of rows) if (isReportSeverity(row.severity)) out[row.severity] += Number(row.n);
  return out;
};

const findingRow = (row: {
  severity: string;
  vulnerability_id: string;
  package_name: string;
  package_version: string;
  fixed_in: string[] | null;
  known_exploited: boolean;
  where?: string;
}): ReportFindingRow | null =>
  isReportSeverity(row.severity)
    ? {
        severity: row.severity,
        vulnerabilityId: row.vulnerability_id,
        packageName: row.package_name,
        packageVersion: row.package_version,
        fixedIn: row.fixed_in ?? [],
        knownExploited: row.known_exploited,
        ...(row.where !== undefined ? { where: row.where } : {}),
      }
    : null;

/* -------------------------------------------------------------------------- */
/* One repository                                                              */
/* -------------------------------------------------------------------------- */

export async function repositoryReport(
  actor: Actor,
  id: string,
  now = new Date(),
): Promise<RepositoryReport> {
  const r = schema.repository;
  const [row] = await db
    .select()
    .from(r)
    .where(and(eq(r.id, id), repositoryVisibleTo(actor)))
    .limit(1);
  if (!row) throw notFound("Repository");
  const [lastScan, lastSuccessful, findings, accepted, gate, warnings, top] = await Promise.all([
    db
      .select({
        state: schema.scan.state,
        at: sql<Date>`coalesce(${schema.scan.finishedAt}, ${schema.scan.createdAt})`,
      })
      .from(schema.scan)
      .where(eq(schema.scan.repositoryId, row.id))
      .orderBy(desc(schema.scan.createdAt), desc(schema.scan.id))
      .limit(1),
    db
      .select({
        at: sql<Date>`coalesce(${schema.scan.finishedAt}, ${schema.scan.createdAt})`,
        commit: schema.scan.commitSha,
        packages: schema.scan.packageCount,
        vulnDbBuiltAt: schema.scan.vulnDbBuiltAt,
      })
      .from(schema.scan)
      .where(and(eq(schema.scan.repositoryId, row.id), eq(schema.scan.state, "succeeded")))
      .orderBy(desc(schema.scan.createdAt), desc(schema.scan.id))
      .limit(1),
    db.execute<{ severity: string; open: number; fixable: number; exploited: number }>(sql`
      select x.severity, count(*)::int as open,
        count(*) filter (where jsonb_array_length(coalesce(x.fixed_in, '[]'::jsonb)) > 0)::int as fixable,
        count(*) filter (where v.known_exploited)::int as exploited
      from ${schema.finding} x join ${schema.vulnerability} v on v.id = x.vulnerability_id
      where x.repository_id = ${row.id} and x.state = 'open' and x.severity in ${SEVERITIES}
      group by x.severity`),
    db.execute<{ total: number; expired: number }>(sql`
      select count(*)::int as total,
        count(*) filter (where accepted_until is not null and accepted_until <= ${now.toISOString()}::timestamptz)::int as expired
      from ${schema.finding} where repository_id = ${row.id} and state = 'accepted'`),
    db
      .select({ result: schema.gateRun.result, at: schema.gateRun.createdAt })
      .from(schema.gateRun)
      .where(eq(schema.gateRun.repositoryId, row.id))
      .orderBy(desc(schema.gateRun.createdAt), desc(schema.gateRun.id))
      .limit(1),
    db.execute<{ n: number; worst: string | null }>(sql`
      select count(*)::int as n,
        (array_agg(severity order by severity_rank desc))[1] as worst
      from ${schema.earlyWarning} where repository_id = ${row.id} and state = 'open'`),
    db.execute<{
      severity: string;
      vulnerability_id: string;
      package_name: string;
      package_version: string;
      fixed_in: string[] | null;
      known_exploited: boolean;
    }>(sql`
      select x.severity, x.vulnerability_id, x.package_name, x.package_version, x.fixed_in, v.known_exploited
      from ${schema.finding} x join ${schema.vulnerability} v on v.id = x.vulnerability_id
      where x.repository_id = ${row.id} and x.state = 'open' and x.severity in ${SEVERITIES}
      order by x.severity_rank desc, v.known_exploited desc, v.cvss_score desc nulls last, x.vulnerability_id, x.package_name
      limit ${TOP}`),
  ]);
  const grades = await gradeFieldsOf(db, REPOSITORY_FINDINGS, actor.organizationId, [
    { id: row.id, scanned: row.lastScanId !== null, failed: lastScan[0]?.state === "failed" },
  ]);
  const grade = grades.get(row.id);
  const exploited = countsOf(findings.rows.map((f) => ({ severity: f.severity, n: f.exploited })));
  const successful = lastSuccessful[0];
  const warning = warnings.rows[0];
  const base: Omit<RepositoryReport, "nextSteps"> = {
    kind: "repository",
    generatedAt: now.toISOString(),
    repository: {
      id: row.id,
      name: row.name,
      url: row.url,
      branch: row.branch,
      inactive: row.inactiveAt !== null,
    },
    lastScan: lastScan[0] ? { state: lastScan[0].state, at: new Date(lastScan[0].at).toISOString() } : null,
    lastSuccessfulScan: successful
      ? {
          at: new Date(successful.at).toISOString(),
          commit: successful.commit,
          packages: successful.packages,
        }
      : null,
    vulnDb: vulnDbState(successful?.vulnDbBuiltAt ?? null, now),
    open: countsOf(findings.rows.map((f) => ({ severity: f.severity, n: f.open }))),
    fixable: countsOf(findings.rows.map((f) => ({ severity: f.severity, n: f.fixable }))),
    knownExploited: exploited.critical + exploited.high + exploited.medium + exploited.low,
    accepted: { total: accepted.rows[0]?.total ?? 0, expired: accepted.rows[0]?.expired ?? 0 },
    grade: grade?.grade ? { grade: grade.grade, stale: grade.gradeStale } : null,
    gate: gate[0] ? { result: gate[0].result, at: gate[0].at.toISOString() } : null,
    earlyWarnings: {
      open: warning?.n ?? 0,
      worst: warning?.worst && isReportSeverity(warning.worst) ? warning.worst : null,
    },
    top: top.rows.map(findingRow).filter((x): x is ReportFindingRow => x !== null),
  };
  return { ...base, nextSteps: repositoryNextSteps(base) };
}

/* -------------------------------------------------------------------------- */
/* One host                                                                    */
/* -------------------------------------------------------------------------- */

export async function hostReport(actor: Actor, id: string, now = new Date()): Promise<HostReport> {
  const h = schema.agentHost;
  const [host] = await db
    .select()
    .from(h)
    .where(and(eq(h.id, id), eq(h.organizationId, actor.organizationId)))
    .limit(1);
  if (!host) throw notFound("Host");
  const org = actor.organizationId;
  const [kernel, packages, containers, imageCounts, warnings, top] = await Promise.all([
    db.execute<{ severity: string; n: number }>(sql`
      select severity, count(*)::int as n from ${schema.hostKernelFinding}
      where host_id = ${host.id} and severity in ${SEVERITIES} group by severity`),
    db.execute<{ severity: string; n: number; fixable: number }>(sql`
      select severity, count(*)::int as n,
        count(*) filter (where jsonb_array_length(coalesce(fixed_in, '[]'::jsonb)) > 0)::int as fixable
      from ${schema.hostPackageFinding}
      where host_id = ${host.id} and severity in ${SEVERITIES} group by severity`),
    db
      .select({
        imageId: schema.hostContainer.imageId,
        imageRef: schema.hostContainer.imageRef,
        digests: schema.containerImage.digests,
        matchedAt: schema.containerImage.matchedAt,
        matchError: schema.containerImage.matchError,
      })
      .from(schema.hostContainer)
      .leftJoin(
        schema.containerImage,
        and(
          eq(schema.containerImage.organizationId, schema.hostContainer.organizationId),
          eq(schema.containerImage.imageId, schema.hostContainer.imageId),
        ),
      )
      .where(eq(schema.hostContainer.hostId, host.id)),
    db.execute<{ image_id: string; severity: string; n: number }>(sql`
      select cf.image_id, cf.severity, count(*)::int as n
      from ${schema.containerImageFinding} cf
      where cf.organization_id = ${org} and cf.severity in ${SEVERITIES}
        and cf.image_id in (select image_id from ${schema.hostContainer} where host_id = ${host.id})
      group by cf.image_id, cf.severity`),
    db.execute<{ n: number; worst: string | null }>(sql`
      select count(*)::int as n, (array_agg(severity order by severity_rank desc))[1] as worst
      from ${schema.runtimeEarlyWarning}
      where organization_id = ${org} and state = 'open'
        and (host_id = ${host.id}
          or (kind = 'image' and subject_id in (select image_id from ${schema.hostContainer} where host_id = ${host.id})))`),
    db.execute<{
      severity: string;
      vulnerability_id: string;
      package_name: string;
      package_version: string;
      fixed_in: string[] | null;
      known_exploited: boolean;
      place: string;
      rank: number;
    }>(sql`
      select f.severity, f.vulnerability_id, f.package_name, f.package_version, f.fixed_in, v.known_exploited, f.place, f.rank
      from (
        select severity, severity_rank as rank, vulnerability_id, package_name, package_version, fixed_in, 'kernel' as place
        from ${schema.hostKernelFinding} where host_id = ${host.id}
        union all
        select severity, severity_rank, vulnerability_id, package_name, package_version, fixed_in, 'packages'
        from ${schema.hostPackageFinding} where host_id = ${host.id}
        union all
        select cf.severity, cf.severity_rank, cf.vulnerability_id, cf.package_name, cf.package_version, cf.fixed_in, i.image_ref
        from (select distinct on (image_id) image_id, image_ref from ${schema.hostContainer}
              where host_id = ${host.id} order by image_id, name) i
        join ${schema.containerImageFinding} cf on cf.organization_id = ${org} and cf.image_id = i.image_id
      ) f join ${schema.vulnerability} v on v.id = f.vulnerability_id
      where f.severity in ${SEVERITIES}
      order by f.rank desc, v.known_exploited desc, v.cvss_score desc nulls last, f.vulnerability_id, f.package_name
      limit ${TOP}`),
  ]);

  const byImage = new Map<string, SeverityCounts>();
  for (const row of imageCounts.rows) {
    const entry = byImage.get(row.image_id) ?? emptyCounts();
    if (isReportSeverity(row.severity)) entry[row.severity] += row.n;
    byImage.set(row.image_id, entry);
  }
  const imageIds = [...new Set(containers.map((c) => c.imageId))];
  const images = imageIds.map((imageId) => ({
    imageId,
    counts: byImage.get(imageId) ?? emptyCounts(),
    container: containers.find((c) => c.imageId === imageId),
  }));
  const refs = containers.map((c) => imageRefKey(c.imageRef)).filter((r): r is string => Boolean(r));
  const updates = await updatesByRef(org, refs);
  const withUpdate = containers.filter((c) => {
    const ref = imageRefKey(c.imageRef);
    const state = updateOf(ref ? updates.get(ref) : undefined, c.digests ?? []).state;
    return state === "newer-build" || state === "newer-version";
  }).length;

  const kernelOpen = countsOf(kernel.rows);
  const packagesOpen = countsOf(packages.rows);
  const imagesOpen = addCounts(...images.map((i) => i.counts));
  const hasPackages = host.runtime === "systemd" || host.hostPackages !== null;
  const builtAt = [host.kernelMatchedDbBuilt, host.hostPackagesMatchedDbBuilt]
    .filter((d): d is Date => d !== null)
    .sort((a, b) => b.getTime() - a.getTime())[0];
  const warning = warnings.rows[0];
  const base: Omit<HostReport, "nextSteps"> = {
    kind: "host",
    generatedAt: now.toISOString(),
    host: {
      id: host.id,
      name: host.name,
      hostname: host.hostname,
      os: host.osName ?? host.os,
      runtime: host.runtime,
      agentVersion: host.agentVersion,
    },
    lastReportAt: host.lastInventoryAt?.toISOString() ?? null,
    reporting: Boolean(
      host.lastInventoryAt && now.getTime() - host.lastInventoryAt.getTime() < HOST_STALE_AFTER_MS,
    ),
    kernel: {
      release: host.kernelRelease,
      checked: host.kernelMatchedAt !== null && host.kernelMatchError === null,
      matchedAt: host.kernelMatchedAt?.toISOString() ?? null,
      open: kernelOpen,
    },
    packages: hasPackages
      ? {
          count: host.hostPackages?.length ?? null,
          matchedAt: host.hostPackagesMatchedAt?.toISOString() ?? null,
          open: packagesOpen,
          fixable: packages.rows.reduce((sum, r) => sum + Number(r.fixable), 0),
        }
      : null,
    images: {
      containers: containers.length,
      images: imageIds.length,
      withSerious: images.filter((i) => i.counts.critical + i.counts.high > 0).length,
      notMatched: images.filter((i) => !i.container?.matchedAt || i.container.matchError).length,
      updates: withUpdate,
      open: imagesOpen,
    },
    open: addCounts(kernelOpen, packagesOpen, imagesOpen),
    vulnDb: vulnDbState(builtAt ?? null, now),
    earlyWarnings: {
      open: warning?.n ?? 0,
      worst: warning?.worst && isReportSeverity(warning.worst) ? warning.worst : null,
    },
    top: top.rows
      .map((row) => findingRow({ ...row, where: row.place }))
      .filter((x): x is ReportFindingRow => x !== null),
  };
  return { ...base, nextSteps: hostNextSteps(base) };
}

/* -------------------------------------------------------------------------- */
/* Routes                                                                      */
/* -------------------------------------------------------------------------- */

export const reportRoutes = new Hono<AppEnv>()
  /** The organisation for the last 7 or 30 days, as the person asking sees it. */
  .get("/organization", async (c) => {
    const actor = c.get("actor");
    const input = organizationQuery.parse(c.req.query());
    if (input.format === "pdf") await rateLimit(`report:${actor.userId}`, 20);
    const now = new Date();
    const report = await organizationReport(db, {
      organizationId: actor.organizationId,
      userId: actor.userId,
      period: rangePeriod(input.days, input.tz, now),
      now,
    });
    if (input.format === "json") return c.json(report);
    const ctx = { language: input.lang, timeZone: input.tz };
    const file = toReportPdf(organizationReportDocument(report, messages(input.lang), ctx));
    await audit(actor, "report.exported", undefined, { kind: "organization", days: input.days });
    return c.body(...pdfResponse(file, report.organization, ctx, now));
  })
  /** Every website with the state of its daily look, worst first (ADR 0033: the module must be on). */
  .get("/websites", async (c) => {
    const actor = c.get("actor");
    await requireModuleOn(actor.organizationId, "websites");
    return c.json({ items: await websitesOverview(db, actor.organizationId) });
  })
  .get("/repositories/:id", async (c) => {
    const actor = c.get("actor");
    const input = fileQuery.parse(c.req.query());
    if (input.format === "pdf") await rateLimit(`report:${actor.userId}`, 20);
    const now = new Date();
    const report = await repositoryReport(actor, c.req.param("id"), now);
    if (input.format === "json") return c.json(report);
    const ctx = { language: input.lang, timeZone: input.tz };
    const file = toReportPdf(repositoryReportDocument(report, messages(input.lang), ctx));
    await audit(
      actor,
      "report.exported",
      { type: "repository", id: report.repository.id },
      { kind: "repository" },
    );
    return c.body(...pdfResponse(file, report.repository.name, ctx, now));
  })
  .get("/hosts/:id", async (c) => {
    const actor = c.get("actor");
    await requireModuleOn(actor.organizationId, "hosts");
    const input = fileQuery.parse(c.req.query());
    if (input.format === "pdf") await rateLimit(`report:${actor.userId}`, 20);
    const now = new Date();
    const report = await hostReport(actor, c.req.param("id"), now);
    if (input.format === "json") return c.json(report);
    const ctx = { language: input.lang, timeZone: input.tz };
    const file = toReportPdf(hostReportDocument(report, messages(input.lang), ctx));
    await audit(actor, "report.exported", { type: "host", id: report.host.id }, { kind: "host" });
    return c.body(...pdfResponse(file, report.host.name, ctx, now));
  });

/* -------------------------------------------------------------------------- */
/* The report mail (per person, opt-in)                                        */
/* -------------------------------------------------------------------------- */

const reportMailBody = z.object({
  frequency: z.enum(REPORT_FREQUENCIES).nullable(),
  attachPdf: z.boolean().default(true),
});

async function reportMailView(actor: Actor) {
  const [[row], [person], mailAvailable] = await Promise.all([
    db
      .select()
      .from(schema.reportSubscription)
      .where(
        and(
          eq(schema.reportSubscription.organizationId, actor.organizationId),
          eq(schema.reportSubscription.userId, actor.userId),
        ),
      )
      .limit(1),
    db
      .select({ userZone: schema.user.timeZone, organizationZone: schema.organization.scanTimeZone })
      .from(schema.user)
      .innerJoin(schema.organization, eq(schema.organization.id, actor.organizationId))
      .where(eq(schema.user.id, actor.userId))
      .limit(1),
    mailChannelAvailable(db, actor.organizationId),
  ]);
  return {
    // A stored choice is reported as off while no mail channel exists, as in the notification matrix (ADR 0019).
    frequency: mailAvailable ? (row?.frequency ?? null) : null,
    attachPdf: row?.attachPdf ?? true,
    mailAvailable,
    timeZone: reportTimeZone(person?.userZone, person?.organizationZone),
  };
}

export const reportMailRoutes = new Hono<AppEnv>()
  .get("/report-mail", async (c) => c.json(await reportMailView(c.get("actor"))))
  /**
   * Chooses how often the report mail comes, or switches it off. Like the notification matrix (ADR 0019) this is personal and
   * not audited; the mail only ever goes to the person's own sign-in address. Refused while no mail channel exists.
   */
  .put("/report-mail", async (c) => {
    const actor = c.get("actor");
    await rateLimit(`report-mail:${actor.userId}`, 30);
    const input = reportMailBody.parse(await c.req.json());
    const where = and(
      eq(schema.reportSubscription.organizationId, actor.organizationId),
      eq(schema.reportSubscription.userId, actor.userId),
    );
    if (input.frequency === null) {
      await db.delete(schema.reportSubscription).where(where);
      return c.json(await reportMailView(actor));
    }
    if (!(await mailChannelAvailable(db, actor.organizationId))) {
      throw new ProblemError(422, "validation", "The request is not valid", undefined, {
        errors: [{ path: "frequency", message: "Your organisation has no mail channel" }],
      });
    }
    await db
      .insert(schema.reportSubscription)
      .values({
        organizationId: actor.organizationId,
        userId: actor.userId,
        frequency: input.frequency,
        attachPdf: input.attachPdf,
      })
      .onConflictDoUpdate({
        target: [schema.reportSubscription.organizationId, schema.reportSubscription.userId],
        set: {
          frequency: input.frequency,
          attachPdf: input.attachPdf,
          // A new frequency starts from now: last week's report is not sent at once. The same one keeps its start.
          since: sql`case when ${schema.reportSubscription.frequency} = ${input.frequency} then ${schema.reportSubscription.since} else now() end`,
          updatedAt: sql`now()`,
        },
      });
    return c.json(await reportMailView(actor));
  });
