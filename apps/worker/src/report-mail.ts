import {
  organizationReportDocument,
  type ReportMessages,
  reportMail,
  toReportPdf,
} from "@garnetops/core/report-documents";
import { dueReportMail, type ReportFrequency, reportFileName, reportTimeZone } from "@garnetops/core/reports";
import {
  MIN_SEVERITY_RANK,
  type VulnerabilityMailFrequency,
  type VulnerabilityMailMessages,
  type VulnerabilityMailSeverity,
  vulnerabilityMail,
} from "@garnetops/core/vulnerability-mail";
import { activeRepository, organizationReport, schema, visibleRepository } from "@garnetops/db";
import { resolveLanguage, resources } from "@garnetops/i18n";
import { and, asc, count, eq, gte, inArray, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { DeliveryError, type MailAttachment, sendMailWithAttachments } from "./notify.ts";

/**
 * The report mail (ADR 0047): for each person who chose it, the organisation report of the day, week or month before, built
 * with that person's visibility, sent to their own sign-in address through the organisation's first enabled mail channel
 * (as personal mail, ADR 0019), with the PDF attached if they want it.
 *
 * A tick every five minutes decides in each person's own zone what is due (ADR 0005). The period's key is recorded before
 * anything is sent, so a repeated autumn hour, a second worker or a crash in the middle never sends a report twice; a mail
 * that fails is recorded with a short code and not retried. Without a mail channel the period is recorded as skipped.
 */

export const REPORT_MAIL_TICK_MS = 5 * 60_000;
/** Records of sent report mails are kept this long. */
const KEEP_DAYS = 400;

export type ReportMailSender = (
  channel: typeof schema.notificationChannel.$inferSelect,
  subject: string,
  text: string,
  to: string[],
  attachments: MailAttachment[],
) => Promise<void>;

export interface ReportMailDeps {
  now?: () => Date;
  send?: ReportMailSender;
}

/** Sends every report mail that is due. Returns the number sent. Never throws. */
export async function sendDueReportMails(deps: ReportMailDeps = {}): Promise<number> {
  const now = deps.now?.() ?? new Date();
  const send = deps.send ?? sendMailWithAttachments;
  let sent = 0;
  try {
    const people = await db
      .select({
        organizationId: schema.reportSubscription.organizationId,
        userId: schema.reportSubscription.userId,
        frequency: schema.reportSubscription.frequency,
        attachPdf: schema.reportSubscription.attachPdf,
        since: schema.reportSubscription.since,
        email: schema.user.email,
        locale: schema.user.locale,
        userZone: schema.user.timeZone,
        organizationZone: schema.organization.scanTimeZone,
      })
      .from(schema.reportSubscription)
      // Only people who are still members: a removed person gets nothing.
      .innerJoin(
        schema.membership,
        and(
          eq(schema.membership.organizationId, schema.reportSubscription.organizationId),
          eq(schema.membership.userId, schema.reportSubscription.userId),
        ),
      )
      .innerJoin(schema.user, eq(schema.user.id, schema.reportSubscription.userId))
      .innerJoin(schema.organization, eq(schema.organization.id, schema.reportSubscription.organizationId));
    for (const person of people) {
      try {
        if (await sendOne(person, now, send)) sent++;
      } catch (error) {
        console.error("report mail:", (error as Error)?.name ?? "error");
      }
    }
    await db
      .delete(schema.reportMailRun)
      .where(
        sql`${schema.reportMailRun.createdAt} < ${now.toISOString()}::timestamptz - ${`${KEEP_DAYS} days`}::interval`,
      );
  } catch (error) {
    console.error("report mail:", (error as Error)?.name ?? "error");
  }
  return sent;
}

async function sendOne(
  person: {
    organizationId: string;
    userId: string;
    frequency: ReportFrequency;
    attachPdf: boolean;
    since: Date;
    email: string;
    locale: string | null;
    userZone: string | null;
    organizationZone: string;
  },
  now: Date,
  send: ReportMailSender,
): Promise<boolean> {
  const timeZone = reportTimeZone(person.userZone, person.organizationZone);
  const due = dueReportMail({ frequency: person.frequency, timeZone, now, since: person.since });
  if (!due) return false;
  const run = schema.reportMailRun;
  const key = and(
    eq(run.organizationId, person.organizationId),
    eq(run.userId, person.userId),
    eq(run.periodKey, due.key),
  );
  // Claim the period first: whoever inserts the row sends the mail, nobody else and never again.
  const claimed = await db
    .insert(run)
    .values({
      organizationId: person.organizationId,
      userId: person.userId,
      periodKey: due.key,
      state: "sending",
    })
    .onConflictDoNothing()
    .returning({ key: run.periodKey });
  if (claimed.length === 0) return false;
  const finish = (state: "sent" | "failed" | "skipped", error: string | null = null) =>
    db.update(run).set({ state, error, finishedAt: now }).where(key);

  const [channel] = await db
    .select()
    .from(schema.notificationChannel)
    .where(
      and(
        eq(schema.notificationChannel.organizationId, person.organizationId),
        eq(schema.notificationChannel.enabled, true),
        inArray(schema.notificationChannel.kind, ["smtp", "graph"]),
      ),
    )
    .orderBy(asc(schema.notificationChannel.createdAt))
    .limit(1);
  if (!channel) {
    await finish("skipped", "no-mail-channel");
    return false;
  }

  try {
    const report = await organizationReport(db, {
      organizationId: person.organizationId,
      userId: person.userId,
      period: due.period,
      now,
    });
    const language = resolveLanguage(person.locale);
    const m = resources[language].translation as unknown as ReportMessages;
    const ctx = { language, timeZone };
    const origin = env.PUBLIC_URL ? new URL(env.PUBLIC_URL).origin : "";
    const { subject, text } = reportMail(report, person.frequency, m, ctx, {
      origin,
      attached: person.attachPdf,
    });
    const attachments: MailAttachment[] = person.attachPdf
      ? [
          {
            filename: reportFileName(report.organization, due.period.from),
            content: toReportPdf(organizationReportDocument(report, m, ctx)),
            contentType: "application/pdf",
          },
        ]
      : [];
    await send(channel, subject, text, [person.email], attachments);
    await finish("sent");
    return true;
  } catch (error) {
    // A delivery error carries a short code or status; anything else is recorded and logged by name only.
    const reason =
      error instanceof DeliveryError
        ? error.message.slice(0, 80)
        : ((error as Error)?.name ?? "error").slice(0, 80);
    await finish("failed", reason);
    console.error("report mail failed:", reason);
    return false;
  }
}

/** The mail channel a person's mail goes through: the one they chose while it is on, else the organisation's first. */
async function mailChannelFor(organizationId: string, chosen: string | null) {
  const channel = schema.notificationChannel;
  const usable = and(
    eq(channel.organizationId, organizationId),
    eq(channel.enabled, true),
    inArray(channel.kind, ["smtp", "graph"]),
  );
  if (chosen) {
    const [row] = await db
      .select()
      .from(channel)
      .where(and(usable, eq(channel.id, chosen)))
      .limit(1);
    if (row) return row;
  }
  const [first] = await db.select().from(channel).where(usable).orderBy(asc(channel.createdAt)).limit(1);
  return first ?? null;
}

/**
 * The vulnerability mail (ADR 0047 addendum 2026-11-16): for each person who chose it, the vulnerabilities found in the day or
 * week before and still open, from their minimum severity, in the repositories they see (or the ones they chose), through the
 * mail channel they chose. Recorded per period like the report mail ("vulnerabilities:" keys), so it is never sent twice;
 * a period without anything new is recorded as skipped and sends nothing. Returns the number sent. Never throws.
 */
export async function sendDueVulnerabilityMails(deps: ReportMailDeps = {}): Promise<number> {
  const now = deps.now?.() ?? new Date();
  const send = deps.send ?? sendMailWithAttachments;
  let sent = 0;
  try {
    const v = schema.vulnerabilityMail;
    const people = await db
      .select({
        organizationId: v.organizationId,
        userId: v.userId,
        frequency: v.frequency,
        minSeverity: v.minSeverity,
        repositoryIds: v.repositoryIds,
        channelId: v.channelId,
        since: v.since,
        email: schema.user.email,
        locale: schema.user.locale,
        userZone: schema.user.timeZone,
        organizationZone: schema.organization.scanTimeZone,
        organization: schema.organization.name,
      })
      .from(v)
      .innerJoin(
        schema.membership,
        and(eq(schema.membership.organizationId, v.organizationId), eq(schema.membership.userId, v.userId)),
      )
      .innerJoin(schema.user, eq(schema.user.id, v.userId))
      .innerJoin(schema.organization, eq(schema.organization.id, v.organizationId));
    for (const person of people) {
      try {
        if (await sendOneVulnerabilityMail(person, now, send)) sent++;
      } catch (error) {
        console.error("vulnerability mail:", (error as Error)?.name ?? "error");
      }
    }
  } catch (error) {
    console.error("vulnerability mail:", (error as Error)?.name ?? "error");
  }
  return sent;
}

async function sendOneVulnerabilityMail(
  person: {
    organizationId: string;
    userId: string;
    frequency: VulnerabilityMailFrequency;
    minSeverity: VulnerabilityMailSeverity;
    repositoryIds: string[] | null;
    channelId: string | null;
    since: Date;
    email: string;
    locale: string | null;
    userZone: string | null;
    organizationZone: string;
    organization: string;
  },
  now: Date,
  send: ReportMailSender,
): Promise<boolean> {
  const timeZone = reportTimeZone(person.userZone, person.organizationZone);
  const due = dueReportMail({ frequency: person.frequency, timeZone, now, since: person.since });
  if (!due) return false;
  const run = schema.reportMailRun;
  const periodKey = `vulnerabilities:${due.key}`;
  const claimed = await db
    .insert(run)
    .values({ organizationId: person.organizationId, userId: person.userId, periodKey, state: "sending" })
    .onConflictDoNothing()
    .returning({ key: run.periodKey });
  if (claimed.length === 0) return false;
  const finish = (state: "sent" | "failed" | "skipped", error: string | null = null) =>
    db
      .update(run)
      .set({ state, error, finishedAt: now })
      .where(
        and(
          eq(run.organizationId, person.organizationId),
          eq(run.userId, person.userId),
          eq(run.periodKey, periodKey),
        ),
      );

  try {
    const f = schema.finding;
    const r = schema.repository;
    const viewer = { organizationId: person.organizationId, userId: person.userId };
    // The repositories the person sees today, active, and among the chosen ones if they chose.
    const covered = and(
      eq(f.organizationId, person.organizationId),
      visibleRepository(f.repositoryId, viewer),
      activeRepository(f.repositoryId),
      person.repositoryIds
        ? inArray(f.repositoryId, person.repositoryIds.length ? person.repositoryIds : [""])
        : undefined,
      eq(f.state, "open"),
      gte(f.severityRank, MIN_SEVERITY_RANK[person.minSeverity]),
    );
    const local = sql`(${f.firstSeenAt} at time zone ${timeZone})::date`;
    const [items, open, exploited] = await Promise.all([
      db
        .select({
          repository: r.name,
          vulnerabilityId: f.vulnerabilityId,
          severity: f.severity,
          knownExploited: schema.vulnerability.knownExploited,
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          packageType: f.packageType,
          fixedIn: f.fixedIn,
        })
        .from(f)
        .innerJoin(r, eq(r.id, f.repositoryId))
        .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, f.vulnerabilityId))
        .where(and(covered, sql`${local} between ${due.period.from}::date and ${due.period.to}::date`))
        .limit(2000),
      db
        .select({ repository: r.name, n: count() })
        .from(f)
        .innerJoin(r, eq(r.id, f.repositoryId))
        .where(covered)
        .groupBy(r.name),
      db
        .select({ n: count() })
        .from(f)
        .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, f.vulnerabilityId))
        .where(and(covered, eq(schema.vulnerability.knownExploited, true))),
    ]);
    const language = resolveLanguage(person.locale);
    const origin = env.PUBLIC_URL ? new URL(env.PUBLIC_URL).origin : "";
    const mail = vulnerabilityMail(
      {
        organization: person.organization,
        frequency: person.frequency,
        period: due.period,
        minSeverity: person.minSeverity,
        items: items.map((i) => ({ ...i, fixedIn: i.fixedIn ?? [] })),
        openByRepository: Object.fromEntries(open.map((o) => [o.repository, o.n])),
        knownExploitedOpen: exploited[0]?.n ?? 0,
      },
      resources[language].translation as unknown as VulnerabilityMailMessages,
      { language, timeZone },
      { origin },
    );
    // Nothing new: nothing is sent.
    if (!mail) {
      await finish("skipped", "nothing-new");
      return false;
    }
    const channel = await mailChannelFor(person.organizationId, person.channelId);
    if (!channel) {
      await finish("skipped", "no-mail-channel");
      return false;
    }
    await send(channel, mail.subject, mail.text, [person.email], []);
    await finish("sent");
    return true;
  } catch (error) {
    const reason =
      error instanceof DeliveryError
        ? error.message.slice(0, 80)
        : ((error as Error)?.name ?? "error").slice(0, 80);
    await finish("failed", reason);
    console.error("vulnerability mail failed:", reason);
    return false;
  }
}

/** Starts the five-minute tick (report mail and vulnerability mail). Returns a function that stops it. */
export function startReportMail(): () => void {
  const tick = async () => {
    await sendDueReportMails();
    await sendDueVulnerabilityMails();
  };
  const timer = setInterval(() => void tick(), REPORT_MAIL_TICK_MS);
  void tick();
  return () => clearInterval(timer);
}
