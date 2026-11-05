import {
  organizationReportDocument,
  type ReportMessages,
  reportMail,
  toReportPdf,
} from "@garnetops/core/report-documents";
import { dueReportMail, type ReportFrequency, reportFileName, reportTimeZone } from "@garnetops/core/reports";
import { organizationReport, schema } from "@garnetops/db";
import { resolveLanguage, resources } from "@garnetops/i18n";
import { and, asc, eq, inArray, sql } from "drizzle-orm";
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

/** Starts the five-minute tick. Returns a function that stops it. */
export function startReportMail(): () => void {
  const timer = setInterval(() => void sendDueReportMails(), REPORT_MAIL_TICK_MS);
  void sendDueReportMails();
  return () => clearInterval(timer);
}
