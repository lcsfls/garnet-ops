import type { NotifyPayload } from "@garnetops/core/notifications";
import { MAIL_MAX_AGE_MS, MAIL_MIN_INTERVAL_MS, type TitleKey } from "@garnetops/core/user-notifications";
import { type NotifyUsersInput, notifyUsers, pruneUserNotifications, schema } from "@garnetops/db";
import { type Language, renderNotificationItem, resolveLanguage, resources } from "@garnetops/i18n";
import { and, asc, eq, inArray, lt, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { DeliveryError, sendMailVia } from "./notify.ts";

/* -------------------------------------------------------------------------- */
/* Creating personal notifications                                             */
/* -------------------------------------------------------------------------- */

/** Replaces the placeholders of the mail texts (`{count}`, `{organization}`) in a single pass. */
const fill = (text: string, values: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (match, key: string) => (key in values ? String(values[key]) : match));

export type MailSender = (
  channel: typeof schema.notificationChannel.$inferSelect,
  title: string,
  text: string,
  to: string[],
) => Promise<void>;

/**
 * Tells the people an event concerns (ADR 0019) and starts the personal mail for those who want
 * it. Never throws: a notification must not fail the work it reports, and the log gets the error
 * name only.
 */
export async function tellUsers(input: NotifyUsersInput, send?: MailSender): Promise<void> {
  try {
    const result = await notifyUsers(db, input);
    if (result.mail > 0) await sendPersonalMail(send ? { send } : {});
  } catch (error) {
    console.error("user notification:", (error as Error)?.name ?? "error");
  }
}

/** The personal notifications of a finished scan of a repository's own branch (same facts as the channels). */
export async function tellAboutScan(
  result: { organizationId: string; ownerUserId: string | null; payloads: NotifyPayload[] },
  send?: MailSender,
): Promise<void> {
  for (const payload of result.payloads) {
    if (!payload.repository) continue;
    const common = {
      organizationId: result.organizationId,
      link: `/repositories/${payload.repository.id}`,
      context: { ownerUserId: result.ownerUserId },
    };
    const repository = payload.repository.name;
    if (payload.event === "finding.new_critical") {
      await tellUsers(
        {
          ...common,
          titleKey: "findingNewCritical",
          params: {
            repository,
            critical: payload.counts?.critical ?? 0,
            knownExploited: payload.counts?.knownExploited ?? 0,
          },
        },
        send,
      );
    } else if (payload.event === "gate.blocked") {
      await tellUsers(
        {
          ...common,
          titleKey: "gateBlocked",
          params: { repository, rules: payload.gate?.blockingRules ?? 0 },
        },
        send,
      );
    } else if (payload.event === "scan.failed") {
      await tellUsers({ ...common, titleKey: "scanFailed", params: { repository } }, send);
    }
  }
}

/** A fix pull request ended: merged on the forge, or failed before it was opened. */
export async function tellAboutFixPr(
  pr: { organizationId: string; repositoryId: string; requestedBy: string | null },
  titleKey: Extract<TitleKey, "fixPrMerged" | "fixPrFailed">,
  send?: MailSender,
): Promise<void> {
  try {
    const [repository] = await db
      .select({ name: schema.repository.name, ownerUserId: schema.repository.ownerUserId })
      .from(schema.repository)
      .where(
        and(
          eq(schema.repository.id, pr.repositoryId),
          eq(schema.repository.organizationId, pr.organizationId),
        ),
      )
      .limit(1);
    if (!repository) return;
    await tellUsers(
      {
        organizationId: pr.organizationId,
        titleKey,
        params: { repository: repository.name },
        link: "/fixes?view=prs",
        context: { ownerUserId: repository.ownerUserId, requestedBy: pr.requestedBy },
      },
      send,
    );
  } catch (error) {
    console.error("user notification:", (error as Error)?.name ?? "error");
  }
}

/* -------------------------------------------------------------------------- */
/* Personal mail                                                               */
/* -------------------------------------------------------------------------- */

const DIGEST_LINES = 20;

interface MailItem {
  titleKey: string;
  params: Record<string, string | number>;
  link: string;
}

/**
 * The subject and body of a personal mail (ADR 0019): the notification's summary and a link, in
 * the person's language. One item is a plain notification; several of one event type are a
 * digest with one line each and a link to the app.
 */
export function renderPersonalMail(
  items: MailItem[],
  language: Language,
  organization: string,
  origin: string,
): { subject: string; text: string } {
  const m = resources[language].translation.inapp.mail;
  const footer = fill(m.footer, { organization });
  const absolute = (link: string) => `${origin}${link}`;
  const [first] = items;
  if (items.length === 1 && first) {
    const { title, text } = renderNotificationItem(language, first.titleKey, first.params);
    return { subject: title, text: `${text}\n${absolute(first.link)}\n\n${footer}` };
  }
  const lines = items
    .slice(0, DIGEST_LINES)
    .map((item) => `- ${renderNotificationItem(language, item.titleKey, item.params).title}`);
  if (items.length > DIGEST_LINES) lines.push(fill(m.more, { count: items.length - DIGEST_LINES }));
  return {
    subject: fill(m.digestSubject, { count: items.length }),
    text: [
      fill(m.digestIntro, { count: items.length, organization }),
      "",
      ...lines,
      "",
      `${m.open} ${absolute("/")}`,
      "",
      footer,
    ].join("\n"),
  };
}

export interface MailDeps {
  send?: MailSender;
  now?: () => Date;
}

/**
 * Sends the personal mails that are waiting (ADR 0019), through the organisation's first enabled
 * mail channel and to the person's own sign-in address only.
 *
 * - At most one mail per person and event type every 15 minutes; what piles up meanwhile goes out
 *   as one digest when the interval is over.
 * - Rows are claimed (marked sent) before sending, so two workers never send the same mail. A mail
 *   that fails is marked failed and not retried: the notification is still in the app.
 * - Without a mail channel, for a person who left the organisation, or after 24 hours, the mail
 *   is dropped.
 * Returns the number of mails sent.
 */
export async function sendPersonalMail(deps: MailDeps = {}): Promise<number> {
  const now = deps.now?.() ?? new Date();
  const send: MailSender = deps.send ?? ((channel, title, text, to) => sendMailVia(channel, title, text, to));
  const n = schema.userNotification;
  await db
    .update(n)
    .set({ mailState: "skipped" })
    .where(and(eq(n.mailState, "pending"), lt(n.createdAt, new Date(now.getTime() - MAIL_MAX_AGE_MS))));

  const groups = await db
    .selectDistinct({ userId: n.userId, organizationId: n.organizationId, event: n.event })
    .from(n)
    .where(eq(n.mailState, "pending"));
  let mails = 0;
  for (const group of groups) {
    try {
      mails += await sendGroup(group, now, send);
    } catch (error) {
      console.error("personal mail:", (error as Error)?.name ?? "error");
    }
  }
  return mails;
}

async function sendGroup(
  group: { userId: string; organizationId: string; event: string },
  now: Date,
  send: MailSender,
): Promise<number> {
  const n = schema.userNotification;
  const mine = and(
    eq(n.userId, group.userId),
    eq(n.organizationId, group.organizationId),
    eq(n.event, group.event),
  );
  const [last] = await db
    .select({ at: sql<Date | null>`max(${n.mailedAt})` })
    .from(n)
    .where(and(mine, eq(n.mailState, "sent")));
  if (last?.at && now.getTime() - new Date(last.at).getTime() < MAIL_MIN_INTERVAL_MS) return 0;

  const drop = () =>
    db
      .update(n)
      .set({ mailState: "skipped" })
      .where(and(mine, eq(n.mailState, "pending")));
  const [person] = await db
    .select({ email: schema.user.email, locale: schema.user.locale, organization: schema.organization.name })
    .from(schema.membership)
    .innerJoin(schema.user, eq(schema.user.id, schema.membership.userId))
    .innerJoin(schema.organization, eq(schema.organization.id, schema.membership.organizationId))
    .where(
      and(
        eq(schema.membership.userId, group.userId),
        eq(schema.membership.organizationId, group.organizationId),
      ),
    )
    .limit(1);
  const [channel] = await db
    .select()
    .from(schema.notificationChannel)
    .where(
      and(
        eq(schema.notificationChannel.organizationId, group.organizationId),
        eq(schema.notificationChannel.enabled, true),
        inArray(schema.notificationChannel.kind, ["smtp", "graph"]),
      ),
    )
    .orderBy(asc(schema.notificationChannel.createdAt))
    .limit(1);
  if (!person || !channel) {
    await drop();
    return 0;
  }

  const claimed = await db
    .update(n)
    .set({ mailState: "sent", mailedAt: now })
    .where(and(mine, eq(n.mailState, "pending")))
    .returning({ id: n.id, titleKey: n.titleKey, params: n.params, link: n.link });
  if (claimed.length === 0) return 0;
  claimed.sort((a, b) => a.id - b.id);
  const origin = env.PUBLIC_URL ? new URL(env.PUBLIC_URL).origin : "";
  const { subject, text } = renderPersonalMail(
    claimed,
    resolveLanguage(person.locale),
    person.organization,
    origin,
  );
  try {
    await send(channel, subject, text, [person.email]);
    return 1;
  } catch (error) {
    await db
      .update(n)
      .set({ mailState: "failed", mailedAt: null })
      .where(
        inArray(
          n.id,
          claimed.map((c) => c.id),
        ),
      );
    // A delivery error carries a short code or status; anything else is logged by name only.
    console.error(
      "personal mail failed:",
      error instanceof DeliveryError ? error.message.slice(0, 80) : ((error as Error)?.name ?? "error"),
    );
    return 0;
  }
}

/* -------------------------------------------------------------------------- */
/* Upkeep                                                                      */
/* -------------------------------------------------------------------------- */

/** Sends waiting mail every minute and prunes old notifications every hour. Returns a function that stops both. */
export function startUserNotificationUpkeep(): () => void {
  const mail = setInterval(
    () => sendPersonalMail().catch((error: Error) => console.error("personal mail:", error.name)),
    60_000,
  );
  const prune = () =>
    pruneUserNotifications(db).catch((error: Error) => console.error("notification retention:", error.name));
  const retention = setInterval(prune, 3_600_000);
  void prune();
  return () => {
    clearInterval(mail);
    clearInterval(retention);
  };
}
